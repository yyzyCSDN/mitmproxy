import datetime
import hashlib
import ipaddress
import logging
import ssl
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID
from OpenSSL import SSL

from mitmproxy import certs
from mitmproxy import connection
from mitmproxy import exceptions
from mitmproxy import options
from mitmproxy import tls
from mitmproxy.addons import tlsconfig
from mitmproxy.net import tls as net_tls
from mitmproxy.proxy import context
from mitmproxy.proxy.layers import modes
from mitmproxy.proxy.layers import quic
from mitmproxy.proxy.layers import tls as proxy_tls
from mitmproxy.test import taddons
from test.mitmproxy.proxy.layers import test_tls
from test.mitmproxy.proxy.layers.quic import test__stream_layers as test_quic
from test.mitmproxy.test_flow import tflow


def test_alpn_select_callback():
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    conn = SSL.Connection(ctx)

    # Test that we respect addons setting `client.alpn`.
    conn.set_app_data(
        tlsconfig.AppData(server_alpn=b"h2", http2=True, client_alpn=b"qux")
    )
    assert tlsconfig.alpn_select_callback(conn, [b"http/1.1", b"qux", b"h2"]) == b"qux"
    conn.set_app_data(tlsconfig.AppData(server_alpn=b"h2", http2=True, client_alpn=b""))
    assert (
        tlsconfig.alpn_select_callback(conn, [b"http/1.1", b"qux", b"h2"])
        == SSL.NO_OVERLAPPING_PROTOCOLS
    )

    # Test that we try to mirror the server connection's ALPN
    conn.set_app_data(
        tlsconfig.AppData(server_alpn=b"h2", http2=True, client_alpn=None)
    )
    assert tlsconfig.alpn_select_callback(conn, [b"http/1.1", b"qux", b"h2"]) == b"h2"

    # Test that we respect the client's preferred HTTP ALPN.
    conn.set_app_data(tlsconfig.AppData(server_alpn=None, http2=True, client_alpn=None))
    assert (
        tlsconfig.alpn_select_callback(conn, [b"qux", b"http/1.1", b"h2"])
        == b"http/1.1"
    )
    assert tlsconfig.alpn_select_callback(conn, [b"qux", b"h2", b"http/1.1"]) == b"h2"

    # Test no overlap
    assert (
        tlsconfig.alpn_select_callback(conn, [b"qux", b"quux"])
        == SSL.NO_OVERLAPPING_PROTOCOLS
    )

    # Test that we don't select an ALPN if the server refused to select one.
    conn.set_app_data(tlsconfig.AppData(server_alpn=b"", http2=True, client_alpn=None))
    assert (
        tlsconfig.alpn_select_callback(conn, [b"http/1.1"])
        == SSL.NO_OVERLAPPING_PROTOCOLS
    )


here = Path(__file__).parent


def _generate_ca(
    cn: str,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _generate_leaf(
    cn: str,
    *sans: str,
    issuer: tuple[rsa.RSAPrivateKey, x509.Certificate] | None = None,
    key_password: bytes | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate, bytes]:
    """Generate a leaf certificate and return key, cert and PEM (key + cert)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_key, issuer_cert = issuer or (None, None)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
        .sign(private_key=issuer_key or key, algorithm=hashes.SHA256())
    )
    encryption = (
        serialization.BestAvailableEncryption(key_password)
        if key_password
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        encryption,
    ) + cert.public_bytes(serialization.Encoding.PEM)
    return key, cert, pem


def _fingerprint(cert: x509.Certificate) -> bytes:
    return cert.fingerprint(hashes.SHA256())


class _BioSSL:
    """Minimal stand-in for test_tls.SSLTest around a custom SSL object."""

    def __init__(self, ssl_obj, inc: ssl.MemoryBIO, out: ssl.MemoryBIO):
        self.obj = ssl_obj
        self._inc = inc
        self._out = out

    def bio_write(self, buf: bytes) -> int:
        return self._inc.write(buf)

    def bio_read(self, bufsize: int = 65536) -> bytes:
        return self._out.read(bufsize)

    def do_handshake(self) -> None:
        return self.obj.do_handshake()


def _unverified_client() -> _BioSSL:
    """A TLS client that does not verify the server certificate."""
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_obj = client_ctx.wrap_bio(inc, out, server_hostname=None)
    return _BioSSL(client_obj, inc, out)


def _peer_fingerprint(ssl_test: test_tls.SSLTest | _BioSSL) -> bytes:
    der = ssl_test.obj.getpeercert(binary_form=True)
    assert der
    return hashlib.sha256(der).digest()


def _ctx(opts: options.Options) -> context.Context:
    return context.Context(
        connection.Client(
            peername=("client", 1234),
            sockname=("127.0.0.1", 8080),
            timestamp_start=1605699329,
        ),
        opts,
    )


class TestTlsConfig:
    def test_configure(self, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            with pytest.raises(Exception, match="file does not exist"):
                tctx.configure(ta, certs=["*=nonexistent"])

            with pytest.raises(Exception, match="Invalid ECDH curve"):
                tctx.configure(ta, tls_ecdh_curve_client="invalid")

            with pytest.raises(Exception, match="Invalid certificate format"):
                tctx.configure(
                    ta,
                    certs=[
                        tdata.path(
                            "mitmproxy/net/data/verificationcerts/trusted-leaf.key"
                        )
                    ],
                )

            assert not ta.certstore.certs
            tctx.configure(
                ta,
                certs=[
                    tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.pem")
                ],
            )
            assert ta.certstore.certs

    def test_reload_certs(self, tmp_path):
        assert tlsconfig.TlsConfig.reload_certs.command_name == "tls.reload_certs"

        exact_file = tmp_path / "exact.pem"
        wildcard_file = tmp_path / "wildcard.pem"
        _, exact1, exact_pem1 = _generate_leaf("example.com", "example.com")
        _, wild1, wild_pem1 = _generate_leaf("wild.example.org", "wild.example.org")
        exact_file.write_bytes(exact_pem1)
        wildcard_file.write_bytes(wild_pem1)

        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                confdir=str(tmp_path / "confdir"),
                certs=[
                    f"example.com={exact_file}",
                    f"*.example.org={wildcard_file}",
                ],
            )
            default_ca = ta.certstore.default_ca
            default_key = ta.certstore.default_privatekey

            def lookup(name: str) -> certs.CertStoreEntry:
                return ta.certstore.get_cert(name, [x509.DNSName(name)])

            assert lookup("example.com").cert.fingerprint() == _fingerprint(exact1)
            assert lookup("www.example.org").cert.fingerprint() == _fingerprint(wild1)
            # Domains without a custom certificate keep using the proxy CA.
            assert lookup("www.example.net").privatekey is default_key

            # Renew both certificates in place, paths stay unchanged.
            _, exact2, exact_pem2 = _generate_leaf("example.com", "example.com")
            _, wild2, wild_pem2 = _generate_leaf("wild.example.org", "wild.example.org")
            exact_file.write_bytes(exact_pem2)
            wildcard_file.write_bytes(wild_pem2)
            ta.reload_certs()

            assert lookup("example.com").cert.fingerprint() == _fingerprint(exact2)
            assert lookup("www.example.org").cert.fingerprint() == _fingerprint(wild2)
            assert lookup("www.example.net").privatekey is default_key
            # The proxy CA is not rotated and old keys do not linger.
            assert ta.certstore.default_ca is default_ca
            assert ta.certstore.certs["example.com"].cert.fingerprint() != _fingerprint(
                exact1
            )

    @pytest.mark.parametrize("failure", ["mismatch", "missing", "encryption"])
    def test_reload_certs_failure_keeps_old_certs(self, tmp_path, tdata, failure):
        cert_file = tmp_path / "site.pem"
        password = b"secret" if failure == "encryption" else None
        _, cert1, pem1 = _generate_leaf(
            "example.com", "example.com", key_password=password
        )
        cert_file.write_bytes(pem1)

        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                confdir=str(tmp_path / "confdir"),
                certs=[f"example.com={cert_file}"],
                cert_passphrase="secret" if failure == "encryption" else None,
            )

            def current() -> certs.CertStoreEntry:
                return ta.certstore.get_cert(
                    "example.com", [x509.DNSName("example.com")]
                )

            assert current().cert.fingerprint() == _fingerprint(cert1)

            if failure == "mismatch":
                cert_file.write_bytes(
                    Path(
                        tdata.path(
                            "mitmproxy/net/data/verificationcerts/private-public-mismatch.pem"
                        )
                    ).read_bytes()
                )
            elif failure == "missing":
                cert_file.unlink()
            else:
                _, _, pem_bad = _generate_leaf(
                    "example.com",
                    "example.com",
                    key_password=b"this-is-not-the-configured-passphrase",
                )
                cert_file.write_bytes(pem_bad)

            with pytest.raises(exceptions.CommandError, match="reload failed"):
                ta.reload_certs()

            # The whole old group remains in effect.
            assert current().cert.fingerprint() == _fingerprint(cert1)

            # Fix the file and reload again: this time it succeeds.
            _, cert2, pem2 = _generate_leaf(
                "example.com", "example.com", key_password=password
            )
            cert_file.write_bytes(pem2)
            ta.reload_certs()
            assert current().cert.fingerprint() == _fingerprint(cert2)

    def test_reload_certs_group_atomicity(self, tmp_path, tdata):
        file_a = tmp_path / "a.pem"
        file_b = tmp_path / "b.pem"
        _, cert_a1, pem_a1 = _generate_leaf("a.example", "a.example")
        _, cert_b1, pem_b1 = _generate_leaf("b.example", "b.example")
        file_a.write_bytes(pem_a1)
        file_b.write_bytes(pem_b1)

        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                confdir=str(tmp_path / "confdir"),
                certs=[f"a.example={file_a}", f"b.example={file_b}"],
            )

            def lookup(name: str) -> certs.CertStoreEntry:
                return ta.certstore.get_cert(name, [x509.DNSName(name)])

            def client_tls_start(sni: str):
                ctx = _ctx(tctx.options)
                ctx.client.sni = sni
                tls_start = tls.TlsData(ctx.client, context=ctx)
                ta.tls_start_client(tls_start)
                return tls_start

            tls_start_before = client_tls_start("a.example")
            ssl_ctx_before = tls_start_before.ssl_conn.get_context()

            # Disk is now half renewed (a) and half broken (b).
            _, cert_a2, pem_a2 = _generate_leaf("a.example", "a.example")
            file_a.write_bytes(pem_a2)
            file_b.write_bytes(
                Path(
                    tdata.path(
                        "mitmproxy/net/data/verificationcerts/private-public-mismatch.pem"
                    )
                ).read_bytes()
            )

            with pytest.raises(exceptions.CommandError):
                ta.reload_certs()

            # No handshake may see the renewed a while b is broken.
            assert lookup("a.example").cert.fingerprint() == _fingerprint(cert_a1)
            assert lookup("b.example").cert.fingerprint() == _fingerprint(cert_b1)
            # The path-cached SSL context is retained as well.
            assert (
                client_tls_start("a.example").ssl_conn.get_context() is ssl_ctx_before
            )

            # Repair b and reload again -> both new groups become visible.
            _, cert_b2, pem_b2 = _generate_leaf("b.example", "b.example")
            file_b.write_bytes(pem_b2)
            ta.reload_certs()
            assert lookup("a.example").cert.fingerprint() == _fingerprint(cert_a2)
            assert lookup("b.example").cert.fingerprint() == _fingerprint(cert_b2)
            assert (
                client_tls_start("a.example").ssl_conn.get_context()
                is not ssl_ctx_before
            )

    def test_reload_certs_chain_and_context_switch(self, tmp_path):
        cert_file = tmp_path / "site.pem"
        _, cert1, pem1 = _generate_leaf("example.com", "example.com")
        cert_file.write_bytes(pem1)

        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                confdir=str(tmp_path / "confdir"),
                certs=[f"example.com={cert_file}"],
            )

            ctx = _ctx(tctx.options)
            ctx.client.sni = "example.com"
            tls_start1 = tls.TlsData(ctx.client, context=ctx)
            ta.tls_start_client(tls_start1)
            ssl_ctx1 = tls_start1.ssl_conn.get_context()
            assert len(ta.certstore.certs["example.com"].chain_certs) == 1

            # Renew with a leaf signed by an intermediate, chain appended.
            intermediate_key, intermediate_cert = _generate_ca("Example Intermediate")
            _, cert2, leaf_pem2 = _generate_leaf(
                "example.com",
                "example.com",
                issuer=(intermediate_key, intermediate_cert),
            )
            intermediate_pem = intermediate_cert.public_bytes(
                serialization.Encoding.PEM
            )
            cert_file.write_bytes(leaf_pem2 + intermediate_pem)
            ta.reload_certs()

            entry2 = ta.certstore.certs["example.com"]
            assert entry2.cert.fingerprint() == _fingerprint(cert2)
            assert len(entry2.chain_certs) == 2
            # The contexts cached by chain file path switched together.
            assert net_tls.create_client_proxy_context.cache_info().currsize == 0

            ctx2 = _ctx(tctx.options)
            ctx2.client.sni = "example.com"
            tls_start2 = tls.TlsData(ctx2.client, context=ctx2)
            ta.tls_start_client(tls_start2)
            ssl_conn2 = tls_start2.ssl_conn
            assert ssl_conn2.get_context() is not ssl_ctx1

            # A client trusting only the new intermediate completes the
            # handshake, proving the new chain is actually served.
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.load_verify_locations(cadata=intermediate_pem.decode())
            inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
            client_obj = client_ctx.wrap_bio(inc, out, server_hostname="example.com")
            assert self.do_handshake(_BioSSL(client_obj, inc, out), ssl_conn2)

    def test_reload_certs_connection_switch(self, tmp_path):
        cert_file = tmp_path / "site.pem"
        _, cert1, pem1 = _generate_leaf("example.com", "example.com")
        cert_file.write_bytes(pem1)

        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                confdir=str(tmp_path / "confdir"),
                certs=[f"*={cert_file}"],
            )

            # This handshake picks up its certificate context before the reload.
            ctx1 = _ctx(tctx.options)
            tls_start1 = tls.TlsData(ctx1.client, context=ctx1)
            ta.tls_start_client(tls_start1)

            _, cert2, pem2 = _generate_leaf("example.com", "example.com")
            cert_file.write_bytes(pem2)
            ta.reload_certs()

            # It completes after the reload with the old material.
            client1 = _unverified_client()
            assert self.do_handshake(client1, tls_start1.ssl_conn)
            assert _peer_fingerprint(client1) == _fingerprint(cert1)

            # A fresh handshake after the reload uses the new material.
            ctx2 = _ctx(tctx.options)
            tls_start2 = tls.TlsData(ctx2.client, context=ctx2)
            ta.tls_start_client(tls_start2)
            client2 = _unverified_client()
            assert self.do_handshake(client2, tls_start2.ssl_conn)
            assert _peer_fingerprint(client2) == _fingerprint(cert2)

    def test_configure_tls_version(self, caplog):
        caplog.set_level(logging.INFO)
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            for attr in [
                "tls_version_client_min",
                "tls_version_client_max",
                "tls_version_server_min",
                "tls_version_server_max",
            ]:
                caplog.clear()
                tctx.configure(ta, **{attr: "SSL3"})
                assert (
                    f"{attr} has been set to SSL3, "
                    "which is not supported by the current OpenSSL build."
                ) in caplog.text
            caplog.clear()
            tctx.configure(ta, tls_version_client_min="UNBOUNDED")
            assert (
                "tls_version_client_min has been set to UNBOUNDED. "
                "Note that your OpenSSL build only supports the following TLS versions"
            ) in caplog.text

    def test_configure_ciphers(self, caplog):
        caplog.set_level(logging.INFO)
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                tls_version_client_min="TLS1",
                ciphers_client="ALL",
            )
            assert (
                "With tls_version_client_min set to TLS1, "
                'ciphers_client must include "@SECLEVEL=0" for insecure TLS versions to work.'
            ) in caplog.text
            caplog.clear()

            tctx.configure(
                ta,
                ciphers_server="ALL",
            )
            assert not caplog.text
            tctx.configure(
                ta,
                tls_version_server_min="SSL3",
            )
            assert (
                "With tls_version_server_min set to SSL3, "
                'ciphers_server must include "@SECLEVEL=0" for insecure TLS versions to work.'
            ) in caplog.text

    def test_get_cert(self, tdata):
        """Test that we generate a certificate matching the connection's context."""
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ta.configure(["confdir"])

            ctx = _ctx(tctx.options)

            # Edge case first: We don't have _any_ idea about the server nor is there a SNI,
            # so we just return our local IP as subject.
            entry = ta.get_cert(ctx)
            assert entry.cert.cn == "127.0.0.1"

            # Here we have an existing server connection...
            ctx.server.address = ("server-address.example", 443)
            with open(
                tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.crt"),
                "rb",
            ) as f:
                ctx.server.certificate_list = [certs.Cert.from_pem(f.read())]
            entry = ta.get_cert(ctx)
            assert entry.cert.cn == "example.mitmproxy.org"
            assert entry.cert.altnames == x509.GeneralNames(
                [
                    x509.DNSName("example.mitmproxy.org"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.DNSName("server-address.example"),
                ]
            )

            # And now we also incorporate SNI.
            ctx.client.sni = "🌈.sni.example"
            entry = ta.get_cert(ctx)
            assert entry.cert.altnames == x509.GeneralNames(
                [
                    x509.DNSName("example.mitmproxy.org"),
                    x509.DNSName("xn--og8h.sni.example"),
                    x509.DNSName("server-address.example"),
                ]
            )

            with open(tdata.path("mitmproxy/data/invalid-subject.pem"), "rb") as f:
                ctx.server.certificate_list = [certs.Cert.from_pem(f.read())]
            with pytest.warns(UserWarning):
                assert ta.get_cert(ctx)  # does not raise

    def test_tls_clienthello(self):
        # only really testing for coverage here, there's no point in mirroring the individual conditions
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ch = tls.ClientHelloData(ctx, None)  # type: ignore
            ta.tls_clienthello(ch)
            assert not ch.establish_server_tls_first

    def do_handshake(
        self,
        tssl_client: test_tls.SSLTest | SSL.Connection,
        tssl_server: test_tls.SSLTest | SSL.Connection,
    ) -> bool:
        # ClientHello
        with pytest.raises((ssl.SSLWantReadError, SSL.WantReadError)):
            tssl_client.do_handshake()
        tssl_server.bio_write(tssl_client.bio_read(65536))

        # ServerHello
        with pytest.raises((ssl.SSLWantReadError, SSL.WantReadError)):
            tssl_server.do_handshake()
        tssl_client.bio_write(tssl_server.bio_read(65536))

        # done
        tssl_client.do_handshake()
        tssl_server.bio_write(tssl_client.bio_read(65536))
        tssl_server.do_handshake()

        return True

    def quic_do_handshake(
        self,
        tssl_client: test_quic.SSLTest,
        tssl_server: test_quic.SSLTest,
    ) -> bool:
        tssl_server.write(tssl_client.read())
        tssl_client.write(tssl_server.read())
        tssl_server.write(tssl_client.read())
        return tssl_client.handshake_completed() and tssl_server.handshake_completed()

    def test_tls_start_client(self, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ta.configure(["confdir"])
            tctx.configure(
                ta,
                certs=[
                    tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.pem")
                ],
                ciphers_client="ECDHE-ECDSA-AES128-GCM-SHA256",
            )
            ctx = _ctx(tctx.options)

            tls_start = tls.TlsData(ctx.client, context=ctx)
            ta.tls_start_client(tls_start)
            tssl_server = tls_start.ssl_conn

            # assert that a preexisting ssl_conn is not overwritten
            ta.tls_start_client(tls_start)
            assert tssl_server is tls_start.ssl_conn

            tssl_client = test_tls.SSLTest()
            assert self.do_handshake(tssl_client, tssl_server)
            assert tssl_client.obj.getpeercert()["subjectAltName"] == (
                ("DNS", "example.mitmproxy.org"),
            )

    def test_quic_start_client(self, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ta.configure(["confdir"])
            tctx.configure(
                ta,
                certs=[
                    tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.pem")
                ],
                ciphers_client="CHACHA20_POLY1305_SHA256",
            )
            ctx = _ctx(tctx.options)

            tls_start = quic.QuicTlsData(ctx.client, context=ctx)
            ta.quic_start_client(tls_start)
            settings_server = tls_start.settings
            settings_server.alpn_protocols = ["h3"]
            tssl_server = test_quic.SSLTest(server_side=True, settings=settings_server)

            # assert that a preexisting settings is not overwritten
            ta.quic_start_client(tls_start)
            assert settings_server is tls_start.settings

            tssl_client = test_quic.SSLTest(alpn=["h3"])
            assert self.quic_do_handshake(tssl_client, tssl_server)
            san = tssl_client.quic.tls._peer_certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            assert san.value.get_values_for_type(x509.DNSName) == [
                "example.mitmproxy.org"
            ]

    def test_tls_start_server_cannot_verify(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            ctx.server.sni = ""  # explicitly opt out of using the address.

            tls_start = tls.TlsData(ctx.server, context=ctx)
            with pytest.raises(
                ValueError, match="Cannot validate certificate hostname without SNI"
            ):
                ta.tls_start_server(tls_start)

    def test_tls_start_server_verify_failed(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.client.alpn_offers = [b"h2"]
            ctx.client.cipher_list = ["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-SHA"]
            ctx.server.address = ("example.mitmproxy.org", 443)

            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            tssl_client = tls_start.ssl_conn
            tssl_server = test_tls.SSLTest(server_side=True)
            with pytest.raises(SSL.Error, match="certificate verify failed"):
                assert self.do_handshake(tssl_client, tssl_server)

    @pytest.mark.parametrize("hostname", ["example.mitmproxy.org", "192.0.2.42"])
    def test_tls_start_server_verify_ok(self, hostname, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = (hostname, 443)
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=tdata.path(
                    "mitmproxy/net/data/verificationcerts/trusted-root.crt"
                ),
            )

            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            tssl_client = tls_start.ssl_conn

            # assert that a preexisting ssl_conn is not overwritten
            ta.tls_start_server(tls_start)
            assert tssl_client is tls_start.ssl_conn

            tssl_server = test_tls.SSLTest(server_side=True, sni=hostname.encode())
            assert self.do_handshake(tssl_client, tssl_server)

    @pytest.mark.parametrize("hostname", ["example.mitmproxy.org", "192.0.2.42"])
    def test_quic_start_server_verify_ok(self, hostname, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = (hostname, 443)
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=tdata.path(
                    "mitmproxy/net/data/verificationcerts/trusted-root.crt"
                ),
            )

            tls_start = quic.QuicTlsData(ctx.server, context=ctx)
            ta.quic_start_server(tls_start)
            settings_client = tls_start.settings
            settings_client.alpn_protocols = ["h3"]
            tssl_client = test_quic.SSLTest(settings=settings_client)

            # assert that a preexisting ssl_conn is not overwritten
            ta.quic_start_server(tls_start)
            assert settings_client is tls_start.settings

            tssl_server = test_quic.SSLTest(
                server_side=True, sni=hostname.encode(), alpn=["h3"]
            )
            assert self.quic_do_handshake(tssl_client, tssl_server)

    def test_tls_start_server_insecure(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)

            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_insecure=True,
                http2=False,
                ciphers_server="ALL",
            )
            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            tssl_client = tls_start.ssl_conn
            tssl_server = test_tls.SSLTest(server_side=True)
            assert self.do_handshake(tssl_client, tssl_server)

    def test_quic_start_server_insecure(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            ctx.client.alpn_offers = [b"h3"]

            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_insecure=True,
                ciphers_server="CHACHA20_POLY1305_SHA256",
            )
            tls_start = quic.QuicTlsData(ctx.server, context=ctx)
            ta.quic_start_server(tls_start)
            tssl_client = test_quic.SSLTest(settings=tls_start.settings)
            tssl_server = test_quic.SSLTest(server_side=True, alpn=["h3"])
            assert self.quic_do_handshake(tssl_client, tssl_server)

    def test_alpn_selection(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            tls_start = tls.TlsData(ctx.server, context=ctx)

            def assert_alpn(http2, client_offers, expected):
                tctx.configure(ta, http2=http2)
                ctx.client.alpn_offers = client_offers
                ctx.server.alpn_offers = None
                tls_start.ssl_conn = None
                ta.tls_start_server(tls_start)
                assert ctx.server.alpn_offers == expected

            assert_alpn(
                True,
                (proxy_tls.HTTP2_ALPN, *proxy_tls.HTTP1_ALPNS, b"foo"),
                (proxy_tls.HTTP2_ALPN, *proxy_tls.HTTP1_ALPNS, b"foo"),
            )
            assert_alpn(
                False,
                (proxy_tls.HTTP2_ALPN, *proxy_tls.HTTP1_ALPNS, b"foo"),
                (*proxy_tls.HTTP1_ALPNS, b"foo"),
            )
            assert_alpn(True, [], [])
            assert_alpn(False, [], [])
            ctx.client.timestamp_tls_setup = time.time()
            # make sure that we don't upgrade h1 to h2,
            # see comment in tlsconfig.py
            assert_alpn(True, [], [])

    def test_no_h2_proxy(self, tdata):
        """Do not negotiate h2 on the client<->proxy connection in secure web proxy mode,
        https://github.com/mitmproxy/mitmproxy/issues/4689"""

        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                certs=[
                    tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.pem")
                ],
            )

            ctx = _ctx(tctx.options)
            # mock up something that looks like a secure web proxy.
            ctx.layers = [modes.HttpProxy(ctx), 123]
            tls_start = tls.TlsData(ctx.client, context=ctx)
            ta.tls_start_client(tls_start)
            assert tls_start.ssl_conn.get_app_data()["client_alpn"] == b"http/1.1"

    @pytest.mark.parametrize(
        "client_certs",
        [
            "mitmproxy/net/data/verificationcerts/trusted-leaf.pem",
            "mitmproxy/net/data/verificationcerts/",
        ],
    )
    def test_client_cert_file(self, tdata, client_certs):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            tctx.configure(
                ta,
                client_certs=tdata.path(client_certs),
                ssl_verify_upstream_trusted_ca=tdata.path(
                    "mitmproxy/net/data/verificationcerts/trusted-root.crt"
                ),
            )

            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            tssl_client = tls_start.ssl_conn
            tssl_server = test_tls.SSLTest(server_side=True)

            assert self.do_handshake(tssl_client, tssl_server)
            assert tssl_server.obj.getpeercert()

    async def test_ca_expired(self, monkeypatch, caplog):
        monkeypatch.setattr(certs.Cert, "has_expired", lambda self: True)
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta):
            ta.configure(["confdir"])
            assert "The mitmproxy certificate authority has expired" in caplog.text

    @pytest.mark.parametrize(
        "cert,expect_crl",
        [
            pytest.param(
                "mitmproxy/net/data/verificationcerts/trusted-leaf.crt",
                True,
                id="with-crl",
            ),
            pytest.param(
                "mitmproxy/net/data/verificationcerts/trusted-root.crt",
                False,
                id="without-crl",
            ),
            pytest.param(
                "mitmproxy/net/data/verificationcerts/invalid-crl.crt",
                False,
                id="invalid-crl",
            ),
        ],
    )
    def test_crl_substitution(self, tdata, cert, expect_crl) -> None:
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ta.configure(["confdir"])
            ctx = _ctx(tctx.options)
            with open(tdata.path(cert), "rb") as f:
                ctx.server.certificate_list = [certs.Cert.from_pem(f.read())]

            crt = ta.get_cert(ctx)

            if expect_crl:
                assert crt.cert.crl_distribution_points[0].endswith(ta.crl_path())
            else:
                assert not crt.cert.crl_distribution_points

    def test_crl_request(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta):
            ta.configure(["confdir"])

            f = tflow.tflow(req=tflow.treq(path="/other.crl"))
            ta.request(f)
            assert not f.response

            f = tflow.tflow(req=tflow.treq(path=ta.crl_path()))
            ta.request(f)
            assert f.response

            f = tflow.tflow(req=tflow.treq(path=ta.crl_path()), live=False)
            ta.request(f)
            assert not f.response


def test_default_ciphers():
    assert (
        tlsconfig._default_ciphers(net_tls.Version.TLS1_3) == tlsconfig._DEFAULT_CIPHERS
    )
    assert (
        tlsconfig._default_ciphers(net_tls.Version.SSL3)
        == tlsconfig._DEFAULT_CIPHERS_WITH_SECLEVEL_0
    )
    assert (
        tlsconfig._default_ciphers(net_tls.Version.UNBOUNDED)
        == tlsconfig._DEFAULT_CIPHERS_WITH_SECLEVEL_0
    )
