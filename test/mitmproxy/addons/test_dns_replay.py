import ipaddress
import struct

import pytest

from mitmproxy import dns
from mitmproxy import exceptions
from mitmproxy import io
from mitmproxy.addons import dns_replay
from mitmproxy.addons import dns_resolver
from mitmproxy.net.dns import domain_names
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from mitmproxy.test import tutils


def tdump(path, flows):
    with open(path, "wb") as f:
        w = io.FlowWriter(f)
        for flow in flows:
            w.add(flow)


def a_rr(name: str, ip: str, ttl: int = 300) -> dns.ResourceRecord:
    return dns.ResourceRecord(
        name, dns.types.A, dns.classes.IN, ttl, ipaddress.ip_address(ip).packed
    )


def aaaa_rr(name: str, ip: str, ttl: int = 300) -> dns.ResourceRecord:
    return dns.ResourceRecord(
        name, dns.types.AAAA, dns.classes.IN, ttl, ipaddress.ip_address(ip).packed
    )


def recorded_flow(
    name: str = "example.com",
    qtype: int = dns.types.A,
    *,
    answers=None,
    authorities=None,
    additionals=None,
    response_code=dns.response_codes.NOERROR,
    truncation: bool = False,
    req_additionals=None,
    id: int = 0x1234,
) -> dns.DNSFlow:
    question = dns.Question(name, qtype, dns.classes.IN)
    req = tutils.tdnsreq(
        id=id,
        questions=[question],
        additionals=req_additionals or [],
    )
    resp = tutils.tdnsresp(
        id=id,
        questions=[question],
        response_code=response_code,
        truncation=truncation,
        answers=answers or [],
        authorities=authorities or [],
        additionals=additionals or [],
    )
    return tflow.tdnsflow(req=req, resp=resp)


def live_query(
    name: str = "example.com",
    qtype: int = dns.types.A,
    *,
    id: int = 0xABCD,
    transport_protocol: str = "udp",
    questions=None,
    additionals=None,
    op_code: int = dns.op_codes.QUERY,
    live: bool = True,
) -> dns.DNSFlow:
    req = tutils.tdnsreq(
        id=id,
        op_code=op_code,
        questions=questions
        or [dns.Question(name, qtype, dns.classes.IN)],
        additionals=additionals or [],
    )
    f = tflow.tdnsflow(req=req, live=live)
    f.client_conn.transport_protocol = transport_protocol
    f.server_conn.transport_protocol = transport_protocol
    return f


def test_configure_loads_file(tmpdir):
    dr = dns_replay.DnsReplay()
    with taddons.context(dr) as tctx:
        fpath = str(tmpdir.join("flows"))
        tdump(fpath, [recorded_flow()])
        tctx.configure(dr, dns_replay=[fpath])
        assert dr.count() == 1

        with pytest.raises(exceptions.OptionsError):
            dr.configured = False
            tctx.configure(dr, dns_replay=["/nonexistent"])


def test_load_file_failure_keeps_old_set(tmpdir):
    dr = dns_replay.DnsReplay()
    with taddons.context(dr):
        fpath = str(tmpdir.join("flows"))
        tdump(fpath, [recorded_flow(answers=[a_rr("example.com", "1.1.1.1")])])
        dr.load_file(fpath)
        assert dr.count() == 1

        with pytest.raises(exceptions.CommandError):
            dr.load_file("/nonexistent")
        # the previous set is still in place, no half-loaded data
        assert dr.count() == 1
        f = live_query()
        dr.dns_request(f)
        assert f.response
        assert f.response.answers

        corrupt = str(tmpdir.join("corrupt"))
        with open(corrupt, "wb") as f_:
            f_.write(b"\x00not a tnetstring")
        with pytest.raises(exceptions.CommandError):
            dr.load_file(corrupt)
        assert dr.count() == 1


def test_replace_and_add_flows():
    dr = dns_replay.DnsReplay()
    with taddons.context(dr):
        first = recorded_flow(answers=[a_rr("example.com", "1.1.1.1")])
        second = recorded_flow(answers=[a_rr("example.com", "2.2.2.2")])
        other = recorded_flow(
            name="other.example", answers=[a_rr("other.example", "3.3.3.3")]
        )

        dr.load_flows([first])
        assert dr.count() == 1
        # replacing drops the old set entirely
        dr.load_flows([other])
        assert dr.count() == 1
        f = live_query()
        dr.dns_request(f)
        assert not f.response

        # adding keeps existing entries
        dr.add_flows([first])
        assert dr.count() == 2

        # for duplicate queries, the last complete answer loaded wins
        dr.add_flows([second])
        f = live_query()
        dr.dns_request(f)
        assert f.response.answers[0].data == ipaddress.ip_address("2.2.2.2").packed


def test_replay_uses_current_id_and_question_and_preserves_records():
    dr = dns_replay.DnsReplay()
    recorded = recorded_flow(
        answers=[a_rr("example.com", "5.6.7.8", ttl=42)],
    )
    with taddons.context(dr):
        dr.load_flows([recorded])

        # matching ignores domain name case and a trailing dot
        assert dr._key(dns.Question("EXAMPLE.com.", dns.types.A, dns.classes.IN)) == (
            "example.com",
            dns.types.A,
        )

        # case is ignored when matching, but the current question is echoed
        # back verbatim
        f = live_query("ExAmPlE.CoM", id=0xABCD)
        dr.dns_request(f)
        assert f.is_replay == "response"
        assert f.response.id == 0xABCD
        assert f.response.questions == f.request.questions
        assert f.response.questions[0].name == "ExAmPlE.CoM"
        assert f.response.answers[0].data == ipaddress.ip_address("5.6.7.8").packed
        assert f.response.answers[0].ttl == 42

        # each reply is independent and gets its own transaction id
        f2 = live_query("example.com", id=0xDCBA)
        dr.dns_request(f2)
        assert f2.response.id == 0xDCBA
        assert f.response is not f2.response
        assert f.response.answers is not f2.response.answers

        # mutating one reply does not corrupt the recording or later replies
        f.response.answers[0].data = b"\x09\x09\x09\x09"
        f3 = live_query("example.com", id=1)
        dr.dns_request(f3)
        assert f3.response.answers[0].data == ipaddress.ip_address("5.6.7.8").packed
        assert dr.library[("example.com", dns.types.A)].answers[0].data == (
            ipaddress.ip_address("5.6.7.8").packed
        )
        assert dr.library[("example.com", dns.types.A)].id == 0x1234


def test_record_type_is_part_of_key():
    dr = dns_replay.DnsReplay()
    a = recorded_flow("example.com", dns.types.A, answers=[a_rr("example.com", "1.2.3.4")])
    aaaa = recorded_flow(
        "example.com", dns.types.AAAA, answers=[aaaa_rr("example.com", "::1")]
    )
    with taddons.context(dr):
        dr.load_flows([a, aaaa])
        assert dr.count() == 2

        f = live_query(qtype=dns.types.A)
        dr.dns_request(f)
        assert f.response.answers[0].data == ipaddress.ip_address("1.2.3.4").packed

        f = live_query(qtype=dns.types.AAAA)
        dr.dns_request(f)
        assert f.response.answers[0].data == ipaddress.ip_address("::1").packed


def test_negative_answer_is_replayed_verbatim():
    soa_rdata = (
        domain_names.pack("ns.example.com")
        + domain_names.pack("hostmaster.example.com")
        + struct.pack("!IIIII", 2025010101, 7200, 3600, 1209600, 60)
    )
    soa = dns.ResourceRecord(
        "example.com", dns.types.SOA, dns.classes.IN, 3600, soa_rdata
    )
    dr = dns_replay.DnsReplay()
    recorded = recorded_flow(
        response_code=dns.response_codes.NXDOMAIN,
        authorities=[soa],
    )
    with taddons.context(dr):
        dr.load_flows([recorded])

        f = live_query()
        dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.NXDOMAIN
        assert f.response.answers == []
        assert len(f.response.authorities) == 1
        assert f.response.authorities[0].type == dns.types.SOA
        assert f.response.authorities[0].ttl == 3600
        assert f.response.authorities[0].data == soa_rdata


def test_ttls_do_not_age():
    dr = dns_replay.DnsReplay()
    recorded = recorded_flow(
        answers=[a_rr("example.com", "5.6.7.8", ttl=7)],
    )
    with taddons.context(dr):
        dr.load_flows([recorded])
        for _ in range(3):
            f = live_query()
            dr.dns_request(f)
            assert f.response.answers[0].ttl == 7


def _large_response() -> dns.DNSFlow:
    name = "many.example"
    answers = [
        dns.ResourceRecord(
            name,
            dns.types.A,
            dns.classes.IN,
            123,
            bytes([10, 0, 0, i]),
        )
        for i in range(40)
    ]
    return recorded_flow(name, answers=answers)


def test_udp_truncation_then_tcp_full_answer():
    dr = dns_replay.DnsReplay()
    with taddons.context(dr):
        dr.load_flows([_large_response()])
        key = ("many.example", dns.types.A)
        assert len(dr.library[key].packed) > 512

        # over UDP the response is marked truncated and fits into 512 bytes
        udp = live_query("many.example", transport_protocol="udp")
        dr.dns_request(udp)
        udp_bytes = udp.response.packed
        assert len(udp_bytes) <= 512
        udp_msg = dns.DNSMessage.unpack(udp_bytes)
        assert udp_msg.truncation
        assert udp_msg.answers == []
        assert udp_msg.id == 0xABCD

        # after the client switches to TCP it gets the complete recording
        tcp = live_query("many.example", transport_protocol="tcp")
        dr.dns_request(tcp)
        tcp_bytes = tcp.response.packed
        assert len(tcp_bytes) > 512
        tcp_msg = dns.DNSMessage.unpack(tcp_bytes)
        assert not tcp_msg.truncation
        assert len(tcp_msg.answers) == 40
        assert tcp_msg.answers[0].ttl == 123
        assert tcp_msg.answers[-1].data == bytes([10, 0, 0, 39])

        # the stored recording is not corrupted by truncation
        assert not dr.library[key].truncation
        assert len(dr.library[key].answers) == 40


def test_small_udp_responses_are_not_truncated():
    dr = dns_replay.DnsReplay()
    with taddons.context(dr):
        dr.load_flows([recorded_flow(answers=[a_rr("example.com", "1.2.3.4")])])
        f = live_query(transport_protocol="udp")
        dr.dns_request(f)
        assert not f.response.truncation
        assert len(f.response.answers) == 1
        assert len(f.response.packed) <= 512


@pytest.mark.parametrize(
    "kwargs",
    [
        # unsupported record type
        dict(questions=[dns.Question("example.com", dns.types.TXT, dns.classes.IN)]),
        # unsupported class
        dict(questions=[dns.Question("example.com", dns.types.A, dns.classes.CH)]),
        # more than one question
        dict(
            questions=[
                dns.Question("a.example", dns.types.A, dns.classes.IN),
                dns.Question("b.example", dns.types.A, dns.classes.IN),
            ]
        ),
        # EDNS OPT meta record
        dict(
            additionals=[
                dns.ResourceRecord("", dns.types.OPT, 4096, 0, b"")
            ]
        ),
    ],
)
def test_unsupported_forward(kwargs):
    dr = dns_replay.DnsReplay()
    with taddons.context(dr):
        dr.load_flows([recorded_flow()])
        f = live_query(**kwargs)
        dr.dns_request(f)
        assert not f.response
        assert not f.error


def test_unsupported_opcode_refused():
    dr = dns_replay.DnsReplay()
    with taddons.context(dr) as tctx:
        dr.load_flows([recorded_flow()])
        tctx.configure(dr, dns_replay_extra="refuse")
        f = live_query(op_code=dns.op_codes.STATUS)
        dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.REFUSED


def test_miss_and_unsupported_refused():
    dr = dns_replay.DnsReplay()
    with taddons.context(dr) as tctx:
        dr.load_flows([recorded_flow()])
        tctx.configure(dr, dns_replay_extra="refuse")

        # recorded domain, but no AAAA recording
        f = live_query(qtype=dns.types.AAAA)
        dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.REFUSED
        assert f.response.answers == []

        # entirely unrecorded domain
        f = live_query("unseen.example")
        dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.REFUSED

        # unsupported query type
        f = live_query(
            questions=[dns.Question("example.com", dns.types.TXT, dns.classes.IN)]
        )
        dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.REFUSED


async def test_refuse_does_not_trigger_upstream(monkeypatch):
    dr = dns_replay.DnsReplay()
    resolver = dns_resolver.DnsResolver()

    def boom(self, message):  # pragma: no cover
        raise AssertionError("refusal must not be resolved upstream")

    monkeypatch.setattr(dns_resolver.DnsResolver, "resolve", boom)

    with taddons.context(dr, resolver) as tctx:
        dr.load_flows([recorded_flow()])
        tctx.configure(dr, dns_replay_extra="refuse")

        f = live_query("unseen.example")
        dr.dns_request(f)
        await resolver.dns_request(f)
        assert f.response.response_code == dns.response_codes.REFUSED


def test_ignored_recordings():
    http_flow = tflow.tflow(resp=True)
    no_response = tflow.tdnsflow()
    truncated = recorded_flow(truncation=True)
    edns_request = recorded_flow(
        req_additionals=[dns.ResourceRecord("", dns.types.OPT, 4096, 0, b"")]
    )
    signed_answer = recorded_flow(
        answers=[
            dns.ResourceRecord(
                "example.com", dns.types.RRSIG, dns.classes.IN, 300, b"\x00" * 16
            )
        ]
    )
    tsig_additional = recorded_flow(
        additionals=[
            dns.ResourceRecord("", dns.types.TSIG, dns.types.ANY, 0, b"\x00")
        ]
    )

    dr = dns_replay.DnsReplay()
    with taddons.context(dr):
        dr.load_flows(
            [
                http_flow,
                no_response,
                truncated,
                edns_request,
                signed_answer,
                tsig_additional,
            ]
        )
        assert dr.count() == 0


def test_skip_guards():
    dr = dns_replay.DnsReplay()
    with taddons.context(dr):
        dr.load_flows([recorded_flow()])

        # already answered
        f = live_query()
        f.response = f.request.fail(dns.response_codes.SERVFAIL)
        dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.SERVFAIL

        # not live
        f = live_query(live=False)
        dr.dns_request(f)
        assert not f.response

        # error already set
        f = live_query()
        f.error = tflow.terr()
        dr.dns_request(f)
        assert not f.response


def test_stop_restores_normal_resolution():
    dr = dns_replay.DnsReplay()
    with taddons.context(dr):
        dr.load_flows([recorded_flow()])
        f = live_query()
        dr.dns_request(f)
        assert f.response

        dr.clear()
        assert dr.count() == 0
        f = live_query()
        dr.dns_request(f)
        assert not f.response
