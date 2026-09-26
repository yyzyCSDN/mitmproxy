import logging
import urllib

import pytest

import mitmproxy.test.tutils
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import io
from mitmproxy.addons import serverplayback
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def tdump(path, flows):
    with open(path, "wb") as f:
        w = io.FlowWriter(f)
        for i in flows:
            w.add(i)


def test_load_file(tmpdir):
    s = serverplayback.ServerPlayback()
    with taddons.context(s):
        fpath = str(tmpdir.join("flows"))
        tdump(fpath, [tflow.tflow(resp=True)])
        s.load_file(fpath)
        assert s.flowmap
        with pytest.raises(exceptions.CommandError):
            s.load_file("/nonexistent")


def test_config(tmpdir):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        fpath = str(tmpdir.join("flows"))
        tdump(fpath, [tflow.tflow(resp=True)])
        tctx.configure(s, server_replay=[fpath])
        s.configured = False
        with pytest.raises(exceptions.OptionsError):
            tctx.configure(s, server_replay=[str(tmpdir)])


def test_server_playback():
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp)
        f = tflow.tflow(resp=True)

        assert not sp.flowmap

        sp.load_flows([f])
        assert sp.flowmap
        assert sp.next_flow(f)
        assert not sp.flowmap

        sp.load_flows([f])
        assert sp.flowmap
        sp.clear()
        assert not sp.flowmap


def test_add_flows():
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp)
        f1 = tflow.tflow(resp=True)
        f2 = tflow.tflow(resp=True)

        sp.load_flows([f1])
        sp.add_flows([f2])

        assert sp.next_flow(f1)
        assert sp.flowmap
        assert sp.next_flow(f2)
        assert not sp.flowmap

        sp.add_flows([f1])
        assert sp.flowmap
        assert sp.next_flow(f1)
        assert not sp.flowmap


def test_ignore_host():
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp, server_replay_ignore_host=True)

        r = tflow.tflow(resp=True)
        r2 = tflow.tflow(resp=True)

        r.request.host = "address"
        r2.request.host = "address"
        assert sp._hash(r) == sp._hash(r2)
        r2.request.host = "wrong_address"
        assert sp._hash(r) == sp._hash(r2)


def test_ignore_content():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_ignore_content=False)

        r = tflow.tflow(resp=True)
        r2 = tflow.tflow(resp=True)

        r.request.content = b"foo"
        r2.request.content = b"foo"
        assert s._hash(r) == s._hash(r2)
        r2.request.content = b"bar"
        assert not s._hash(r) == s._hash(r2)

        tctx.configure(s, server_replay_ignore_content=True)
        r = tflow.tflow(resp=True)
        r2 = tflow.tflow(resp=True)
        r.request.content = b"foo"
        r2.request.content = b"foo"
        assert s._hash(r) == s._hash(r2)
        r2.request.content = b"bar"
        assert s._hash(r) == s._hash(r2)
        r2.request.content = b""
        assert s._hash(r) == s._hash(r2)
        r2.request.content = None
        assert s._hash(r) == s._hash(r2)


def test_ignore_content_wins_over_params():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(
            s,
            server_replay_ignore_content=True,
            server_replay_ignore_payload_params=["param1", "param2"],
        )

        # NOTE: parameters are mutually exclusive in options
        r = tflow.tflow(resp=True)
        r.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        r.request.content = b"paramx=y"

        r2 = tflow.tflow(resp=True)
        r2.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        r2.request.content = b"paramx=x"

        # same parameters
        assert s._hash(r) == s._hash(r2)


def test_ignore_payload_params_other_content_type():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(
            s,
            server_replay_ignore_content=False,
            server_replay_ignore_payload_params=["param1", "param2"],
        )

        r = tflow.tflow(resp=True)
        r.request.headers["Content-Type"] = "application/json"
        r.request.content = b'{"param1":"1"}'
        r2 = tflow.tflow(resp=True)
        r2.request.headers["Content-Type"] = "application/json"
        r2.request.content = b'{"param1":"1"}'
        # same content
        assert s._hash(r) == s._hash(r2)
        # distint content (note only x-www-form-urlencoded payload is analysed)
        r2.request.content = b'{"param1":"2"}'
        assert not s._hash(r) == s._hash(r2)


def test_hash():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s)

        r = tflow.tflow()
        r2 = tflow.tflow()

        assert s._hash(r)
        assert s._hash(r) == s._hash(r2)
        r.request.headers["foo"] = "bar"
        assert s._hash(r) == s._hash(r2)
        r.request.path = "voing"
        assert s._hash(r) != s._hash(r2)

        r.request.path = "path?blank_value"
        r2.request.path = "path?"
        assert s._hash(r) != s._hash(r2)


def test_headers():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_use_headers=["foo"])

        r = tflow.tflow(resp=True)
        r.request.headers["foo"] = "bar"
        r2 = tflow.tflow(resp=True)
        assert not s._hash(r) == s._hash(r2)
        r2.request.headers["foo"] = "bar"
        assert s._hash(r) == s._hash(r2)
        r2.request.headers["oink"] = "bar"
        assert s._hash(r) == s._hash(r2)

        r = tflow.tflow(resp=True)
        r2 = tflow.tflow(resp=True)
        assert s._hash(r) == s._hash(r2)


def test_load():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s)

        r = tflow.tflow(resp=True)
        r.request.headers["key"] = "one"

        r2 = tflow.tflow(resp=True)
        r2.request.headers["key"] = "two"

        s.load_flows([r, r2])

        assert s.count() == 2

        n = s.next_flow(r)
        assert n.request.headers["key"] == "one"
        assert s.count() == 1

        n = s.next_flow(r)
        assert n.request.headers["key"] == "two"
        assert not s.flowmap
        assert s.count() == 0

        assert not s.next_flow(r)


def test_load_with_server_replay_reuse():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reuse=True)

        r = tflow.tflow(resp=True)
        r.request.headers["key"] = "one"

        r2 = tflow.tflow(resp=True)
        r2.request.headers["key"] = "two"

        s.load_flows([r, r2])

        assert s.count() == 2
        s.next_flow(r)
        assert s.count() == 2


def test_ignore_params():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_ignore_params=["param1", "param2"])

        r = tflow.tflow(resp=True)
        r.request.path = "/test?param1=1"
        r2 = tflow.tflow(resp=True)
        r2.request.path = "/test"
        assert s._hash(r) == s._hash(r2)
        r2.request.path = "/test?param1=2"
        assert s._hash(r) == s._hash(r2)
        r2.request.path = "/test?param2=1"
        assert s._hash(r) == s._hash(r2)
        r2.request.path = "/test?param3=2"
        assert not s._hash(r) == s._hash(r2)


def thash(r, r2, setter):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        s = serverplayback.ServerPlayback()
        tctx.configure(s, server_replay_ignore_payload_params=["param1", "param2"])

        setter(r, paramx="x", param1="1")

        setter(r2, paramx="x", param1="1")
        # same parameters
        assert s._hash(r) == s._hash(r2)
        # ignored parameters !=
        setter(r2, paramx="x", param1="2")
        assert s._hash(r) == s._hash(r2)
        # missing parameter
        setter(r2, paramx="x")
        assert s._hash(r) == s._hash(r2)
        # ignorable parameter added
        setter(r2, paramx="x", param1="2")
        assert s._hash(r) == s._hash(r2)
        # not ignorable parameter changed
        setter(r2, paramx="y", param1="1")
        assert not s._hash(r) == s._hash(r2)
        # not ignorable parameter missing
        setter(r2, param1="1")
        r2.request.content = b"param1=1"
        assert not s._hash(r) == s._hash(r2)


def test_ignore_payload_params():
    def urlencode_setter(r, **kwargs):
        r.request.content = urllib.parse.urlencode(kwargs).encode()

    r = tflow.tflow(resp=True)
    r.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
    r2 = tflow.tflow(resp=True)
    r2.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
    thash(r, r2, urlencode_setter)

    boundary = "somefancyboundary"

    def multipart_setter(r, **kwargs):
        b = f"--{boundary}\n"
        parts = []
        for k, v in kwargs.items():
            parts.append('Content-Disposition: form-data; name="%s"\n\n%s\n' % (k, v))
        c = b + b.join(parts) + b
        r.request.content = c.encode()
        r.request.headers["content-type"] = "multipart/form-data; boundary=" + boundary

    r = tflow.tflow(resp=True)
    r2 = tflow.tflow(resp=True)
    thash(r, r2, multipart_setter)


def test_runtime_modify_params():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        r = tflow.tflow(resp=True)
        r.request.path = "/test?param1=1"
        r2 = tflow.tflow(resp=True)
        r2.request.path = "/test"

        s.load_flows([r])
        hash = next(iter(s.flowmap.keys()))

        tctx.configure(s, server_replay_ignore_params=["param1"])
        hash_mod = next(iter(s.flowmap.keys()))

        assert hash != hash_mod
        assert hash_mod == s._hash(r2)


def test_server_playback_full():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(
            s,
            server_replay_refresh=True,
        )

        f = tflow.tflow()
        f.response = mitmproxy.test.tutils.tresp(content=f.request.content)
        s.load_flows([f, f])

        tf = tflow.tflow()
        assert not tf.response
        s.request(tf)
        assert tf.response.data == f.response.data

        tf = tflow.tflow()
        tf.request.content = b"gibble"
        assert not tf.response
        s.request(tf)
        assert not tf.response


async def test_server_playback_kill():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_refresh=True, server_replay_kill_extra=True)

        f = tflow.tflow()
        f.response = mitmproxy.test.tutils.tresp(content=f.request.content)
        s.load_flows([f])

        f = tflow.tflow()
        f.request.host = "nonexistent"
        await tctx.cycle(s, f)
        assert f.error


async def test_server_playback_kill_new_option():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_refresh=True, server_replay_extra="kill")

        f = tflow.tflow()
        f.response = mitmproxy.test.tutils.tresp(content=f.request.content)
        s.load_flows([f])

        f = tflow.tflow()
        f.request.host = "nonexistent"
        await tctx.cycle(s, f)
        assert f.error


@pytest.mark.parametrize(
    "option,status",
    [
        ("204", 204),
        ("400", 400),
        ("404", 404),
        ("500", 500),
    ],
)
async def test_server_playback_404(option, status):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_refresh=True, server_replay_extra=option)

        f = tflow.tflow()
        f.response = mitmproxy.test.tutils.tresp(content=f.request.content)
        s.load_flows([f])

        f = tflow.tflow()
        f.request.host = "nonexistent"
        s.request(f)
        assert f.response.status_code == status


def test_server_playback_response_deleted():
    """
    The server playback addon holds references to flows that can be modified by the user in the meantime.
    One thing that can happen is that users remove the response object. This happens for example when doing a client
    replay at the same time.
    """
    sp = serverplayback.ServerPlayback()
    with taddons.context(sp) as tctx:
        tctx.configure(sp)
        f1 = tflow.tflow(resp=True)
        f2 = tflow.tflow(resp=True)

        assert not sp.flowmap

        sp.load_flows([f1, f2])
        assert sp.flowmap

        f1.response = f2.response = None
        assert not sp.next_flow(f1)
        assert not sp.flowmap


# ---------------------------------------------------------------------------
# server_replay_reconstruct: mixed 200/304 recordings
# ---------------------------------------------------------------------------

LAST_MODIFIED = "Mon, 01 Jan 2024 00:00:00 GMT"
LAST_MODIFIED_OLDER = "Sun, 31 Dec 2023 00:00:00 GMT"
RECON_LOGGER = "mitmproxy.addons.serverplayback"


def recorded_get(
    *,
    status: int = 200,
    body: bytes | None = None,
    req_headers: tuple[tuple[str, str], ...] = (),
    resp_headers: tuple[tuple[str, str], ...] = (),
    end: float,
    start: float | None = None,
) -> http.HTTPFlow:
    f = tflow.tflow()
    for name, value in req_headers:
        f.request.headers[name] = value
    if body is None:
        body = b"" if status == 304 else b"message"
    raw_headers = [
        (name.encode("ascii"), value.encode("ascii")) for name, value in resp_headers
    ]
    response = http.Response.make(status, body, raw_headers)
    if status == 304:
        response.reason = b"Not Modified"
    response.timestamp_start = start if start is not None else end - 10
    response.timestamp_end = end
    f.response = response
    return f


def client_get(headers: tuple[tuple[str, str], ...] = ()) -> http.HTTPFlow:
    f = tflow.tflow()
    for name, value in headers:
        f.request.headers[name] = value
    return f


def full_entity(
    *,
    etag: str | None = '"v1"',
    body=b"hello",
    resp_headers: tuple[tuple[str, str], ...] = (),
    req_headers: tuple[tuple[str, str], ...] = (),
    end: float = 1000.0,
) -> http.HTTPFlow:
    headers = []
    if etag is not None:
        headers.append(("etag", etag))
    headers.append(("last-modified", LAST_MODIFIED))
    headers.extend(resp_headers)
    return recorded_get(
        status=200,
        body=body,
        req_headers=req_headers,
        resp_headers=tuple(headers),
        end=end,
    )


def not_modified(
    *,
    req_headers: tuple[tuple[str, str], ...] = (("if-none-match", '"v1"'),),
    resp_headers: tuple[tuple[str, str], ...] = (
        ("etag", '"v1"'),
        ("last-modified", LAST_MODIFIED),
    ),
    end: float = 2000.0,
) -> http.HTTPFlow:
    return recorded_get(
        status=304, req_headers=req_headers, resp_headers=resp_headers, end=end
    )


def test_reconstruct_empty_cache_gets_body_and_merged_metadata():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows(
            [
                full_entity(resp_headers=(("cache-control", "max-age=10"),)),
                not_modified(
                    resp_headers=(
                        ("etag", '"v1"'),
                        ("last-modified", LAST_MODIFIED),
                        ("cache-control", "max-age=20"),
                    )
                ),
            ]
        )
        assert len(s.reconstructions) == 2

        first = client_get()
        s.request(first)
        assert first.response.status_code == 200
        assert first.response.content == b"hello"
        assert first.response.headers["cache-control"] == "max-age=10"

        # The recorded 304 is replayed as a complete 200 for an empty cache.
        second = client_get()
        s.request(second)
        assert second.response.status_code == 200
        assert second.response.content == b"hello"
        assert second.response.headers["cache-control"] == "max-age=20"
        assert second.response.headers["etag"] == '"v1"'
        assert second.response.headers["last-modified"] == LAST_MODIFIED
        assert s.count() == 0


def test_reconstruct_conditional_client():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows([full_entity() for _ in range(5)])

        matched = client_get((("if-none-match", '"v1"'),))
        s.request(matched)
        assert matched.response.status_code == 304
        assert matched.response.content == b""
        assert "content-length" not in matched.response.headers
        assert matched.response.headers["etag"] == '"v1"'
        assert matched.response.headers["last-modified"] == LAST_MODIFIED

        wildcard = client_get((("if-none-match", "*"),))
        s.request(wildcard)
        assert wildcard.response.status_code == 304

        weak = client_get((("if-none-match", 'W/"v1"'),))
        s.request(weak)
        assert weak.response.status_code == 304

        fresh = client_get((("if-modified-since", LAST_MODIFIED),))
        s.request(fresh)
        assert fresh.response.status_code == 304

        stale = client_get((("if-modified-since", LAST_MODIFIED_OLDER),))
        s.request(stale)
        assert stale.response.status_code == 200
        assert stale.response.content == b"hello"


def test_reconstruct_if_none_match_takes_precedence():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows([full_entity()])
        # Matching ETag despite an old If-Modified-Since: ETag wins.
        f = client_get(
            (
                ("if-none-match", '"v1"'),
                ("if-modified-since", LAST_MODIFIED_OLDER),
            )
        )
        s.request(f)
        assert f.response.status_code == 304


def test_reconstruct_refresh_preserves_last_modified():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=True)
        s.load_flows(
            [
                full_entity(
                    resp_headers=(("date", LAST_MODIFIED_OLDER),),
                )
            ]
        )
        f = client_get()
        s.request(f)
        # The entity validator stays anchored to the recording ...
        assert f.response.headers["last-modified"] == LAST_MODIFIED
        # ... while the other time-based refresh behaviour is unchanged.
        assert f.response.headers["date"] != LAST_MODIFIED_OLDER


def test_reconstruct_consumed_200_remains_entity_basis():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        full = full_entity()
        modified = not_modified()
        s.load_flows([full, modified])
        assert s.count() == 2

        first = client_get()
        s.request(first)
        assert first.response.content == b"hello"
        assert s.count() == 1

        # The 200 flow was consumed, but still backs the recorded 304.
        second = client_get()
        s.request(second)
        assert second.response.status_code == 200
        assert second.response.content == b"hello"
        assert s.count() == 0
        # The consumed 200 must not re-enter the replay queue.
        assert not s.flowmap


def test_reconstruct_vary_variants_are_not_cross_consumed():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        en_full = full_entity(
            etag='"en"',
            body=b"english",
            req_headers=(("accept-language", "en"),),
            resp_headers=(
                ("vary", "Accept-Language"),
                ("content-language", "en"),
            ),
            end=1000.0,
        )
        en_304 = not_modified(
            req_headers=(
                ("accept-language", "en"),
                ("if-none-match", '"en"'),
            ),
            resp_headers=(
                ("etag", '"en"'),
                ("vary", "Accept-Language"),
            ),
            end=1100.0,
        )
        de_full = full_entity(
            etag='"de"',
            body=b"german",
            req_headers=(("accept-language", "de"),),
            resp_headers=(
                ("vary", "Accept-Language"),
                ("content-language", "de"),
            ),
            end=2000.0,
        )
        de_304 = not_modified(
            req_headers=(
                ("accept-language", "de"),
                ("if-none-match", '"de"'),
            ),
            resp_headers=(
                ("etag", '"de"'),
                ("vary", "Accept-Language"),
            ),
            end=2100.0,
        )
        s.load_flows([en_full, en_304, de_full, de_304])

        first_de = client_get((("accept-language", "de"),))
        s.request(first_de)
        assert first_de.response.content == b"german"
        assert first_de.response.headers["content-language"] == "de"
        assert s.count() == 3

        second_de = client_get((("accept-language", "de"),))
        s.request(second_de)
        assert second_de.response.status_code == 200
        assert second_de.response.content == b"german"
        # The representation language of the 200 is not mixed in.
        assert second_de.response.headers["content-language"] == "de"
        assert s.count() == 2

        first_en = client_get((("accept-language", "en"),))
        s.request(first_en)
        assert first_en.response.content == b"english"
        assert s.count() == 1

        second_en = client_get((("accept-language", "en"),))
        s.request(second_en)
        assert second_en.response.status_code == 200
        assert second_en.response.content == b"english"
        assert second_en.response.headers["content-language"] == "en"
        assert s.count() == 0


def test_reconstruct_merges_only_metadata_a_304_may_update():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows(
            [
                full_entity(
                    resp_headers=(
                        ("content-language", "en"),
                        ("cache-control", "max-age=10"),
                    ),
                ),
                not_modified(
                    resp_headers=(
                        ("etag", '"v1"'),
                        ("last-modified", LAST_MODIFIED),
                        ("cache-control", "max-age=99"),
                        ("content-language", "de"),
                        ("content-encoding", "gzip"),
                        ("content-length", "999"),
                    )
                ),
            ]
        )
        f = client_get()  # consumes the 200
        s.request(f)
        f = client_get()  # consumes the reconstructed 304
        s.request(f)
        assert f.response.status_code == 200
        assert f.response.content == b"hello"
        assert f.response.headers["cache-control"] == "max-age=99"
        assert f.response.headers["content-language"] == "en"
        assert f.response.headers["content-length"] == str(len(b"hello"))
        assert "content-encoding" not in f.response.headers


def test_reconstruct_confirmed_chain_adopts_missing_etag():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        full = full_entity(etag=None)
        first_validation = not_modified(
            req_headers=(("if-modified-since", LAST_MODIFIED),),
            resp_headers=(
                ("etag", '"v1"'),
                ("last-modified", LAST_MODIFIED),
            ),
            end=2000.0,
        )
        second_validation = not_modified(
            req_headers=(("if-none-match", '"v1"'),),
            resp_headers=(("etag", '"v1"'),),
            end=3000.0,
        )
        s.load_flows([full, first_validation, second_validation])
        assert len(s.reconstructions) == 3

        for _ in range(3):
            validated = client_get((("if-none-match", '"v1"'),))
            s.request(validated)
            assert validated.response.status_code == 304


def test_reconstruct_no_earlier_entity_falls_back(caplog):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        caplog.set_level(logging.INFO, logger=RECON_LOGGER)
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows([not_modified(end=1000.0)])
        assert s.reconstructions == {}
        assert "no earlier complete 200 entity" in caplog.text

        # Existing replay behaviour for the recorded 304 is unchanged.
        f = client_get()
        s.request(f)
        assert f.response.status_code == 304
        assert f.response.content == b""


def test_reconstruct_missing_completion_timestamp(caplog):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        caplog.set_level(logging.INFO, logger=RECON_LOGGER)
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        full = full_entity(end=1000.0)
        full.response.timestamp_end = None
        s.load_flows([full, not_modified(end=2000.0)])
        assert s.reconstructions == {}
        assert "completion timestamp is missing" in caplog.text
        assert "no earlier complete 200 entity" in caplog.text


def test_reconstruct_etag_conflict_is_skipped(caplog):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        caplog.set_level(logging.INFO, logger=RECON_LOGGER)
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows(
            [
                full_entity(etag='"v1"'),
                not_modified(
                    req_headers=(("if-none-match", '"v1"'),),
                    resp_headers=(("etag", '"v2"'),),
                ),
            ]
        )
        assert len(s.reconstructions) == 1
        assert "conflicts with entity ETag" in caplog.text


def test_reconstruct_last_modified_conflict_is_skipped(caplog):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        caplog.set_level(logging.INFO, logger=RECON_LOGGER)
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows(
            [
                full_entity(etag='"v1"'),
                not_modified(
                    req_headers=(("if-none-match", '"v1"'),),
                    resp_headers=(
                        ("etag", '"v1"'),
                        ("last-modified", LAST_MODIFIED_OLDER),
                    ),
                ),
            ]
        )
        assert len(s.reconstructions) == 1
        assert "Last-Modified of the 304 conflicts" in caplog.text


def test_reconstruct_vary_star_is_skipped(caplog):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        caplog.set_level(logging.INFO, logger=RECON_LOGGER)
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows([full_entity(resp_headers=(("vary", "*"),))])
        assert s.reconstructions == {}
        assert "Vary: *" in caplog.text


def test_reconstruct_does_not_borrow_bodies_from_later_records(caplog):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        caplog.set_level(logging.INFO, logger=RECON_LOGGER)
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        early_304 = not_modified(end=1000.0)
        late_200 = full_entity(end=2000.0)
        s.load_flows([early_304, late_200])
        assert len(s.reconstructions) == 1
        assert "no earlier complete 200 entity" in caplog.text


def test_reconstruct_304_without_conditional_header_is_skipped(caplog):
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        caplog.set_level(logging.INFO, logger=RECON_LOGGER)
        tctx.configure(s, server_replay_reconstruct=True, server_replay_refresh=False)
        s.load_flows(
            [
                full_entity(),
                recorded_get(
                    status=304,
                    resp_headers=(("etag", '"v1"'),),
                    end=2000.0,
                ),
            ]
        )
        assert len(s.reconstructions) == 1
        assert "conditional header" in caplog.text


def test_reconstruct_disabled_keeps_legacy_behaviour():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s)
        assert not tctx.options.server_replay_reconstruct
        s.load_flows([full_entity(), not_modified()])
        assert s.reconstructions == {}

        first = client_get()
        s.request(first)
        assert first.response.status_code == 200
        assert first.response.content == b"hello"

        second = client_get()
        s.request(second)
        assert second.response.status_code == 304
        assert second.response.content == b""


def test_reconstruct_reuse_with_variants():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(
            s,
            server_replay_reconstruct=True,
            server_replay_reuse=True,
            server_replay_refresh=False,
        )
        s.load_flows(
            [
                full_entity(
                    etag='"en"',
                    body=b"english",
                    req_headers=(("accept-language", "en"),),
                    resp_headers=(("vary", "Accept-Language"),),
                    end=1000.0,
                ),
                full_entity(
                    etag='"de"',
                    body=b"german",
                    req_headers=(("accept-language", "de"),),
                    resp_headers=(("vary", "Accept-Language"),),
                    end=2000.0,
                ),
            ]
        )
        assert s.count() == 2
        for _ in range(2):
            de = client_get((("accept-language", "de"),))
            s.request(de)
            assert de.response.content == b"german"
        en = client_get((("accept-language", "en"),))
        s.request(en)
        assert en.response.content == b"english"
        assert s.count() == 2


def test_reconstruct_toggle_rebuilds_state():
    s = serverplayback.ServerPlayback()
    with taddons.context(s) as tctx:
        tctx.configure(s, server_replay_refresh=False)
        s.load_flows([full_entity(), not_modified()])
        assert s.reconstructions == {}

        tctx.configure(s, server_replay_reconstruct=True)
        assert len(s.reconstructions) == 2

        tctx.configure(s, server_replay_reconstruct=False)
        assert s.reconstructions == {}
        # Legacy replay still works after disabling.
        first = client_get()
        s.request(first)
        assert first.response.status_code == 200
        second = client_get()
        s.request(second)
        assert second.response.status_code == 304
