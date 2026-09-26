import email.utils
import os
import sys
from pathlib import Path

import pytest

from mitmproxy.addons import maplocal as maplocal_module
from mitmproxy.addons.maplocal import _entity_tag_matches
from mitmproxy.addons.maplocal import _if_range_matches
from mitmproxy.addons.maplocal import _parse_byte_ranges
from mitmproxy.addons.maplocal import _parse_entity_tags
from mitmproxy.addons.maplocal import _satisfiable_ranges
from mitmproxy.addons.maplocal import file_candidates
from mitmproxy.addons.maplocal import MapLocal
from mitmproxy.addons.maplocal import MapLocalSpec
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from mitmproxy.utils.spec import parse_spec


@pytest.mark.parametrize(
    "url,spec,expected_candidates",
    [
        # trailing slashes
        ("https://example.com/foo", ":example.com/foo:/tmp", ["/tmp/index.html"]),
        ("https://example.com/foo/", ":example.com/foo:/tmp", ["/tmp/index.html"]),
        ("https://example.com/foo", ":example.com/foo:/tmp/", ["/tmp/index.html"]),
    ]
    + [
        # simple prefixes
        (
            "http://example.com/foo/bar.jpg",
            ":example.com/foo:/tmp",
            ["/tmp/bar.jpg", "/tmp/bar.jpg/index.html"],
        ),
        (
            "https://example.com/foo/bar.jpg",
            ":example.com/foo:/tmp",
            ["/tmp/bar.jpg", "/tmp/bar.jpg/index.html"],
        ),
        (
            "https://example.com/foo/bar.jpg?query",
            ":example.com/foo:/tmp",
            ["/tmp/bar.jpg", "/tmp/bar.jpg/index.html"],
        ),
        (
            "https://example.com/foo/bar/baz.jpg",
            ":example.com/foo:/tmp",
            ["/tmp/bar/baz.jpg", "/tmp/bar/baz.jpg/index.html"],
        ),
        ("https://example.com/foo/bar.jpg", ":/foo/bar.jpg:/tmp", ["/tmp/index.html"]),
    ]
    + [
        # URL decode and special characters
        (
            "http://example.com/foo%20bar.jpg",
            ":example.com:/tmp",
            [
                "/tmp/foo bar.jpg",
                "/tmp/foo bar.jpg/index.html",
                "/tmp/foo_bar.jpg",
                "/tmp/foo_bar.jpg/index.html",
            ],
        ),
        (
            "http://example.com/fóobår.jpg",
            ":example.com:/tmp",
            [
                "/tmp/fóobår.jpg",
                "/tmp/fóobår.jpg/index.html",
                "/tmp/f_ob_r.jpg",
                "/tmp/f_ob_r.jpg/index.html",
            ],
        ),
    ]
    + [
        # index.html
        ("https://example.com/foo", ":example.com/foo:/tmp", ["/tmp/index.html"]),
        ("https://example.com/foo/", ":example.com/foo:/tmp", ["/tmp/index.html"]),
        (
            "https://example.com/foo/bar",
            ":example.com/foo:/tmp",
            ["/tmp/bar", "/tmp/bar/index.html"],
        ),
        (
            "https://example.com/foo/bar/",
            ":example.com/foo:/tmp",
            ["/tmp/bar", "/tmp/bar/index.html"],
        ),
    ]
    + [
        # regex
        (
            "https://example/view.php?f=foo.jpg",
            ":example/view.php\\?f=(.+):/tmp",
            ["/tmp/foo.jpg", "/tmp/foo.jpg/index.html"],
        ),
        (
            "https://example/results?id=1&foo=2",
            ":example/(results\\?id=.+):/tmp",
            [
                "/tmp/results?id=1&foo=2",
                "/tmp/results?id=1&foo=2/index.html",
                "/tmp/results_id=1_foo=2",
                "/tmp/results_id=1_foo=2/index.html",
            ],
        ),
    ]
    + [
        # test directory traversal detection
        ("https://example.com/../../../../../../etc/passwd", ":example.com:/tmp", []),
        # this is slightly hacky, but werkzeug's behavior differs per system.
        (
            "https://example.com/C:\\foo.txt",
            ":example.com:/tmp",
            []
            if sys.platform == "win32"
            else [
                "/tmp/C:\\foo.txt",
                "/tmp/C:\\foo.txt/index.html",
                "/tmp/C__foo.txt",
                "/tmp/C__foo.txt/index.html",
            ],
        ),
        (
            "https://example.com//etc/passwd",
            ":example.com:/tmp",
            ["/tmp/etc/passwd", "/tmp/etc/passwd/index.html"],
        ),
    ],
)
def test_file_candidates(url, spec, expected_candidates):
    # we circumvent the path existence checks here to simplify testing
    filt, subj, repl = parse_spec(spec)
    spec = MapLocalSpec(filt, subj, Path(repl))

    candidates = file_candidates(url, spec)
    assert [x.as_posix() for x in candidates] == expected_candidates


class TestMapLocal:
    def test_configure(self, tmpdir):
        ml = MapLocal()
        with taddons.context(ml) as tctx:
            tctx.configure(ml, map_local=["/foo/bar/" + str(tmpdir)])
            with pytest.raises(Exception, match="Invalid regular expression"):
                tctx.configure(ml, map_local=["/foo/+/" + str(tmpdir)])
            with pytest.raises(Exception, match="Invalid file path"):
                tctx.configure(ml, map_local=["/foo/.+/three"])

    def test_simple(self, tmpdir):
        ml = MapLocal()

        with taddons.context(ml) as tctx:
            tmpfile = tmpdir.join("foo.jpg")
            tmpfile.write("foo")
            tctx.configure(ml, map_local=["|//example.org/images|" + str(tmpdir)])
            f = tflow.tflow()
            f.request.url = b"https://example.org/images/foo.jpg"
            ml.request(f)
            assert f.response.content == b"foo"

            tmpfile = tmpdir.join("images", "bar.jpg")
            tmpfile.write("bar", ensure=True)
            tctx.configure(ml, map_local=["|//example.org|" + str(tmpdir)])
            f = tflow.tflow()
            f.request.url = b"https://example.org/images/bar.jpg"
            ml.request(f)
            assert f.response.content == b"bar"

            tmpfile = tmpdir.join("foofoobar.jpg")
            tmpfile.write("foofoobar", ensure=True)
            tctx.configure(
                ml, map_local=["|example.org/foo/foo/bar.jpg|" + str(tmpfile)]
            )
            f = tflow.tflow()
            f.request.url = b"https://example.org/foo/foo/bar.jpg"
            ml.request(f)
            assert f.response.content == b"foofoobar"

    async def test_nonexistent_files(self, tmpdir, monkeypatch, caplog):
        caplog.set_level("INFO")
        ml = MapLocal()

        with taddons.context(ml) as tctx:
            tctx.configure(ml, map_local=["|example.org/css|" + str(tmpdir)])
            f = tflow.tflow()
            f.request.url = b"https://example.org/css/nonexistent"
            ml.request(f)
            assert f.response.status_code == 404
            assert "None of the local file candidates exist" in caplog.text

            tmpfile = tmpdir.join("foo.jpg")
            tmpfile.write("foo")
            tctx.configure(ml, map_local=["|//example.org/images|" + str(tmpfile)])
            tmpfile.remove()
            monkeypatch.setattr(Path, "is_file", lambda x: True)
            f = tflow.tflow()
            f.request.url = b"https://example.org/images/foo.jpg"
            ml.request(f)
            assert "Could not read" in caplog.text

    def test_is_killed(self, tmpdir):
        ml = MapLocal()
        with taddons.context(ml) as tctx:
            tmpfile = tmpdir.join("foo.jpg")
            tmpfile.write("foo")
            tctx.configure(ml, map_local=["|//example.org/images|" + str(tmpfile)])
            f = tflow.tflow()
            f.request.url = b"https://example.org/images/foo.jpg"
            f.kill()
            ml.request(f)
            assert not f.response


@pytest.mark.parametrize(
    "header,expected",
    [
        ("bytes=0-3", [("range", 0, 3)]),
        ("bytes=7-", [("range", 7, None)]),
        ("bytes=-4", [("suffix", 4)]),
        ("bytes=-0", [("suffix", 0)]),
        ("bytes=0-100", [("range", 0, 100)]),
        (
            "bytes=0-2,8-9,4-5",
            [("range", 0, 2), ("range", 8, 9), ("range", 4, 5)],
        ),
        ("  bytes=0-3  ", [("range", 0, 3)]),
        ("bytes= 0-3 , 8-9 ", [("range", 0, 3), ("range", 8, 9)]),
        # malformed or unknown unit -> ignore
        ("bytes=", None),
        ("bytes=,,", None),
        ("bytes=a-b", None),
        ("bytes=5-3", None),
        ("bytes=0-3,5-2", None),
        ("items=0-3", None),
        ("Bytes=0-3", None),
    ],
)
def test_parse_byte_ranges(header, expected):
    assert _parse_byte_ranges(header) == expected


@pytest.mark.parametrize(
    "specs,size,expected",
    [
        # single range, suffix, open end
        ([("range", 0, 3)], 10, [(0, 3)]),
        ([("range", 7, None)], 10, [(7, 9)]),
        ([("suffix", 4)], 10, [(6, 9)]),
        # a suffix longer than the file covers the whole representation
        ([("suffix", 100)], 10, [(0, 9)]),
        # ranges are clamped to the end
        ([("range", 0, 100)], 10, [(0, 9)]),
        ([("range", 5, 100)], 10, [(5, 9)]),
        # unsatisfiable specs are dropped
        ([("range", 10, None)], 10, []),
        ([("range", 20, 30)], 10, []),
        ([("suffix", 0)], 10, []),
        ([("suffix", 5)], 0, []),
        # satisfiable specs survive even if others are not; order preserved
        (
            [("range", 20, None), ("range", 0, 0), ("range", 8, None)],
            10,
            [(0, 0), (8, 9)],
        ),
    ],
)
def test_satisfiable_ranges(specs, size, expected):
    assert _satisfiable_ranges(specs, size) == expected


@pytest.mark.parametrize(
    "header,expected",
    [
        ('"abc"', ['"abc"']),
        ('"a", "b", W/"c"', ['"a"', '"b"', 'W/"c"']),
        ("*", ["*"]),
        ('*, "a"', ["*", '"a"']),
        ("", None),
        ("abc", None),
        ('"a", b', None),
        ("W/*", None),
    ],
)
def test_parse_entity_tags(header, expected):
    assert _parse_entity_tags(header) == expected


def test_entity_tag_matching():
    etag = '"v1"'
    assert _entity_tag_matches(["*"], etag, strong=True)
    assert _entity_tag_matches(['"v1"'], etag, strong=True)
    assert not _entity_tag_matches(['"v2"'], etag, strong=True)
    # weak tags do not match under strong comparison ...
    assert not _entity_tag_matches(['W/"v1"'], etag, strong=True)
    # ... but they do under weak comparison
    assert _entity_tag_matches(['W/"v1"'], etag, strong=False)
    assert not _entity_tag_matches(None, etag, strong=False)


class TestMapLocalHttp:
    CONTENT = b"0123456789"

    def _configure(self, tmpdir, content: bytes = CONTENT, filename="foo.bin"):
        ml = MapLocal()
        tmpfile = tmpdir.join(filename)
        tmpfile.write_binary(content)
        path = Path(str(tmpfile))
        os.utime(path, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
        tctx = taddons.context(ml)
        tctx.__enter__()
        tctx.configure(
            ml,
            map_local=["|//example.org/videos|" + str(tmpdir)],
            map_local_http=True,
        )
        return ml, tctx, path

    def _flow(self, method="GET", headers=None):
        f = tflow.tflow()
        f.request.url = b"https://example.org/videos/foo.bin"
        f.request.method = method
        for k, v in (headers or {}).items():
            f.request.headers[k] = v
        return f

    def _request(self, ml, method="GET", headers=None):
        f = self._flow(method, headers)
        ml.request(f)
        return f.response

    def test_option_disabled_by_default(self):
        ml = MapLocal()
        with taddons.context(ml) as tctx:
            assert tctx.options.map_local_http is False

    def test_full_get_has_validators(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            response = self._request(ml)
            stat = path.stat()
            assert response.status_code == 200
            assert response.content == self.CONTENT
            assert response.headers["Accept-Ranges"] == "bytes"
            assert response.headers["Content-Length"] == str(len(self.CONTENT))
            assert response.headers["ETag"].startswith('"')
            assert response.headers["ETag"].endswith('"')
            assert response.headers["Last-Modified"] == email.utils.formatdate(
                stat.st_mtime, usegmt=True
            )
        finally:
            tctx.__exit__(None, None, None)

    def test_if_none_match(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            etag = self._request(ml).headers["ETag"]

            response = self._request(ml, headers={"If-None-Match": etag})
            assert response.status_code == 304
            assert response.content == b""
            assert "content-length" not in response.headers
            assert response.headers["ETag"] == etag

            # a weak form of the same validator also matches
            response = self._request(ml, headers={"If-None-Match": f"W/{etag}"})
            assert response.status_code == 304

            # an unrelated validator yields the full representation
            response = self._request(ml, headers={"If-None-Match": '"other"'})
            assert response.status_code == 200
            assert response.content == self.CONTENT

            # wildcard always matches an existing representation
            response = self._request(ml, headers={"If-None-Match": "*"})
            assert response.status_code == 304
        finally:
            tctx.__exit__(None, None, None)

    def test_if_modified_since(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            last_modified = path.stat().st_mtime
            same = email.utils.formatdate(last_modified, usegmt=True)
            older = email.utils.formatdate(last_modified - 100, usegmt=True)
            newer = email.utils.formatdate(last_modified + 100, usegmt=True)

            response = self._request(ml, headers={"If-Modified-Since": same})
            assert response.status_code == 304
            assert response.content == b""

            response = self._request(ml, headers={"If-Modified-Since": newer})
            assert response.status_code == 304

            response = self._request(ml, headers={"If-Modified-Since": older})
            assert response.status_code == 200
            assert response.content == self.CONTENT

            # malformed dates are ignored
            response = self._request(ml, headers={"If-Modified-Since": "not a date"})
            assert response.status_code == 200

            # If-None-Match takes precedence over If-Modified-Since
            response = self._request(
                ml,
                headers={"If-None-Match": '"other"', "If-Modified-Since": same},
            )
            assert response.status_code == 200
        finally:
            tctx.__exit__(None, None, None)

    def test_if_match(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            etag = self._request(ml).headers["ETag"]

            assert self._request(ml, headers={"If-Match": etag}).status_code == 200
            assert self._request(ml, headers={"If-Match": "*"}).status_code == 200

            response = self._request(ml, headers={"If-Match": '"other"'})
            assert response.status_code == 412
            assert response.content == b""

            # weak validators never satisfy If-Match (strong comparison)
            response = self._request(ml, headers={"If-Match": f"W/{etag}"})
            assert response.status_code == 412

            # a malformed If-Match header fails the precondition
            response = self._request(ml, headers={"If-Match": "garbage"})
            assert response.status_code == 412
        finally:
            tctx.__exit__(None, None, None)

    def test_if_unmodified_since(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            last_modified = path.stat().st_mtime
            newer = email.utils.formatdate(last_modified + 100, usegmt=True)
            older = email.utils.formatdate(last_modified - 100, usegmt=True)

            response = self._request(ml, headers={"If-Unmodified-Since": newer})
            assert response.status_code == 200

            response = self._request(ml, headers={"If-Unmodified-Since": older})
            assert response.status_code == 412

            # malformed dates are ignored; If-Match suppresses the date check
            response = self._request(ml, headers={"If-Unmodified-Since": "garbage"})
            assert response.status_code == 200
        finally:
            tctx.__exit__(None, None, None)

    def test_precondition_precedence(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            etag = self._request(ml).headers["ETag"]
            # failing If-Match wins over a matching If-None-Match
            response = self._request(
                ml,
                headers={"If-Match": '"other"', "If-None-Match": etag},
            )
            assert response.status_code == 412
        finally:
            tctx.__exit__(None, None, None)

    def test_single_ranges(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            response = self._request(ml, headers={"Range": "bytes=0-3"})
            assert response.status_code == 206
            assert response.content == b"0123"
            assert response.headers["Content-Range"] == "bytes 0-3/10"
            assert response.headers["Content-Length"] == "4"

            # open-ended range
            response = self._request(ml, headers={"Range": "bytes=7-"})
            assert response.content == b"789"
            assert response.headers["Content-Range"] == "bytes 7-9/10"

            # suffix range
            response = self._request(ml, headers={"Range": "bytes=-4"})
            assert response.content == b"6789"
            assert response.headers["Content-Range"] == "bytes 6-9/10"

            # suffix longer than the file
            response = self._request(ml, headers={"Range": "bytes=-100"})
            assert response.status_code == 206
            assert response.content == self.CONTENT
            assert response.headers["Content-Range"] == "bytes 0-9/10"

            # end beyond the file is clamped
            response = self._request(ml, headers={"Range": "bytes=0-100"})
            assert response.content == self.CONTENT
            assert response.headers["Content-Range"] == "bytes 0-9/10"

            # one-byte range
            response = self._request(ml, headers={"Range": "bytes=9-9"})
            assert response.content == b"9"
            assert response.headers["Content-Range"] == "bytes 9-9/10"

            # validator headers are still present on partial content
            assert response.headers["ETag"]
            assert response.headers["Last-Modified"]
            assert response.headers["Accept-Ranges"] == "bytes"
        finally:
            tctx.__exit__(None, None, None)

    def test_range_unsatisfiable(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            for value in ("bytes=10-20", "bytes=10-", "bytes=-0"):
                response = self._request(ml, headers={"Range": value})
                assert response.status_code == 416
                assert response.headers["Content-Range"] == "bytes */10"
                assert response.content == b""
        finally:
            tctx.__exit__(None, None, None)

    def test_malformed_range_ignored(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            for value in (
                "bytes=",
                "bytes=,,",
                "bytes=a-b",
                "bytes=5-3",
                "bytes=0-3,5-2",
                "items=0-3",
            ):
                response = self._request(ml, headers={"Range": value})
                assert response.status_code == 200
                assert response.content == self.CONTENT
        finally:
            tctx.__exit__(None, None, None)

    def test_partially_satisfiable_multipart(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            response = self._request(ml, headers={"Range": "bytes=20-,0-0"})
            assert response.status_code == 206
            assert response.content == b"0"
            assert response.headers["Content-Range"] == "bytes 0-0/10"
        finally:
            tctx.__exit__(None, None, None)

    def test_if_range(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            etag = self._request(ml).headers["ETag"]
            last_modified = self._request(ml).headers["Last-Modified"]

            # matching entity tag -> partial content
            response = self._request(
                ml, headers={"Range": "bytes=0-3", "If-Range": etag}
            )
            assert response.status_code == 206
            assert response.content == b"0123"

            # mismatching entity tag -> complete entity
            response = self._request(
                ml,
                headers={"Range": "bytes=0-3", "If-Range": '"stale"'},
            )
            assert response.status_code == 200
            assert response.content == self.CONTENT

            # matching date -> partial content
            response = self._request(
                ml,
                headers={
                    "Range": "bytes=0-3",
                    "If-Range": last_modified,
                },
            )
            assert response.status_code == 206

            # older date -> complete entity
            stat_mtime = path.stat().st_mtime
            response = self._request(
                ml,
                headers={
                    "Range": "bytes=0-3",
                    "If-Range": email.utils.formatdate(stat_mtime - 100, usegmt=True),
                },
            )
            assert response.status_code == 200

            # unparsable validator -> complete entity
            response = self._request(
                ml, headers={"Range": "bytes=0-3", "If-Range": "garbage"}
            )
            assert response.status_code == 200
        finally:
            tctx.__exit__(None, None, None)

    def test_multipart_ranges_in_request_order(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            response = self._request(ml, headers={"Range": "bytes=0-2,8-9,4-5"})
            assert response.status_code == 206
            content_type = response.headers["Content-Type"]
            assert content_type.startswith("multipart/byteranges; boundary=")
            boundary = content_type.split("boundary=", 1)[1].encode()

            # parts are ordered like the request, including their data
            body = response.content
            assert response.headers["Content-Length"] == str(len(body))
            positions = [
                body.index(b"Content-Range: bytes 0-2/10"),
                body.index(b"Content-Range: bytes 8-9/10"),
                body.index(b"Content-Range: bytes 4-5/10"),
            ]
            assert positions == sorted(positions)
            for chunk in (b"012", b"89", b"45"):
                assert chunk in body
            # proper multipart framing
            assert body.startswith(b"--" + boundary + b"\r\n")
            assert body.endswith(b"--" + boundary + b"--\r\n")
            # each part carries the representation's media metadata
            assert body.count(b"Content-Type:") == 3

            # the same range requested twice yields two parts
            response = self._request(ml, headers={"Range": "bytes=0-0,0-0"})
            assert response.status_code == 206
            assert response.content.count(b"Content-Range: bytes 0-0/10") == 2
        finally:
            tctx.__exit__(None, None, None)

    def test_head(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            response = self._request(ml, method="HEAD")
            assert response.status_code == 200
            assert response.content == b""
            assert response.headers["Content-Length"] == str(len(self.CONTENT))
            assert response.headers["ETag"]
            assert response.headers["Last-Modified"]

            # Range is ignored for HEAD: full-length headers, no body
            response = self._request(ml, method="HEAD", headers={"Range": "bytes=0-3"})
            assert response.status_code == 200
            assert response.content == b""
            assert response.headers["Content-Length"] == str(len(self.CONTENT))
            assert "Content-Range" not in response.headers

            # conditional HEAD still yields 304 without a body
            etag = self._request(ml).headers["ETag"]
            response = self._request(ml, method="HEAD", headers={"If-None-Match": etag})
            assert response.status_code == 304
            assert response.content == b""
            assert "content-length" not in response.headers
        finally:
            tctx.__exit__(None, None, None)

    def test_no_unnecessary_file_reads(self, tmpdir, monkeypatch):
        ml, tctx, path = self._configure(tmpdir)
        try:
            etag = self._request(ml).headers["ETag"]

            real_open = Path.open
            bytes_read = []

            class ReadSpy:
                def __init__(self, inner):
                    self._inner = inner

                def read(self, n=-1):
                    data = self._inner.read(n)
                    bytes_read.append(len(data))
                    return data

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return self._inner.close()

                def __getattr__(self, name):
                    return getattr(self._inner, name)

            monkeypatch.setattr(
                Path,
                "open",
                lambda self, *a, **kw: ReadSpy(real_open(self, *a, **kw)),
            )

            bytes_read.clear()
            self._request(ml, method="HEAD")
            assert sum(bytes_read) == 0

            bytes_read.clear()
            self._request(ml, headers={"If-None-Match": etag})
            assert sum(bytes_read) == 0

            bytes_read.clear()
            self._request(ml, headers={"Range": "bytes=0-3"})
            assert sum(bytes_read) == 4

            bytes_read.clear()
            self._request(ml)
            assert sum(bytes_read) == len(self.CONTENT)
        finally:
            tctx.__exit__(None, None, None)

    def test_replaced_file_uses_new_file_next_request(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir, content=b"AAAA")
        try:
            first = self._request(ml)
            assert first.content == b"AAAA"
            etag_old = first.headers["ETag"]

            path.write_bytes(b"BBBBBB")
            second = self._request(ml)
            assert second.content == b"BBBBBB"
            assert second.headers["Content-Length"] == "6"
            assert second.headers["ETag"] != etag_old
        finally:
            tctx.__exit__(None, None, None)

    def test_response_uses_a_single_open_file_handle(self, tmpdir, monkeypatch):
        ml, tctx, path = self._configure(tmpdir)
        try:
            real_open = Path.open
            real_fstat = os.fstat
            handles = []
            fstat_fds = []

            class HandleSpy:
                def __init__(self, inner):
                    self._inner = inner
                    self.fd = inner.fileno()
                    self.bytes_read = 0
                    self.closed = False

                def read(self, n=-1):
                    data = self._inner.read(n)
                    self.bytes_read += len(data)
                    return data

                def close(self):
                    if not self.closed:
                        self.closed = True
                        self._inner.close()

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    self.close()

                def __getattr__(self, name):
                    return getattr(self._inner, name)

            def open_spy(self, *a, **kw):
                mode = a[0] if a else kw.get("mode", "r")
                handle = real_open(self, *a, **kw)
                if mode == "rb":
                    spy = HandleSpy(handle)
                    handles.append(spy)
                    return spy
                return handle

            def fstat_spy(fd):
                fstat_fds.append(fd)
                return real_fstat(fd)

            monkeypatch.setattr(Path, "open", open_spy)
            monkeypatch.setattr(os, "fstat", fstat_spy)

            response = self._request(ml)
            # exactly one open per response; metadata comes from that handle
            assert len(handles) == 1
            assert fstat_fds == [handles[0].fd]
            assert handles[0].bytes_read == len(self.CONTENT)
            assert handles[0].closed
            assert response.content == self.CONTENT
            assert response.headers["Content-Length"] == str(len(self.CONTENT))

            # the next request opens the (possibly replaced) file again
            path.write_bytes(b"BBBBBB")
            response = self._request(ml)
            assert len(handles) == 2
            assert fstat_fds[1] == handles[1].fd
            assert handles[1].bytes_read == 6
            assert response.content == b"BBBBBB"
            assert response.headers["Content-Length"] == "6"

            # a ranged response reads only its range from the single handle
            response = self._request(ml, headers={"Range": "bytes=0-3"})
            assert len(handles) == 3
            assert handles[2].bytes_read == 4
            assert response.content == b"BBBB"
        finally:
            tctx.__exit__(None, None, None)

    def test_replacement_mid_response_keeps_one_consistent_file(
        self, tmpdir, monkeypatch
    ):
        ml, tctx, path = self._configure(tmpdir, content=b"AAAA")
        try:
            replacement = Path(str(tmpdir.join("other.bin")))
            replacement.write_bytes(b"BBBBBB")

            real_read_exact = maplocal_module._read_exact

            def replace_then_read(handle, offset, length):
                try:
                    os.replace(replacement, path)
                except OSError:
                    pytest.skip("atomic replacement of the open file is unsupported")
                return real_read_exact(handle, offset, length)

            monkeypatch.setattr(maplocal_module, "_read_exact", replace_then_read)
            response = self._request(ml)
            # validator, length and body all come from the originally opened
            # file even though the path now points at a different file
            assert response.content == b"AAAA"
            assert response.headers["Content-Length"] == "4"

            monkeypatch.undo()
            response = self._request(ml)
            assert response.content == b"BBBBBB"
            assert response.headers["Content-Length"] == "6"
        finally:
            tctx.__exit__(None, None, None)

    def test_disabled_mode_keeps_legacy_behavior(self, tmpdir):
        ml = MapLocal()
        tmpfile = tmpdir.join("foo.bin")
        tmpfile.write_binary(self.CONTENT)
        with taddons.context(ml) as tctx:
            tctx.configure(ml, map_local=["|//example.org/videos|" + str(tmpdir)])
            assert tctx.options.map_local_http is False

            f = self._flow()
            ml.request(f)
            assert f.response.status_code == 200
            assert f.response.content == self.CONTENT
            assert "ETag" not in f.response.headers
            assert "Accept-Ranges" not in f.response.headers
            assert "Last-Modified" not in f.response.headers

    def test_other_methods_keep_legacy_behavior(self, tmpdir):
        ml, tctx, path = self._configure(tmpdir)
        try:
            for method in ("POST", "PUT", "DELETE"):
                response = self._request(ml, method=method)
                assert response.status_code == 200
                assert response.content == self.CONTENT
                assert "ETag" not in response.headers
                assert "Accept-Ranges" not in response.headers
                # Range must not influence legacy behavior
                response = self._request(
                    ml, method=method, headers={"Range": "bytes=0-3"}
                )
                assert response.content == self.CONTENT
        finally:
            tctx.__exit__(None, None, None)

    def test_content_type_still_guessed(self, tmpdir):
        ml = MapLocal()
        tmpfile = tmpdir.join("foo.jpg")
        tmpfile.write_binary(self.CONTENT)
        with taddons.context(ml) as tctx:
            tctx.configure(
                ml,
                map_local=["|//example.org/images|" + str(tmpdir)],
                map_local_http=True,
            )
            f = tflow.tflow()
            f.request.url = b"https://example.org/images/foo.jpg"
            ml.request(f)
            assert f.response.headers["Content-Type"] == "image/jpeg"
            assert f.response.status_code == 200


def test_if_range_matching():
    etag = '"v1"'
    mtime = 1_600_000_000.0
    assert _if_range_matches(etag, etag, mtime)
    assert _if_range_matches(f"W/{etag}", etag, mtime)
    assert not _if_range_matches('"other"', etag, mtime)
    assert _if_range_matches(email.utils.formatdate(mtime, usegmt=True), etag, mtime)
    assert not _if_range_matches(
        email.utils.formatdate(mtime - 100, usegmt=True), etag, mtime
    )
    assert not _if_range_matches("garbage", etag, mtime)
