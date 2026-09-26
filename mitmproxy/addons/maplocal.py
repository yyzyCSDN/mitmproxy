import binascii
import email.utils
import logging
import mimetypes
import os
import re
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import Literal
from typing import NamedTuple

from werkzeug.security import safe_join

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import version
from mitmproxy.utils.spec import parse_spec

#: Body data is transferred in chunks of this size so that large files never
#: have to be loaded into memory as a whole just to serve a small range.
_CHUNK_SIZE = 1024 * 1024

#: A single byte-range-spec, either ``first-last`` / ``first-`` or a
#: suffix range ``-suffix``.
_BYTE_RANGE_SPEC_RE = re.compile(r"^(?:(?P<first>\d+)-(?P<last>\d*)|-(?P<suffix>\d+))$")


class MapLocalSpec(NamedTuple):
    matches: flowfilter.TFilter
    regex: str
    local_path: Path


def parse_map_local_spec(option: str) -> MapLocalSpec:
    filter, regex, replacement = parse_spec(option)

    try:
        re.compile(regex)
    except re.error as e:
        raise ValueError(f"Invalid regular expression {regex!r} ({e})")

    try:
        path = Path(replacement).expanduser().resolve(strict=True)
    except FileNotFoundError as e:
        raise ValueError(f"Invalid file path: {replacement} ({e})")

    return MapLocalSpec(filter, regex, path)


def _safe_path_join(root: Path, untrusted: str) -> Path:
    """Join a Path element with an untrusted str.

    This is a convenience wrapper for werkzeug's safe_join,
    raising a ValueError if the path is malformed."""
    untrusted_parts = Path(untrusted).parts
    joined = safe_join(root.as_posix(), *untrusted_parts)
    if joined is None:
        raise ValueError("Untrusted paths.")
    return Path(joined)


def file_candidates(url: str, spec: MapLocalSpec) -> list[Path]:
    """
    Get all potential file candidates given a URL and a mapping spec ordered by preference.
    This function already assumes that the spec regex matches the URL.
    """
    m = re.search(spec.regex, url)
    assert m
    if m.groups():
        suffix = m.group(1)
    else:
        suffix = re.split(spec.regex, url, maxsplit=1)[1]
        suffix = suffix.split("?")[0]  # remove query string
        suffix = suffix.strip("/")

    if suffix:
        decoded_suffix = urllib.parse.unquote(suffix)
        suffix_candidates = [decoded_suffix, f"{decoded_suffix}/index.html"]

        escaped_suffix = re.sub(r"[^0-9a-zA-Z\-_.=(),/]", "_", decoded_suffix)
        if decoded_suffix != escaped_suffix:
            suffix_candidates.extend([escaped_suffix, f"{escaped_suffix}/index.html"])
        try:
            return [_safe_path_join(spec.local_path, x) for x in suffix_candidates]
        except ValueError:
            return []
    else:
        return [spec.local_path / "index.html"]


def _http_date(timestamp: float) -> str:
    """Format a POSIX timestamp as an RFC 9110 IMF-fixdate (HTTP-date)."""
    return email.utils.formatdate(timestamp, usegmt=True)


def _parse_http_date(value: str) -> float | None:
    """Parse an HTTP-date, returning a POSIX timestamp or ``None`` if invalid."""
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    return parsed.timestamp()


def _parse_entity_tags(value: str) -> list[str] | None:
    """Parse an If-Match/If-None-Match header value.

    Returns the entity tags in request order (with any ``W/`` weakness
    prefix preserved), the single string ``"*"`` for a wildcard, or ``None``
    if the header value is malformed.
    """
    tags: list[str] = []
    for part in value.split(","):
        tag = part.strip()
        weak = tag[:2].upper() == "W/"
        if weak:
            tag = tag[2:].strip()
        if tag == "*" and not weak:
            tags.append("*")
        elif len(tag) >= 2 and tag[0] == '"' and tag[-1] == '"':
            tags.append("W/" + tag if weak else tag)
        else:
            return None
    return tags or None


def _entity_tag_matches(tags: list[str] | None, etag: str, *, strong: bool) -> bool:
    """Check whether *etag* matches one of *tags*.

    Wildcards match any existing representation. With *strong* comparison
    weak entity tags never match.
    """
    if not tags:
        return False
    for tag in tags:
        if tag == "*":
            return True
        is_weak = tag[:2].upper() == "W/"
        if strong and is_weak:
            continue
        candidate = tag[2:] if is_weak else tag
        if candidate == etag:
            return True
    return False


# Parsed Range specs: a byte range ("range", first, last-or-None) or a
# suffix range ("suffix", suffix-length).
ByteRangeSpec = tuple[Literal["range"], int, int | None] | tuple[Literal["suffix"], int]


def _parse_byte_ranges(value: str) -> list[ByteRangeSpec] | None:
    """Parse a ``Range`` header value for the ``bytes`` unit.

    The specs are returned in request order. ``None`` is returned when the
    range unit is not ``bytes`` or the header is malformed; in that case the
    Range header must be ignored (RFC 9110, Section 14.1.2).
    """
    header = value.strip()
    if not header.startswith("bytes="):
        # Unknown range unit.
        return None
    body = header[len("bytes=") :].strip()
    if not body:
        return None
    specs: list[ByteRangeSpec] = []
    for item in body.split(","):
        match = _BYTE_RANGE_SPEC_RE.fullmatch(item.strip())
        if not match:
            return None
        if match.group("suffix") is not None:
            specs.append(("suffix", int(match.group("suffix"))))
        else:
            first = int(match.group("first"))
            last_raw = match.group("last")
            last: int | None = int(last_raw) if last_raw else None
            if last is not None and last < first:
                # Syntactically invalid byte-range-spec.
                return None
            specs.append(("range", first, last))
    return specs


def _satisfiable_ranges(specs: list[ByteRangeSpec], size: int) -> list[tuple[int, int]]:
    """Clamp parsed specs to the representation, keeping the request order.

    Unsatisfiable specs are dropped; an empty result means that a 416
    response has to be generated.
    """
    ranges: list[tuple[int, int]] = []
    for spec in specs:
        if spec[0] == "suffix":
            length = spec[1]
            if length == 0 or size == 0:
                continue
            first = max(0, size - length)
            ranges.append((first, size - 1))
        else:
            first, last = spec[1], spec[2]
            if first >= size:
                continue
            end = size - 1 if last is None else min(last, size - 1)
            ranges.append((first, end))
    return ranges


def _if_range_matches(value: str, etag: str, last_modified: float) -> bool:
    """Evaluate an If-Range validator (entity tag or HTTP-date)."""
    candidate = value.strip()
    if candidate[:2].upper() == "W/":
        candidate = candidate[2:].strip()
    if candidate.startswith('"'):
        return len(candidate) >= 2 and candidate[-1] == '"' and candidate == etag
    date = _parse_http_date(value)
    if date is None:
        return False
    # If-Range uses an exact date match, not a modified-since comparison.
    return int(date) == int(last_modified)


def _read_exact(handle, offset: int, length: int) -> bytes:
    """Read exactly *length* bytes from *handle* starting at *offset*.

    The file is read in fixed-size chunks, so a small range never pulls the
    whole file into memory. Raises OSError on short reads.
    """
    handle.seek(offset)
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        chunk = handle.read(min(remaining, _CHUNK_SIZE))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if remaining:
        raise OSError(
            f"short read for {getattr(handle, 'name', '<file>')}: "
            f"expected {length} bytes at offset {offset}, "
            f"got {length - remaining}"
        )
    return b"".join(chunks)


class MapLocal:
    def __init__(self) -> None:
        self.replacements: list[MapLocalSpec] = []

    def load(self, loader):
        loader.add_option(
            "map_local",
            Sequence[str],
            [],
            """
            Map remote resources to a local file using a pattern of the form
            "[/flow-filter]/url-regex/file-or-directory-path", where the
            separator can be any character.
            """,
        )
        loader.add_option(
            "map_local_http",
            bool,
            False,
            """
            Serve GET and HEAD requests mapped by map_local with standard
            HTTP content negotiation: ETag and Last-Modified validators are
            emitted and conditional request headers (If-Match,
            If-None-Match, If-Modified-Since, If-Unmodified-Since, If-Range)
            are honoured, including 304 Not Modified and 412 Precondition
            Failed responses. GET additionally supports byte-range requests
            (single, suffix, open-ended and multipart/byteranges ranges),
            which lets browsers seek in and resume mapped media files.
            Disabled by default; other request methods are unaffected.
            """,
        )

    def configure(self, updated):
        if "map_local" in updated:
            self.replacements = []
            for option in ctx.options.map_local:
                try:
                    spec = parse_map_local_spec(option)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse map_local option {option}: {e}"
                    ) from e

                self.replacements.append(spec)

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response or flow.error or not flow.live:
            return

        url = flow.request.pretty_url
        http_mode = bool(ctx.options.map_local_http)
        method = flow.request.method.upper()

        all_candidates = []
        for spec in self.replacements:
            if spec.matches(flow) and re.search(spec.regex, url):
                if spec.local_path.is_file():
                    candidates = [spec.local_path]
                else:
                    candidates = file_candidates(url, spec)
                all_candidates.extend(candidates)

                local_file = None
                for candidate in candidates:
                    if candidate.is_file():
                        local_file = candidate
                        break

                if local_file:
                    if http_mode and method in ("GET", "HEAD"):
                        # The HTTP path handles validators, preconditions and
                        # ranges itself. A return value of None means that the
                        # file could not be opened/read, in which case we fall
                        # through to the next matching rule.
                        response = self._serve_http(flow.request, local_file)
                        if response is not None:
                            flow.response = response
                            return
                    else:
                        headers = {"Server": version.MITMPROXY}
                        mimetype = mimetypes.guess_type(str(local_file))[0]
                        if mimetype:
                            headers["Content-Type"] = mimetype

                        try:
                            contents = local_file.read_bytes()
                        except OSError as e:
                            logging.warning(f"Could not read file: {e}")
                            continue

                        flow.response = http.Response.make(200, contents, headers)
                        # only set flow.response once, for the first matching rule
                        return
        if all_candidates:
            flow.response = http.Response.make(404)
            logging.info(
                f"None of the local file candidates exist: {', '.join(str(x) for x in all_candidates)}"
            )

    def _serve_http(
        self, request: http.Request, local_file: Path
    ) -> http.Response | None:
        """Build an HTTP response for a mapped GET/HEAD request.

        The file is opened exactly once: the validator headers, content
        length and body data all originate from that one open file handle.
        If the file at *local_file* is replaced, the next request opens the
        new file instead.
        """
        try:
            handle = local_file.open("rb")
        except OSError as e:
            logging.warning(f"Could not read file: {e}")
            return None

        try:
            with handle:
                stat_result = os.fstat(handle.fileno())
                size = stat_result.st_size
                last_modified = stat_result.st_mtime
                # nginx-style strong validator derived from the opened file's
                # metadata, so no body bytes have to be read for validation.
                etag = f'"{stat_result.st_mtime_ns:x}-{size:x}"'

                headers: dict[str, str] = {
                    "Server": version.MITMPROXY,
                    "Accept-Ranges": "bytes",
                    "ETag": etag,
                    "Last-Modified": _http_date(last_modified),
                }
                mimetype = mimetypes.guess_type(str(local_file))[0]
                if mimetype:
                    headers["Content-Type"] = mimetype

                is_head = request.method.upper() == "HEAD"

                # Preconditions are evaluated before reading any body data,
                # following the precedence in RFC 9110, Section 13.2.2.
                if_match = request.headers.get("if-match")
                if if_match is not None:
                    if not _entity_tag_matches(
                        _parse_entity_tags(if_match), etag, strong=True
                    ):
                        return http.Response.make(412, b"", headers)
                else:
                    if_unmodified_since = request.headers.get("if-unmodified-since")
                    if if_unmodified_since is not None:
                        date = _parse_http_date(if_unmodified_since)
                        if date is not None and int(last_modified) > int(date):
                            return http.Response.make(412, b"", headers)

                if_none_match = request.headers.get("if-none-match")
                if if_none_match is not None:
                    not_modified = _entity_tag_matches(
                        _parse_entity_tags(if_none_match), etag, strong=False
                    )
                else:
                    # If-Modified-Since is ignored when If-None-Match exists.
                    if_modified_since = request.headers.get("if-modified-since")
                    date = (
                        _parse_http_date(if_modified_since)
                        if if_modified_since is not None
                        else None
                    )
                    not_modified = date is not None and int(last_modified) <= int(date)
                if not_modified:
                    response = http.Response.make(304, b"", headers)
                    # 304 responses have no message body.
                    response.headers.pop("content-length", None)
                    return response

                if is_head:
                    # HEAD requests carry the full representation's headers
                    # but never a body; Range only applies to GET.
                    response = http.Response.make(200, b"", headers)
                    response.headers["Content-Length"] = str(size)
                    return response

                # Range only applies to GET. A malformed Range header or an
                # unknown range unit is ignored, as is a Range whose If-Range
                # validator does not match.
                ranges: list[tuple[int, int]] | None = None
                range_header = request.headers.get("range")
                if range_header is not None:
                    parsed_ranges = _parse_byte_ranges(range_header)
                    if parsed_ranges is not None:
                        if_range = request.headers.get("if-range")
                        if if_range is None or _if_range_matches(
                            if_range, etag, last_modified
                        ):
                            ranges = _satisfiable_ranges(parsed_ranges, size)
                            if not ranges:
                                headers["Content-Range"] = f"bytes */{size}"
                                return http.Response.make(416, b"", headers)

                if ranges is None:
                    # Full representation.
                    content = _read_exact(handle, 0, size)
                    return http.Response.make(200, content, headers)

                if len(ranges) == 1:
                    first, last = ranges[0]
                    content = _read_exact(handle, first, last - first + 1)
                    headers["Content-Range"] = f"bytes {first}-{last}/{size}"
                    return http.Response.make(206, content, headers)

                return self._make_multipart_response(handle, ranges, size, headers)
        except OSError as e:
            logging.warning(f"Could not read file: {e}")
            return None

    def _make_multipart_response(
        self,
        handle,
        ranges: list[tuple[int, int]],
        size: int,
        headers: dict[str, str],
    ) -> http.Response:
        """Assemble a multipart/byteranges response, parts in request order."""
        boundary = "mitmproxy_map_local_" + binascii.hexlify(os.urandom(16)).decode()
        content_type = headers.get("Content-Type")

        parts: list[bytes] = []
        for first, last in ranges:
            part_headers = [f"--{boundary}"]
            if content_type:
                part_headers.append(f"Content-Type: {content_type}")
            part_headers.append(f"Content-Range: bytes {first}-{last}/{size}")
            preamble = ("\r\n".join(part_headers) + "\r\n\r\n").encode("ascii")
            data = _read_exact(handle, first, last - first + 1)
            parts.append(preamble + data + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode("ascii"))

        body = b"".join(parts)
        headers["Content-Type"] = f"multipart/byteranges; boundary={boundary}"
        return http.Response.make(206, body, headers)
