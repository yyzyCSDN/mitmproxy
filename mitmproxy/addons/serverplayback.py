import hashlib
import logging
import urllib
from collections.abc import Hashable
from collections.abc import Sequence
from dataclasses import dataclass
from email.utils import mktime_tz
from email.utils import parsedate_tz
from typing import Any

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import hooks
from mitmproxy import http
from mitmproxy import io
from mitmproxy.net.http import status_codes

logger = logging.getLogger(__name__)

HASH_OPTIONS = [
    "server_replay_ignore_content",
    "server_replay_ignore_host",
    "server_replay_ignore_params",
    "server_replay_ignore_payload_params",
    "server_replay_ignore_port",
    "server_replay_use_headers",
]

#: Response header fields that a recorded 304 must not overwrite on the
#: stored 200 entity. ``Content-Length`` stays tied to the entity body,
#: ``Content-Encoding``/``Content-Language``/``Content-Type``/
#: ``Content-Location`` describe the selected representation and must never be
#: mixed in from another record, ``Vary`` defines variant selection,
#: ``ETag``/``Last-Modified`` are checked for consistency instead, and
#: ``Date`` describes the recording and is recomputed by response refreshing.
_RECONSTRUCTION_IMMUTABLE_HEADERS = frozenset(
    {
        "content-length",
        "content-encoding",
        "content-language",
        "content-location",
        "content-range",
        "content-type",
        "date",
        "etag",
        "last-modified",
        "vary",
    }
)

#: Representation headers that are meaningless (or misleading) on a bodyless
#: 304 synthesized for a validating client.
_RECONSTRUCTION_304_DROP_HEADERS = frozenset(
    {
        "content-encoding",
        "content-language",
        "content-length",
        "content-location",
        "content-range",
        "content-type",
        "transfer-encoding",
    }
)


def _parse_http_date(value: str | None) -> float | None:
    if not value:
        return None
    parsed = parsedate_tz(value)
    if parsed is None:
        return None
    return mktime_tz(parsed)


def _parse_vary(response: http.Response) -> tuple[str, ...] | None:
    """
    Parses the Vary header into the tuple of request header names it selects
    on. An empty tuple means the response does not vary; ``None`` means
    ``Vary: *`` (variants cannot be reconstructed safely).
    """
    raw = response.headers.get("vary")
    if raw is None:
        return ()
    names: list[str] = []
    for part in raw.split(","):
        name = part.strip().lower()
        if name == "*":
            return None
        if name and name not in names:
            names.append(name)
    return tuple(names)


def _variant_key(
    request: http.Request, vary: tuple[str, ...]
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((name, tuple(request.headers.get_all(name))) for name in vary)


def _strip_weak(etag: str) -> str:
    etag = etag.strip()
    if etag[:2].upper() == "W/":
        etag = etag[2:].strip()
    return etag


def _parse_etag_list(value: str) -> list[str]:
    """
    Parses an If-None-Match/ETag header value into its individual entity tags,
    respecting double-quoted strings (which may contain commas).
    """
    tokens: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        while i < n and value[i] in " \t,":
            i += 1
        if i >= n:
            break
        start = i
        if value[i] == '"':
            i += 1
            while i < n and value[i] != '"':
                if value[i] == "\\" and i + 1 < n:
                    i += 1
                i += 1
            if i < n:
                i += 1
        else:
            while i < n and value[i] != ",":
                i += 1
        token = value[start:i].strip()
        if token:
            tokens.append(token)
    return tokens


def _etag_matches(if_none_match: str, etag: str) -> bool:
    """
    Weak entity-tag comparison as used for GET validation (RFC 9110),
    including the ``*`` wildcard.
    """
    target = _strip_weak(etag)
    for token in _parse_etag_list(if_none_match):
        if token == "*" or _strip_weak(token) == target:
            return True
    return False


@dataclass
class _Entity:
    """
    A complete GET 200 entity that bodies can be taken from. The entity tag
    and Last-Modified timestamp may be adopted from a confirmed validation
    chain when the 200 itself did not carry them.
    """

    response: http.Response
    etag: str | None
    last_modified: float | None
    vary: tuple[str, ...]
    variant_key: tuple[tuple[str, tuple[str, ...]], ...]
    timestamp_end: float


@dataclass
class _Reconstruction:
    """
    A replayable view of a recorded flow: the 200 entity it belongs to and a
    prototype response that carries the entity body and all metadata merged
    from confirmed 304 records up to this point in the recording.
    """

    entity: _Entity
    prototype: http.Response


class ServerPlayback:
    flowmap: dict[Hashable, list[http.HTTPFlow]]
    configured: bool
    reconstructions: dict[int, _Reconstruction]

    def __init__(self):
        self.flowmap = {}
        self.configured = False
        self.reconstructions = {}

    def load(self, loader):
        loader.add_option(
            "server_replay_kill_extra",
            bool,
            False,
            "Kill extra requests during replay (for which no replayable response was found)."
            "[Deprecated, prefer to use server_replay_extra='kill']",
        )
        loader.add_option(
            "server_replay_extra",
            str,
            "forward",
            "Behaviour for extra requests during replay for which no replayable response was found. "
            "Setting a numeric string value will return an empty HTTP response with the respective status code.",
            choices=["forward", "kill", "204", "400", "404", "500"],
        )
        loader.add_option(
            "server_replay_reuse",
            bool,
            False,
            """
            Don't remove flows from server replay state after use. This makes it
            possible to replay same response multiple times.
            """,
        )
        loader.add_option(
            "server_replay_nopop",
            bool,
            False,
            """
            Deprecated alias for `server_replay_reuse`.
            """,
        )
        loader.add_option(
            "server_replay_refresh",
            bool,
            True,
            """
            Refresh server replay responses by adjusting date, expires and
            last-modified headers, as well as adjusting cookie expiration.
            """,
        )
        loader.add_option(
            "server_replay_reconstruct",
            bool,
            False,
            """
            Reconstruct replayable GET entities from saved recordings that
            contain both a complete 200 response and later 304 Not Modified
            responses for the same resource, so that clients without a cached
            copy can still use the recording. On load, recorded 304s are
            associated with an earlier complete 200 entity by response
            completion time, the recorded request's conditional headers, the
            response validators (ETag/Last-Modified) and Vary, and metadata a
            304 is allowed to update (e.g. Cache-Control, Expires) is merged
            onto the 200 body. 304 records are skipped (with a log message)
            when there is no earlier entity, response completion timestamps
            are missing, the validators conflict, or Vary is "*"; bodies are
            never taken from later records and the origin server is never
            contacted. When replaying such entities, 200 or 304 is chosen
            based on the current client's If-None-Match/If-Modified-Since,
            and the entity's Last-Modified header is preserved instead of
            being refreshed. Only GET recordings are affected; when disabled,
            server replay behaves exactly as before.
            """,
        )
        loader.add_option(
            "server_replay_use_headers",
            Sequence[str],
            [],
            """
            Request headers that need to match while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay",
            Sequence[str],
            [],
            "Replay server responses from a saved file.",
        )
        loader.add_option(
            "server_replay_ignore_content",
            bool,
            False,
            "Ignore request content while searching for a saved flow to replay.",
        )
        loader.add_option(
            "server_replay_ignore_params",
            Sequence[str],
            [],
            """
            Request parameters to be ignored while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_payload_params",
            Sequence[str],
            [],
            """
            Request payload parameters (application/x-www-form-urlencoded or
            multipart/form-data) to be ignored while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_host",
            bool,
            False,
            """
            Ignore request destination host while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_port",
            bool,
            False,
            """
            Ignore request destination port while searching for a saved flow
            to replay.
            """,
        )

    @command.command("replay.server")
    def load_flows(self, flows: Sequence[flow.Flow]) -> None:
        """
        Replay server responses from flows.
        """
        self.flowmap = {}
        self.reconstructions = {}
        self.add_flows(flows)

    @command.command("replay.server.add")
    def add_flows(self, flows: Sequence[flow.Flow]) -> None:
        """
        Add responses from flows to server replay list.
        """
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                lst = self.flowmap.setdefault(self._hash(f), [])
                lst.append(f)
        self._build_reconstructions()
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.server.file")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        try:
            flows = io.read_flows_from_paths([path])
        except exceptions.FlowReadException as e:
            raise exceptions.CommandError(str(e))
        self.load_flows(flows)

    @command.command("replay.server.stop")
    def clear(self) -> None:
        """
        Stop server replay.
        """
        self.flowmap = {}
        self.reconstructions = {}
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.server.count")
    def count(self) -> int:
        return sum(len(i) for i in self.flowmap.values())

    def _hash(self, flow: http.HTTPFlow) -> Hashable:
        """
        Calculates a loose hash of the flow request.
        """
        r = flow.request
        _, _, path, _, query, _ = urllib.parse.urlparse(r.url)
        queriesArray = urllib.parse.parse_qsl(query, keep_blank_values=True)

        key: list[Any] = [str(r.scheme), str(r.method), str(path)]
        if not ctx.options.server_replay_ignore_content:
            if ctx.options.server_replay_ignore_payload_params and r.multipart_form:
                key.extend(
                    (k, v)
                    for k, v in r.multipart_form.items(multi=True)
                    if k.decode(errors="replace")
                    not in ctx.options.server_replay_ignore_payload_params
                )
            elif ctx.options.server_replay_ignore_payload_params and r.urlencoded_form:
                key.extend(
                    (k, v)
                    for k, v in r.urlencoded_form.items(multi=True)
                    if k not in ctx.options.server_replay_ignore_payload_params
                )
            else:
                key.append(str(r.raw_content))

        if not ctx.options.server_replay_ignore_host:
            key.append(r.pretty_host)
        if not ctx.options.server_replay_ignore_port:
            key.append(r.port)

        filtered = []
        ignore_params = ctx.options.server_replay_ignore_params or []
        for p in queriesArray:
            if p[0] not in ignore_params:
                filtered.append(p)
        for p in filtered:
            key.append(p[0])
            key.append(p[1])

        if ctx.options.server_replay_use_headers:
            headers = []
            for i in ctx.options.server_replay_use_headers:
                v = r.headers.get(i)
                headers.append((i, v))
            key.append(headers)
        return hashlib.sha256(repr(key).encode("utf8", "surrogateescape")).digest()

    def next_flow(self, flow: http.HTTPFlow) -> http.HTTPFlow | None:
        """
        Returns the next flow object, or None if no matching flow was
        found.
        """
        hash = self._hash(flow)
        bucket = self.flowmap.get(hash)
        if bucket is None:
            return None
        if ctx.options.server_replay_reuse or ctx.options.server_replay_nopop:
            return next(
                (
                    candidate
                    for candidate in bucket
                    if candidate.response and self._is_replay_candidate(candidate, flow)
                ),
                None,
            )
        index = 0
        while index < len(bucket):
            candidate = bucket[index]
            if not candidate.response:
                # Flows without a response can never be replayed, see
                # test_server_playback_response_deleted.
                bucket.pop(index)
                continue
            if self._is_replay_candidate(candidate, flow):
                bucket.pop(index)
                if not bucket:
                    del self.flowmap[hash]
                return candidate
            # A reconstruction variant that does not match this request (see
            # Vary) must stay in the queue for other clients.
            index += 1
        if not bucket:
            del self.flowmap[hash]
        return None

    def _is_replay_candidate(
        self, candidate: http.HTTPFlow, request_flow: http.HTTPFlow
    ) -> bool:
        """
        In reconstruction mode, recorded flows attached to a reconstructed
        entity only match requests that selected the same Vary variant. All
        other flows retain the default matching behaviour.
        """
        if not ctx.options.server_replay_reconstruct:
            return True
        reconstruction = self.reconstructions.get(id(candidate))
        if reconstruction is None:
            return True
        entity = reconstruction.entity
        return _variant_key(request_flow.request, entity.vary) == entity.variant_key

    def _build_reconstructions(self) -> None:
        """
        Builds reconstruction state for mixed 200/304 GET recordings.

        Records are walked in the order of their response completion time: a
        recorded 304 can only be backed by a complete 200 entity (or an
        already confirmed validation chain) that was recorded earlier. The
        original flowmap is left untouched.
        """
        self.reconstructions = {}
        if not ctx.options.server_replay_reconstruct:
            return
        records: list[tuple[float, Hashable, http.HTTPFlow]] = []
        for key, flows in self.flowmap.items():
            for f in flows:
                if f.response is None or f.request.method.upper() != "GET":
                    continue
                timestamp_end = f.response.timestamp_end
                if timestamp_end is None:
                    self._skip_reconstruction(
                        f, "response completion timestamp is missing"
                    )
                    continue
                records.append((timestamp_end, key, f))
        records.sort(key=lambda item: item[0])

        entities: dict[Hashable, list[_Entity]] = {}
        for timestamp_end, key, f in records:
            assert f.response is not None
            if f.response.status_code == 200:
                if f.response.raw_content is None:
                    self._skip_reconstruction(
                        f, "200 response does not contain a complete entity body"
                    )
                    continue
                vary = _parse_vary(f.response)
                if vary is None:
                    self._skip_reconstruction(f, "Vary: * forbids reconstruction")
                    continue
                entity = _Entity(
                    response=f.response,
                    etag=f.response.headers.get("etag"),
                    last_modified=_parse_http_date(
                        f.response.headers.get("last-modified")
                    ),
                    vary=vary,
                    variant_key=_variant_key(f.request, vary),
                    timestamp_end=timestamp_end,
                )
                entities.setdefault(key, []).append(entity)
                # The 200 flow is itself replayable through the reconstruction
                # path. The entity stays registered even after the flow is
                # consumed from the queue, but it is never re-queued.
                self.reconstructions[id(f)] = _Reconstruction(entity, f.response)
            elif f.response.status_code == 304:
                self._reconstruct_not_modified(key, f, timestamp_end, entities)

    def _reconstruct_not_modified(
        self,
        key: Hashable,
        f: http.HTTPFlow,
        timestamp_end: float,
        entities: dict[Hashable, list[_Entity]],
    ) -> None:
        assert f.response is not None
        request = f.request
        response = f.response

        request_etag = request.headers.get("if-none-match")
        request_modified_since = _parse_http_date(
            request.headers.get("if-modified-since")
        )
        if request_etag is None and request_modified_since is None:
            self._skip_reconstruction(
                f,
                "recorded 304 request has no If-None-Match/If-Modified-Since "
                "conditional header",
            )
            return

        vary = _parse_vary(response)
        if vary is None:
            self._skip_reconstruction(f, "Vary: * forbids reconstruction")
            return

        candidates = []
        for entity in entities.get(key, ()):
            # Bodies are never borrowed from records that completed later.
            if entity.timestamp_end > timestamp_end:
                continue
            if vary and frozenset(entity.vary) != frozenset(vary):
                continue
            if _variant_key(request, entity.vary) != entity.variant_key:
                continue
            if request_etag is not None:
                # If-None-Match takes precedence; without an entity tag the
                # validation cannot be confirmed.
                if entity.etag is None or not _etag_matches(request_etag, entity.etag):
                    continue
            else:
                assert request_modified_since is not None
                if (
                    entity.last_modified is None
                    or request_modified_since < entity.last_modified
                ):
                    continue
            candidates.append(entity)

        if not candidates:
            self._skip_reconstruction(
                f, "no earlier complete 200 entity confirms this 304"
            )
            return

        entity = max(candidates, key=lambda candidate: candidate.timestamp_end)

        # The validators on the 304 have to be consistent with the confirmed
        # entity; a mismatch indicates a different, unrecorded representation.
        response_etag = response.headers.get("etag")
        if (
            response_etag is not None
            and entity.etag is not None
            and _strip_weak(response_etag) != _strip_weak(entity.etag)
        ):
            self._skip_reconstruction(
                f,
                f"ETag {response_etag!r} conflicts with entity ETag {entity.etag!r}",
            )
            return
        response_modified = _parse_http_date(response.headers.get("last-modified"))
        if (
            response_modified is not None
            and entity.last_modified is not None
            and response_modified != entity.last_modified
        ):
            self._skip_reconstruction(
                f, "Last-Modified of the 304 conflicts with the entity"
            )
            return

        # Extend the confirmed validation chain with newly advertised
        # validators so that subsequent records can be confirmed as well.
        if response_etag is not None and entity.etag is None:
            entity.etag = response_etag
        if response_modified is not None and entity.last_modified is None:
            entity.last_modified = response_modified

        prototype = entity.response.copy()
        merged: dict[str, list[str]] = {}
        for name, value in response.headers.items(multi=True):
            name = name.lower()
            if name in _RECONSTRUCTION_IMMUTABLE_HEADERS:
                continue
            merged.setdefault(name, []).append(value)
        for name, values in merged.items():
            prototype.headers.set_all(name, values)

        self.reconstructions[id(f)] = _Reconstruction(entity, prototype)
        logger.info(
            "server replay reconstruction: %s backed by earlier 200 entity",
            request.pretty_url,
        )

    def _skip_reconstruction(self, f: http.HTTPFlow, reason: str) -> None:
        logger.info(
            "server replay reconstruction: skipping %s %s (%s)",
            f.request.method,
            f.request.pretty_url,
            reason,
        )

    def _client_validates(
        self, request: http.Request, reconstruction: _Reconstruction
    ) -> bool:
        """
        Whether the current client's conditional request already holds the
        reconstructed entity and should receive a 304.
        """
        entity = reconstruction.entity
        if_none_match = request.headers.get("if-none-match")
        if if_none_match is not None:
            # If-None-Match is evaluated instead of If-Modified-Since when both
            # are present (RFC 9110).
            return entity.etag is not None and _etag_matches(if_none_match, entity.etag)
        modified_since = _parse_http_date(request.headers.get("if-modified-since"))
        return (
            entity.last_modified is not None
            and modified_since is not None
            and modified_since >= entity.last_modified
        )

    def _make_not_modified(self, reconstruction: _Reconstruction) -> http.Response:
        response = reconstruction.prototype.copy()
        response.status_code = 304
        response.reason = status_codes.RESPONSES[304]
        response.content = b""
        for header in _RECONSTRUCTION_304_DROP_HEADERS:
            response.headers.pop(header, None)
        return response

    def configure(self, updated):
        if ctx.options.server_replay_kill_extra:
            logger.warning(
                "server_replay_kill_extra has been deprecated, "
                "please update your config to use server_replay_extra='kill'."
            )
        if ctx.options.server_replay_nopop:  # pragma: no cover
            logger.error(
                "server_replay_nopop has been renamed to server_replay_reuse, please update your config."
            )
        if not self.configured and ctx.options.server_replay:
            self.configured = True
            try:
                flows = io.read_flows_from_paths(ctx.options.server_replay)
            except exceptions.FlowReadException as e:
                raise exceptions.OptionsError(str(e))
            self.load_flows(flows)
        if any(
            option in updated for option in [*HASH_OPTIONS, "server_replay_reconstruct"]
        ):
            self.recompute_hashes()

    def recompute_hashes(self) -> None:
        """
        Rebuild flowmap if the hashing method has changed during execution,
        see https://github.com/mitmproxy/mitmproxy/issues/4506
        """
        flows = [flow for lst in self.flowmap.values() for flow in lst]
        self.load_flows(flows)

    def request(self, f: http.HTTPFlow) -> None:
        if self.flowmap:
            rflow = self.next_flow(f)
            if rflow:
                assert rflow.response
                reconstruction = (
                    self.reconstructions.get(id(rflow))
                    if ctx.options.server_replay_reconstruct
                    else None
                )
                if reconstruction is not None and self._client_validates(
                    f.request, reconstruction
                ):
                    response = self._make_not_modified(reconstruction)
                elif reconstruction is not None:
                    # A recorded 304 is replayed with the body of the earlier
                    # 200 entity it was reconstructed from.
                    response = reconstruction.prototype.copy()
                else:
                    response = rflow.response.copy()
                if ctx.options.server_replay_refresh:
                    last_modified = response.headers.get("last-modified")
                    response.refresh()
                    if reconstruction is not None and last_modified is not None:
                        # Entity validators stay anchored to the recording so
                        # that conditional clients keep validating correctly;
                        # all other refresh behaviour is unchanged.
                        response.headers["last-modified"] = last_modified
                f.response = response
                f.is_replay = "response"
            elif (
                ctx.options.server_replay_kill_extra
                or ctx.options.server_replay_extra == "kill"
            ):
                logging.warning(
                    "server_playback: killed non-replay request {}".format(
                        f.request.url
                    )
                )
                f.kill()
            elif ctx.options.server_replay_extra != "forward":
                logging.warning(
                    "server_playback: returned {} non-replay request {}".format(
                        ctx.options.server_replay_extra, f.request.url
                    )
                )
                f.response = http.Response.make(int(ctx.options.server_replay_extra))
                f.is_replay = "response"
