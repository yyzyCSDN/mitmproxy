from __future__ import annotations

import time
from collections.abc import Sequence

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import dns
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import hooks
from mitmproxy import io

# RFC 1035, 4.2.1: UDP DNS messages are limited to 512 bytes unless EDNS is used.
UDP_SIZE_LIMIT = 512

# EDNS OPT meta-RRs and transaction/DNSSEC signature records are not supported yet.
_UNSUPPORTED_RECORD_TYPES = (
    dns.types.OPT,
    dns.types.SIG,
    dns.types.RRSIG,
    dns.types.TSIG,
)


class DnsReplay:
    """
    Replay previously recorded DNS responses.

    In contrast to a DNS cache, recordings are answered verbatim: the records
    and their TTLs are returned exactly as recorded, they neither age nor get
    refreshed. Only the transaction ID and the question section are taken from
    the current query.
    """

    library: dict[tuple[str, int], dns.DNSMessage]
    configured: bool

    def __init__(self) -> None:
        self.library = {}
        self.configured = False

    def load(self, loader) -> None:
        loader.add_option(
            "dns_replay",
            Sequence[str],
            [],
            "Replay DNS responses from a saved file.",
        )
        loader.add_option(
            "dns_replay_extra",
            str,
            "forward",
            "Behaviour for DNS queries for which no replayable response was recorded "
            "or which are not supported by DNS replay. 'forward' resolves them "
            "normally, 'refuse' returns a REFUSED response without contacting an "
            "upstream name server.",
            choices=["forward", "refuse"],
        )

    def configure(self, updated) -> None:
        if not self.configured and ctx.options.dns_replay:
            self.configured = True
            try:
                flows = io.read_flows_from_paths(ctx.options.dns_replay)
            except exceptions.FlowReadException as e:
                raise exceptions.OptionsError(str(e))
            self.load_flows(flows)

    @command.command("replay.dns")
    def load_flows(self, flows: Sequence[flow.Flow]) -> None:
        """
        Replace the DNS replay set with the DNS responses from these flows.
        The new set is only activated once all flows have been read, so a
        read failure leaves the previous set in place.
        """
        self.library = self._build_library(flows)
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.dns.add")
    def add_flows(self, flows: Sequence[flow.Flow]) -> None:
        """
        Add DNS responses from flows to the replay set. If a query is already
        present, the last complete answer loaded wins.
        """
        self.library.update(self._build_library(flows))
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.dns.file")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        """
        Replace the DNS replay set with the DNS responses from a saved file.
        If the file cannot be read, the current replay set is kept.
        """
        try:
            flows = io.read_flows_from_paths([path])
        except exceptions.FlowReadException as e:
            raise exceptions.CommandError(str(e))
        self.load_flows(flows)

    @command.command("replay.dns.stop")
    def clear(self) -> None:
        """
        Stop DNS replay and restore normal DNS resolution.
        """
        self.library = {}
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.dns.count")
    def count(self) -> int:
        """
        Number of recorded DNS queries available for replay.
        """
        return len(self.library)

    def _build_library(
        self, flows: Sequence[flow.Flow]
    ) -> dict[tuple[str, int], dns.DNSMessage]:
        library: dict[tuple[str, int], dns.DNSMessage] = {}
        for f in flows:
            if not isinstance(f, dns.DNSFlow):
                continue
            question = self._replayable_question(f.request)
            if question is None:
                continue
            response = f.response
            if response is None or not self._is_recorded_answer(response):
                continue
            library[self._key(question)] = response
        return library

    @staticmethod
    def _key(question: dns.Question) -> tuple[str, int]:
        # Domain names are compared case-insensitively and a trailing dot is
        # insignificant, only name and record type identify an answer.
        return (question.name.rstrip(".").lower(), question.type)

    @classmethod
    def _replayable_question(cls, message: dns.DNSMessage) -> dns.Question | None:
        """
        Returns the question if this is a single-question IN-class A/AAAA query
        without EDNS or signature records, and None otherwise.
        """
        if not message.query or message.op_code != dns.op_codes.QUERY:
            return None
        question = message.question
        if question is None:
            return None
        if question.class_ != dns.classes.IN:
            return None
        if question.type not in (dns.types.A, dns.types.AAAA):
            return None
        if any(rr.type in _UNSUPPORTED_RECORD_TYPES for rr in message.additionals):
            return None
        return question

    @classmethod
    def _is_recorded_answer(cls, message: dns.DNSMessage | None) -> bool:
        if message is None or message.query:
            return False
        # A truncated recording is not a complete answer.
        if message.truncation:
            return False
        for section in (message.answers, message.authorities, message.additionals):
            if any(rr.type in _UNSUPPORTED_RECORD_TYPES for rr in section):
                return False
        return True

    def dns_request(self, f: dns.DNSFlow) -> None:
        if not self.library:
            return
        if not f.live or f.response or f.error:
            return
        question = self._replayable_question(f.request)
        recorded = (
            self.library.get(self._key(question)) if question is not None else None
        )
        if recorded is not None:
            f.response = self._replay(recorded, f)
            f.is_replay = "response"
        elif ctx.options.dns_replay_extra == "refuse":
            # Do not fall through to upstream resolution.
            f.response = f.request.fail(dns.response_codes.REFUSED)
            f.is_replay = "response"

    def _replay(self, recorded: dns.DNSMessage, f: dns.DNSFlow) -> dns.DNSMessage:
        # Build an independent copy of the recording. Nothing here must mutate
        # the stored recording, which can be replayed many times.
        oversized = (
            f.client_conn.transport_protocol == "udp"
            and len(recorded.packed) > UDP_SIZE_LIMIT
        )
        response = dns.DNSMessage.from_state(recorded.get_state())
        # Use the current query's transaction ID and question section.
        response.id = f.request.id
        response.questions = [
            dns.Question.from_state(q.get_state()) for q in f.request.questions
        ]
        response.timestamp = time.time()
        if oversized:
            # Signal the client to re-query over TCP, where the full response
            # will be available. The recording itself stays intact.
            response.truncation = True
            response.answers = []
            response.authorities = []
            response.additionals = []
        return response
