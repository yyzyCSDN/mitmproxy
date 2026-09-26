"""
Replay recorded DNS responses for fully offline integration tests.

Instead of running a separate fake DNS server, mitmproxy can answer queries
from a previously recorded flow file. Records and TTLs are returned verbatim,
they neither age nor get refreshed upstream.

Record DNS traffic once:

    mitmdump --mode dns -w dns.mitm

Replay it later. By default, queries without a recorded answer are resolved
normally; set ``--dns-replay-extra refuse`` for a fully offline setup where
they get a REFUSED response instead:

    mitmdump --mode dns --dns-replay dns.mitm --dns-replay-extra refuse

This script shows how to drive the same feature programmatically: it forces
the offline ``refuse`` policy and provides a ``dns_replay_swap`` command that
atomically replaces the recording set at runtime, keeping the previous set if
the new file cannot be read:

    :dns_replay_swap @d:/recordings/new-dns.mitm
"""

from __future__ import annotations

import logging

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions

logger = logging.getLogger(__name__)


def running() -> None:
    # Do not contact any real name server for unrecorded queries.
    ctx.options.dns_replay_extra = "refuse"


@command.command("dns_replay_swap")
def dns_replay_swap(path: mitmproxy.types.Path) -> None:
    """
    Replace the DNS replay set with a different recording file.
    If the file cannot be read, the current set is kept.
    """
    try:
        ctx.master.commands.call("replay.dns.file", path)
    except exceptions.CommandError as e:
        logger.warning(str(e))
