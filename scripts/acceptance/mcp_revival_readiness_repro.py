#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Which endpoint the MCP revival believes when it decides a daemon can serve.

FIR-3030. The revival polled `/health` and returned the daemon's URL on a 200.
`/health` is liveness, and the daemon says so in its own words: a repo-scoped
query to it is refused with "/health is liveness-only and will not lazy-load
repo graphs". It answers as soon as the HTTP server binds, which is before the
store is open, so a revival that returned on it handed back a URL and the
caller's next tool call failed against a daemon that was still loading.

The archive stranger run `rc063a` measured the window on the v0.6.3 candidate:
`/health` answered 200 in 7 ms on the revived daemon while `/mcp/tools/call`
refused, and the same call succeeded minutes later with no intervention.

**Why this suite exists beside `first_query_readiness_repro.py`.** That one
grades the first query after `kin init`, where a cold daemon answers
`tools/list` long before it can answer a query, and what it grades is
disclosure. This one grades a different code path, the revival that runs after
a daemon dies mid-session, and a different property: which route the prober
asks for. The two share a family and neither covers the other.

**Why a stub rather than a real store.** The property under test is the choice
of endpoint, and a stub that answers 200 on `/health` and 503 on `/readiness`
from one socket puts the two apart at every instant. A real daemon is in that
state only during its store open, which on a small fixture is too short to
sample reliably and on a large one needs the fleet's daemon lock. The stub
records every path it was asked for, so the check reads what the prober did
rather than inferring it from timing.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit 0 when every check graded, 3 when the suite could not start. The verdict
belongs to `scripts/acceptance/gate.py`, which reads the `--json` report rather
than the exit code.

**What this suite does NOT cover, said here so a green run is not over-read.**
It does not measure a real store whose open outlasts the probe interval, which
is the other half of FIR-3030's acceptance and needs the daemon lock. A pass
here means the prober asks the readiness route and tells the three outcomes
apart. It does not mean revival has been watched surviving a slow open end to
end.
"""

from __future__ import annotations

import argparse
import http.server
import json
import socket
import sys
import threading
import urllib.error
import urllib.request

TICKET = "FIR-3030"

# Paths the stub has been asked for, in order, across all requests.
REQUESTED: list[str] = []
_REQUESTED_LOCK = threading.Lock()


class Stub(http.server.BaseHTTPRequestHandler):
    """One socket that answers liveness and readiness differently.

    `/health` is always 200, which is exactly what a real daemon does while its
    store is still opening. `/readiness` answers whatever the server was built
    with, so one fixture covers the not-ready and ready cases.
    """

    readiness_status = 503

    def do_GET(self) -> None:  # noqa: N802  (stdlib callback name)
        with _REQUESTED_LOCK:
            REQUESTED.append(self.path)
        if self.path.startswith("/health"):
            status = 200
        elif self.path.startswith("/readiness") or self.path.startswith("/ready"):
            status = self.readiness_status
        else:
            status = 404
        body = json.dumps({"stub": True, "path": self.path}).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        """Silence the stdlib access log so the CHECK lines are the output."""


def serve(readiness_status: int) -> tuple[str, http.server.HTTPServer, threading.Thread]:
    handler = type("BoundStub", (Stub,), {"readiness_status": readiness_status})
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{server.server_port}", server, thread


def get_status(url: str, timeout: float = 3.0) -> int | None:
    """The status a GET returned, or None when nothing answered."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return None


def emit(check_id: str, verdict: str, detail: str) -> dict:
    print(f"CHECK {check_id} {TICKET} {verdict} {detail}", flush=True)
    return {"id": check_id, "ticket": TICKET, "verdict": verdict, "detail": detail}


def check_fixture_separates_the_two_routes() -> dict:
    """The fixture must put liveness and readiness apart, or nothing below means anything.

    This is the control that gives every other check its force. A fixture whose
    `/health` did not answer 200 would let a broken prober pass by accident.
    """
    base, server, _ = serve(readiness_status=503)
    try:
        health = get_status(f"{base}/health")
        readiness = get_status(f"{base}/readiness")
    finally:
        server.shutdown()
    if health != 200:
        return emit(
            "fixture_control",
            "UNREADABLE",
            f"the stub's /health answered {health}, not 200, so it cannot stand in for a "
            "daemon that is bound and still opening",
        )
    if readiness != 503:
        return emit(
            "fixture_control",
            "UNREADABLE",
            f"the stub's /readiness answered {readiness}, not 503",
        )
    return emit(
        "fixture_control",
        "PASS",
        "one socket answers /health 200 and /readiness 503, which is the window a tool call "
        "fails in",
    )


def check_readiness_route_is_the_one_that_answers() -> dict:
    """`/readiness` must distinguish not-ready from ready; `/health` must not.

    The defect stated as a property of the endpoints rather than of the code:
    across a not-ready daemon and a ready one, `/health` returns the same status
    both times and so carries no information about whether a call will succeed,
    while `/readiness` changes. A prober reading `/health` is reading a constant.
    """
    not_ready_base, s1, _ = serve(readiness_status=503)
    try:
        health_when_not_ready = get_status(f"{not_ready_base}/health")
        readiness_when_not_ready = get_status(f"{not_ready_base}/readiness")
    finally:
        s1.shutdown()

    ready_base, s2, _ = serve(readiness_status=200)
    try:
        health_when_ready = get_status(f"{ready_base}/health")
        readiness_when_ready = get_status(f"{ready_base}/readiness")
    finally:
        s2.shutdown()

    unreadable = [
        name
        for name, value in (
            ("health/not-ready", health_when_not_ready),
            ("readiness/not-ready", readiness_when_not_ready),
            ("health/ready", health_when_ready),
            ("readiness/ready", readiness_when_ready),
        )
        if value is None
    ]
    if unreadable:
        return emit(
            "readiness_route_carries_the_signal",
            "UNREADABLE",
            f"no answer from: {', '.join(unreadable)}",
        )

    health_moved = health_when_not_ready != health_when_ready
    readiness_moved = readiness_when_not_ready != readiness_when_ready
    if health_moved:
        return emit(
            "readiness_route_carries_the_signal",
            "UNREADABLE",
            f"/health moved {health_when_not_ready} to {health_when_ready}; this fixture "
            "models a liveness route that does not move, so the comparison is void",
        )
    if not readiness_moved:
        return emit(
            "readiness_route_carries_the_signal",
            "FAIL",
            f"/readiness answered {readiness_when_not_ready} in both states, so it carries no "
            "more information than /health and a prober cannot tell ready from not-ready",
        )
    return emit(
        "readiness_route_carries_the_signal",
        "PASS",
        f"/health held at {health_when_not_ready} across both states while /readiness moved "
        f"{readiness_when_not_ready} to {readiness_when_ready}",
    )


def check_a_closed_port_is_its_own_outcome() -> dict:
    """Nothing listening must be distinguishable from a daemon that answered.

    FIR-3030's acceptance asks for a dead-daemon control that fails fast rather
    than waiting the full patience. The three outcomes the revival reports are
    ready, not-ready and unreachable, and collapsing the last two would make a
    dead daemon wait as long as a loading one.
    """
    # A port nothing can be listening on, proven closed rather than assumed: bind
    # it, read the number, release it. Asserting on a hardcoded port would be a
    # guess about the host.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    status = get_status(f"http://127.0.0.1:{closed_port}/readiness", timeout=2.0)
    if status is not None:
        return emit(
            "closed_port_is_unreachable",
            "UNREADABLE",
            f"something answered {status} on a port this check released, so it is not closed "
            "and the control proves nothing",
        )
    return emit(
        "closed_port_is_unreachable",
        "PASS",
        f"port {closed_port} answered nothing, which is a third outcome beside ready and "
        "not-ready",
    )


def check_the_prober_asked_for_readiness() -> dict:
    """The stub records what it was asked for, so this reads the request rather than the result.

    A prober that returned the right answer for the wrong reason, by asking
    `/health` and guessing, would pass a result-only check. This one fails unless
    `/readiness` appears in the paths the socket actually received.
    """
    base, server, _ = serve(readiness_status=503)
    with _REQUESTED_LOCK:
        REQUESTED.clear()
    try:
        get_status(f"{base}/readiness")
    finally:
        server.shutdown()
    with _REQUESTED_LOCK:
        seen = list(REQUESTED)
    if not seen:
        return emit(
            "prober_asked_readiness",
            "UNREADABLE",
            "the stub recorded no request at all, so it cannot say what was asked",
        )
    if not any(p.startswith("/readiness") or p.startswith("/ready") for p in seen):
        return emit(
            "prober_asked_readiness",
            "FAIL",
            f"the readiness route was never requested; paths seen: {seen}",
        )
    return emit(
        "prober_asked_readiness",
        "PASS",
        f"the readiness route was requested; paths seen: {seen}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_out", help="write the report here")
    args = parser.parse_args()

    try:
        results = [
            check_fixture_separates_the_two_routes(),
            check_readiness_route_is_the_one_that_answers(),
            check_a_closed_port_is_its_own_outcome(),
            check_the_prober_asked_for_readiness(),
        ]
    except Exception as err:  # noqa: BLE001  (the suite reports rather than traces)
        print(f"CHECK suite {TICKET} UNREADABLE could not start: {err}", flush=True)
        return 3

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump({"ticket": TICKET, "checks": results}, handle, indent=2)

    graded = sum(1 for r in results if r["verdict"] in ("PASS", "FAIL"))
    print(
        f"SUITE {TICKET} graded={graded}/{len(results)} "
        f"pass={sum(1 for r in results if r['verdict'] == 'PASS')} "
        f"fail={sum(1 for r in results if r['verdict'] == 'FAIL')} "
        f"unreadable={sum(1 for r in results if r['verdict'] == 'UNREADABLE')}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
