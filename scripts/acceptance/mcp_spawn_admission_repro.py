#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""What an MCP session costs a repository it has asked nothing about.

FIR-3099. `kin mcp start` used to resolve its repo daemon from a task it
started beside the stdio loop, and the workspace-roots binder resolved one
again from the client's `roots/list` answer. Resolving a daemon STARTS one when
none is serving, and a daemon that starts opens the store and schedules the
background embedding pass. So an agent session that made no Kin call at all was
paying for a full embed of that repository. Measured on 2026-09-02 against a
24-file fixture whose store is 657.8 KiB: a daemon appeared 0.1 s after the
handshake and held 1.80 GiB resident and 99 percent of a core at sixty seconds,
with `sample` putting every frame in `run_background_embedding_batch`. On the
kin checkout the same shape reached 17.7 GiB on Metal, beside a measured run
that held the fleet's gpu lock.

Both doors are graded here, because closing one leaves the other open:

* the launcher's own startup binding, which fires whatever the client sends;
* the workspace-roots binder, which fires on the `roots/list` answer and is the
  only door when the server was launched outside a repository.

**The control is the point of the suite.** A server that answered nothing at
all would pass "no daemon appeared" perfectly. So the last check makes one
`semantic_locate` call and requires the daemon AND its embedding worker to
appear. Without it, deleting the MCP server would score four passes.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit 0 when every check graded, 3 when the suite could not start. The verdict
belongs to `scripts/acceptance/gate.py`, which reads the `--json` report rather
than the exit code.

**What this does NOT cover, said here so a green run is not over-read.** It
grades one repository per arm on a fixture whose daemon opens in seconds, so it
says nothing about a store whose open outlasts the observation window, and it
does not measure Metal: every arm forces `KIN_EMBED_BACKEND=cpu` so the suite
never contends for the GPU on the fleet host. What it proves is that a
handshake, a tool list and a workspace-roots answer start no daemon, and that a
tool call still does.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

TICKET = "FIR-3099"

# The daemon's own line for "my embedding worker is past the init wait and
# running", emitted by `kin_daemon::daemon` immediately before it queues or
# defers the pass. Named once so neither side can reword it and disarm this.
EMBED_WORKER_MARKER = "embedding worker started"

# How long to watch after the handshake. The reproduction saw the daemon at
# 0.1 s and its embedding worker inside ten, so this is many times the window
# in which the old behavior was visible.
WATCH_SECONDS = 45.0


def emit(check_id: str, status: str, detail: str) -> dict:
    print(f"CHECK {check_id} {TICKET} {status} {detail}", flush=True)
    return {"id": check_id, "ticket": TICKET, "status": status, "detail": detail}


def emit_row(check_id: str, status: str, detail: str) -> dict:
    """One report row without printing a CHECK line, for the self-test."""
    return {"id": check_id, "ticket": TICKET, "status": status, "detail": detail}


def report_payload(results: list[dict]) -> dict:
    """The report shape `scripts/acceptance/gate.py` reads.

    The key is `results` and not `checks`, and each row's verdict is `status`.
    That is not a style choice: the gate calls `payload.get("results")` and
    refuses anything else by name, then reads `row.get("status")` to decide.
    This suite shipped keyed `checks`, so main's push run for 4e37d08b3 printed
    four PASS lines and the verdict step still errored on the file they wrote.
    That is the fifth suite to break this gate on this key, after
    same_owner_call, working_copy_freshness, init_budget and vcs_read_surfaces.

    Written once here and read back through the gate's own loader by the
    self-test below, which is the part that stops it drifting again. A suite
    that only asserts its own shape is asserting against itself.
    """
    return {"suite": "mcp_spawn", "ticket": TICKET, "results": results}


# ── graders ──────────────────────────────────────────────────────────────
# Pure over their inputs so `--self-test` can put each one against the case it
# must call the other way.


def daemon_lines(ps_output: str, repo: str, daemon_bin: str) -> list[tuple[str, str]]:
    """`(pid, argv)` for every `kin-daemon` serving `repo`.

    Both needles are required, and the daemon binary must be the executable
    rather than merely somewhere in the line: on a shared host another lane's
    daemon must not be counted as this arm's, and neither must the driver that
    carries both paths in its own argv.

    The pid comes back with the line because the watch samples repeatedly, and a
    caller that counted lines rather than pids would report one daemon seen
    twenty-two times as twenty-two daemons.
    """
    found = []
    for line in ps_output.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        args = parts[5]
        if args.split(None, 1)[0] != daemon_bin:
            continue
        if repo not in args:
            continue
        found.append((parts[0], args))
    return found


def embed_worker_ran(daemon_log: str) -> bool:
    """Whether a daemon log records its embedding worker starting."""
    return EMBED_WORKER_MARKER in daemon_log


# ── fixture and session ──────────────────────────────────────────────────


def build_fixture(root: Path, kin: str, env: dict) -> Path:
    """A committed repository with entities and no vectors."""
    repo = root / "repo"
    repo.mkdir(parents=True)
    for i in range(24):
        (repo / f"mod_{i:02d}.py").write_text(
            f'"""Module {i}."""\n\n\n'
            f"class Handler{i}:\n"
            f"    def dispatch(self, payload):\n"
            f"        return self.transform(payload)\n\n"
            f"    def transform(self, payload):\n"
            f'        return {{"shard": {i}, "value": payload}}\n\n\n'
            f"def build_handler_{i}() -> Handler{i}:\n"
            f"    return Handler{i}()\n"
        )
    # The identity is passed with `-c` as well as through the environment, and
    # the commit is signed off, so this works on a bare CI runner with no git
    # config AND on a workstation whose hooks require a DCO line. A fixture the
    # suite cannot commit reports UNREADABLE for every check, which is a broken
    # grader rather than a product verdict.
    git = {**env, "GIT_AUTHOR_NAME": "Kin CI", "GIT_AUTHOR_EMAIL": "ci@kinlab.ai",
           "GIT_COMMITTER_NAME": "Kin CI", "GIT_COMMITTER_EMAIL": "ci@kinlab.ai"}
    ident = ["-c", "user.name=Kin CI", "-c", "user.email=ci@kinlab.ai"]
    for argv in (["git", "init", "-q", "."],
                 ["git", *ident, "add", "-A"],
                 ["git", *ident, "commit", "-qsm", "Add the spawn-admission fixture"]):
        done = subprocess.run(argv, cwd=repo, env=git, capture_output=True, text=True)
        if done.returncode != 0:
            raise RuntimeError(
                f"{' '.join(argv)} failed ({done.returncode}): "
                f"{(done.stderr or done.stdout).strip()[:400]}")
    done = subprocess.run([kin, "init", "--no-enrich", "."], cwd=repo, env=env,
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"kin init failed ({done.returncode}): "
                           f"{(done.stderr or done.stdout).strip()[-400:]}")
    return repo


def session(kin: str, daemon_bin: str, repo: Path, kin_home: Path, cwd: Path,
            roots_answer: Path | None, tool_call: str | None,
            watch_seconds: float, stop_when: str = "never") -> dict:
    """One MCP server, one handshake, and what appeared in the process table.

    Drives the server exactly as an agent CLI does: newline-delimited JSON-RPC
    on stdin, `initialize`, `notifications/initialized`, `tools/list`, then
    `tools/call` only when this arm is the control. stdin stays open the whole
    time, because a client that closed it would end the session before the
    window this suite is watching.
    """
    env = dict(os.environ)
    env["KIN_HOME"] = str(kin_home)
    env["KIN_EMBED_BACKEND"] = "cpu"
    env["KIN_MCP_TOOL_PROFILE"] = "agent-default"
    for leaked in ("KIN_DAEMON_URL", "KIN_NO_DAEMON", "KIN_MCP_REPO"):
        env.pop(leaked, None)

    proc = subprocess.Popen([kin, "mcp", "start"], cwd=str(cwd), env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    stdout_lines: list[str] = []

    def pump() -> None:
        for line in proc.stdout:
            stdout_lines.append(line)
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("method") == "roots/list" and roots_answer is not None:
                proc.stdin.write(json.dumps({
                    "jsonrpc": "2.0", "id": message.get("id"),
                    "result": {"roots": [{"uri": f"file://{roots_answer}",
                                          "name": "fixture"}]},
                }) + "\n")
                proc.stdin.flush()

    threading.Thread(target=pump, daemon=True).start()

    caps = {"roots": {"listChanged": True}} if roots_answer is not None else {}
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": caps,
                    "clientInfo": {"name": "fir3099-acceptance", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    if tool_call:
        messages.append({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": tool_call,
                                    "arguments": {"query": "where is a handler dispatched"}}})
    for message in messages:
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()
        time.sleep(0.3)

    # `stop_when` ends the watch early for the control arms, which have already
    # proved their point once the thing they are waiting for appears. The
    # no-daemon arms never stop early: their claim is about the whole window, so
    # ending it as soon as nothing has happened would be no claim at all.
    log_path = repo / ".kin" / "daemon.log"
    seen: dict[str, str] = {}
    deadline = time.time() + watch_seconds
    while time.time() < deadline:
        ps = subprocess.run(["ps", "-Ao", "pid=,ppid=,rss=,pcpu=,etime=,args="],
                            capture_output=True, text=True).stdout
        seen.update(dict(daemon_lines(ps, str(repo), daemon_bin)))
        if stop_when == "daemon" and seen:
            break
        if stop_when == "embed" and log_path.exists() and embed_worker_ran(
                log_path.read_text(errors="replace")):
            break
        time.sleep(2)

    try:
        proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=10)

    result = {
        "daemons": [f"pid {pid}: {args}" for pid, args in sorted(seen.items())],
        "daemon_log": log_path.read_text(errors="replace") if log_path.exists() else "",
        "stderr": (proc.stderr.read() or "")[-4000:],
        "stdout": "".join(stdout_lines)[-4000:],
    }
    subprocess.run([kin, "daemon", "stop"], cwd=str(repo), env=env,
                   capture_output=True, text=True)
    return result


# ── checks ───────────────────────────────────────────────────────────────


def check_handshake_starts_no_daemon(kin, daemon_bin, workdir) -> dict:
    """The launcher's own startup binding, which fires whatever the client sends."""
    root = workdir / "startup-door"
    home = root / "kin-home"
    home.mkdir(parents=True)
    env = {**os.environ, "KIN_HOME": str(home), "KIN_EMBED_BACKEND": "cpu"}
    repo = build_fixture(root, kin, env)
    outcome = session(kin, daemon_bin, repo, home, repo, None, None, WATCH_SECONDS)
    if outcome["daemons"]:
        return emit("startup_binding_starts_no_daemon", "FAIL",
                    f"the handshake started {len(outcome['daemons'])} daemon(s) with no tool "
                    f"call: {outcome['daemons'][0][:160]}")
    if embed_worker_ran(outcome["daemon_log"]):
        return emit("startup_binding_starts_no_daemon", "FAIL",
                    "no daemon was in the process table but the daemon log records an "
                    "embedding worker starting")
    return emit("startup_binding_starts_no_daemon", "PASS",
                f"initialize, initialized and tools/list started no daemon in "
                f"{WATCH_SECONDS:.0f}s and dispatched no embedding")


def check_roots_answer_starts_no_daemon(kin, daemon_bin, workdir) -> dict:
    """The workspace-roots binder, which is the only door outside a repository."""
    root = workdir / "roots-door"
    home = root / "kin-home"
    home.mkdir(parents=True)
    outside = root / "not-a-repo"
    outside.mkdir(parents=True)
    env = {**os.environ, "KIN_HOME": str(home), "KIN_EMBED_BACKEND": "cpu"}
    repo = build_fixture(root, kin, env)
    outcome = session(kin, daemon_bin, repo, home, outside, repo, None, WATCH_SECONDS)
    if outcome["daemons"]:
        return emit("workspace_roots_start_no_daemon", "FAIL",
                    f"the client's roots answer started {len(outcome['daemons'])} daemon(s) "
                    f"with no tool call: {outcome['daemons'][0][:160]}")
    if embed_worker_ran(outcome["daemon_log"]):
        return emit("workspace_roots_start_no_daemon", "FAIL",
                    "no daemon was in the process table but the daemon log records an "
                    "embedding worker starting")
    return emit("workspace_roots_start_no_daemon", "PASS",
                f"a roots/list answer naming the repository started no daemon in "
                f"{WATCH_SECONDS:.0f}s")


def check_a_tool_call_still_starts_the_daemon(kin, daemon_bin, workdir) -> dict:
    """The control. Without it the two checks above pass on a server that does nothing."""
    root = workdir / "control"
    home = root / "kin-home"
    home.mkdir(parents=True)
    env = {**os.environ, "KIN_HOME": str(home), "KIN_EMBED_BACKEND": "cpu"}
    repo = build_fixture(root, kin, env)
    outcome = session(kin, daemon_bin, repo, home, repo, None, "semantic_locate",
                      WATCH_SECONDS * 2, stop_when="daemon")
    if not outcome["daemons"]:
        return emit("a_tool_call_still_starts_the_daemon", "FAIL",
                    "a semantic_locate call produced no daemon, so the two no-daemon checks "
                    f"above prove nothing; server stderr: {outcome['stderr'][-400:]}")
    return emit("a_tool_call_still_starts_the_daemon", "PASS",
                f"the first semantic_locate produced the daemon: "
                f"{outcome['daemons'][0][:160]}")


def check_a_tool_call_still_dispatches_the_embed(kin, daemon_bin, workdir) -> dict:
    """The other half of the control: the daemon a call produces still embeds."""
    root = workdir / "control-embed"
    home = root / "kin-home"
    home.mkdir(parents=True)
    env = {**os.environ, "KIN_HOME": str(home), "KIN_EMBED_BACKEND": "cpu"}
    repo = build_fixture(root, kin, env)
    outcome = session(kin, daemon_bin, repo, home, repo, None, "semantic_locate",
                      WATCH_SECONDS * 2, stop_when="embed")
    if not outcome["daemon_log"]:
        return emit("a_tool_call_still_dispatches_the_embed", "UNREADABLE",
                    "the daemon wrote no log for this store, so the embedding marker "
                    "cannot be read either way")
    if not embed_worker_ran(outcome["daemon_log"]):
        return emit("a_tool_call_still_dispatches_the_embed", "FAIL",
                    "the daemon a tool call produced never started its embedding worker, so "
                    "a cold store would answer without vectors forever")
    return emit("a_tool_call_still_dispatches_the_embed", "PASS",
                f"the daemon a tool call produced logged '{EMBED_WORKER_MARKER}'")


# ── self-test ────────────────────────────────────────────────────────────


def self_test() -> int:
    """Every grader against the case it must call the other way.

    A suite whose graders cannot tell their own cases apart reports a clean
    product on a broken one, so these run before any binary is built.
    """
    failures = []
    daemon_bin = "/opt/kin/bin/kin-daemon"
    repo = "/work/fixture"
    present = (
        f"  101   100  55000  39.1 00:01 {daemon_bin} --repo {repo} --port 0\n"
    )
    absent = "  102   100  20000   0.1 00:02 /usr/bin/python3 driver.py\n"
    other_lane = f"  103   100  55000  10.0 00:03 {daemon_bin} --repo /work/other --port 0\n"
    # The driver carries both needles in its own argv; a substring match would
    # count it as a daemon, which is the bug this shape exists to avoid.
    driver = f"  104   100  20000   0.1 00:04 /usr/bin/python3 repro.py --daemon {daemon_bin} --repo {repo}\n"

    cases = [
        ("a daemon for this repo is found", present + absent, 1),
        ("no daemon is not invented", absent, 0),
        ("another lane's daemon is not counted", other_lane + absent, 0),
        ("the driver's own argv is not a daemon", driver, 0),
    ]
    for name, ps_output, expected in cases:
        rows = daemon_lines(ps_output, repo, daemon_bin)
        got = len(rows)
        if got and any(not pid.isdigit() for pid, _ in rows):
            failures.append(f"daemon_lines: {name}: a row came back without a pid")
        if got != expected:
            failures.append(f"daemon_lines: {name}: expected {expected}, got {got}")

    # One daemon sampled twice is one daemon. A watch that counted lines would
    # report the same process as many, which is what the pid key prevents.
    repeated = present + present
    if len(dict(daemon_lines(repeated, repo, daemon_bin))) != 1:
        failures.append("daemon_lines: one daemon sampled twice must key to one pid")

    if not embed_worker_ran(f"INFO kin_daemon: {EMBED_WORKER_MARKER}\n"):
        failures.append("embed_worker_ran: missed the marker it exists to find")
    if embed_worker_ran("INFO kin_daemon: reconcile complete\n"):
        failures.append("embed_worker_ran: reported an embedding worker from a log with none")
    if embed_worker_ran(""):
        failures.append("embed_worker_ran: reported an embedding worker from an empty log")

    # The row the gate's own error message prescribes: write this suite's report
    # and read it back through gate.py's loader, so a key that drifts fails here
    # rather than on main after four PASS lines have already printed.
    import importlib.util
    import tempfile

    gate_path = Path(__file__).with_name("gate.py")
    spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
    if spec is None or spec.loader is None:
        failures.append("gate.py could not be loaded, so the report shape is unchecked")
    else:
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        rows = [emit_row("probe", "PASS", "self-test")]
        with tempfile.TemporaryDirectory() as tmp:
            written = Path(tmp) / "mcp_spawn.json"
            written.write_text(json.dumps(report_payload(rows)), encoding="utf-8")
            try:
                loaded = gate.load_report(str(written))
            except Exception as err:  # noqa: BLE001
                failures.append(f"the gate's own loader refused this suite's report: {err}")
            else:
                if "probe" not in loaded:
                    failures.append("the gate's loader read the report but not its row id")
                elif loaded["probe"].get("status") != "PASS":
                    failures.append(
                        "the gate reads each row's verdict from `status`; this report "
                        f"gave it {loaded['probe'].get('status')!r}")
            # And the inverse, so the check above cannot pass by accident: the
            # shape this suite used to ship must still be refused.
            stale = Path(tmp) / "stale.json"
            stale.write_text(json.dumps({"ticket": TICKET, "checks": rows}), encoding="utf-8")
            try:
                gate.load_report(str(stale))
            except Exception:
                pass
            else:
                failures.append("the gate accepted a `checks`-keyed report, so this "
                                "control proves nothing")

    for failure in failures:
        print(f"SELFTEST FAIL {failure}", flush=True)
    if failures:
        return 1
    print(f"SELFTEST {TICKET} OK: {len(cases) + 6} grader cases, each against its inverse, "
          f"including the report this gate must be able to read",
          flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", help="path to the kin binary under test")
    parser.add_argument("--daemon", help="path to the kin-daemon binary under test")
    parser.add_argument("--json", dest="json_out", help="write the report here")
    parser.add_argument("--self-test", action="store_true",
                        help="falsify this suite's graders and exit")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.kin or not args.daemon:
        print(f"CHECK suite {TICKET} UNREADABLE --kin and --daemon are required", flush=True)
        return 3

    kin = str(Path(args.kin).resolve())
    daemon_bin = str(Path(args.daemon).resolve())
    workdir = Path(tempfile.mkdtemp(prefix="kin-fir3099-"))
    try:
        results = [
            check_handshake_starts_no_daemon(kin, daemon_bin, workdir),
            check_roots_answer_starts_no_daemon(kin, daemon_bin, workdir),
            check_a_tool_call_still_starts_the_daemon(kin, daemon_bin, workdir),
            check_a_tool_call_still_dispatches_the_embed(kin, daemon_bin, workdir),
        ]
    except Exception as err:  # noqa: BLE001  (the suite reports rather than traces)
        print(f"CHECK suite {TICKET} UNREADABLE could not start: {err}", flush=True)
        return 3
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(report_payload(results), handle, indent=2)

    print(
        f"SUITE {TICKET} graded={sum(1 for r in results if r['status'] in ('PASS', 'FAIL'))}"
        f"/{len(results)} pass={sum(1 for r in results if r['status'] == 'PASS')} "
        f"fail={sum(1 for r in results if r['status'] == 'FAIL')} "
        f"unreadable={sum(1 for r in results if r['status'] == 'UNREADABLE')}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
