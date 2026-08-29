#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""First-contact honesty: what a stranger meets before the graph answers anything.

Eight defects strangers hit on shipped builds, each on a surface that runs before
any semantic question is asked, and none of them visible to the suites that grade
answers. Checks 0 to 2 come from the npm0549 green stranger on 0.5.49; check 3
comes from the rc060n brown stranger on 0.6.0; checks 4 to 6 come from the
2026-08-28 cold walkthrough; check 7 comes from the v0.6.1 release run:

  CHECK 0 (FIR-2627)  `kin commit --help` never said a Kin commit is not a git
                      commit, so the write-through assumption formed at help and
                      was corrected only after a commit had already run.
  CHECK 1 (FIR-2628)  `npm install -g @kinlab/kin` fails EACCES for a non-root
                      user with no sudo. npm dies before this package is
                      unpacked, so no postinstall and no launcher can catch it;
                      the only fix that reaches the user is the documented
                      install path itself not needing the prefix that is refused.
  CHECK 2 (FIR-2629)  `kin doctor --fix --install-language-servers` failed behind
                      a proxy without naming the environment as the cause, the
                      variables that would route it, the offline route to a
                      working server, or the fact that Kin works without one.
                      Probed through `kin setup --install-language-servers`,
                      which reaches the same installer without needing a store;
                      check 2's own docstring says why and what pins the rest.
  CHECK 3 (FIR-2787)  `kin doctor` said nothing about memory until a repository
                      existed, so a stranger on a 12 GiB container learned what
                      the machine could not do only after an eleven-minute
                      conversion had already spent itself. Graded outside a
                      repository, which is the only place the question is asked
                      in time.
  CHECK 4 (coldwalk)  `kin doctor --fix --install-language-servers` refused on a
                      host with no `rustup`, so following the product's own
                      repair left a Rust repository with no reference edges.
  CHECK 5 (coldwalk)  the MCP entry the install page hands every client exited 2
                      on `initialize` when the launch directory held no `.kin/`,
                      which the page's own ordering guarantees for a first-time
                      user.
  CHECK 6 (coldwalk)  `kin init` printed `cross-file enrichment complete
                      (5/303 files)` over a sweep whose Rust server never
                      started, and the same store's `kin graph status` said the
                      Rust edges were missing. One store cannot say both things.
  CHECK 7 (FIR-2919)  `kin doctor --json` reported `"healthy": true` on a fresh
                      Windows install whose own rows read `embedding_model`
                      pending and `memory_floor` degraded, while the same run's
                      printed page closed on "2 checks need attention". The
                      release install proof threw on the contradiction and
                      fenced v0.6.1.

A new suite rather than rows bolted onto the graph suites, for one reason: these
are graded on the surfaces a stranger meets first, and most of them need no
store, no daemon and no corpus at all. Checks 4 and 6 do build one, because the
defects they cover live in `kin init` and in a sweep; each builds its own from a
handful of files and none of them touches a corpus. The CHECK line format, the
exit codes and the JSON shape are the same as every other suite here, because
scripts/acceptance/gate.py reads all of them through one contract.

Exit status: 1 when any check fails, 2 when none fail but some are unreadable, 3
on a setup error, 0 only when every selected check passes.
"""

import argparse
import gzip
import hashlib
import io
import threading
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text):
    return ANSI.sub("", text or "")


def flatten(text):
    """Collapse every run of whitespace, so a wrapped line still matches.

    Help output and doctor rows are wrapped to the terminal, so a sentence the
    product really does print is split across lines by the renderer. A byte-level
    search for that sentence then finds nothing and reads exactly like the
    sentence being absent.
    """
    return " ".join(strip_ansi(text).split())


def run(cmd, cwd=None, env=None, timeout=600, stdin_text=None):
    """(rc, stdout, stderr), never raising on a non-zero exit."""
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if stdin_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
    except OSError as exc:
        return 127, "", "could not execute %s: %s" % (cmd[0], exc)
    try:
        out, err = proc.communicate(input=stdin_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out or "", (err or "") + "\n[timed out after %ss]" % timeout
    return proc.returncode, out or "", err or ""


class Result(object):
    def __init__(self, check_id, ticket, title):
        self.id = check_id
        self.ticket = ticket
        self.title = title
        self.asserts = []

    def add(self, status, detail):
        self.asserts.append({"status": status, "detail": detail})

    def ok(self, detail):
        self.add(PASS, detail)

    def bad(self, detail):
        self.add(FAIL, detail)

    def unknown(self, detail):
        self.add(UNREADABLE, detail)

    @property
    def status(self):
        if any(a["status"] == FAIL for a in self.asserts):
            return FAIL
        if any(a["status"] == UNREADABLE for a in self.asserts):
            return UNREADABLE
        if not self.asserts:
            return UNREADABLE
        return PASS

    @property
    def detail(self):
        for wanted in (FAIL, UNREADABLE):
            for a in self.asserts:
                if a["status"] == wanted:
                    return a["detail"]
        return self.asserts[-1]["detail"]


# --------------------------------------------------------------------- graders
#
# Every grader below is a pure function of text, so --self-test can hand it the
# exact defect that shipped and require it to fail on it. A grader that cannot
# tell its own cases apart reports a clean product on a broken one, which is the
# failure mode these suites exist to prevent.


# The sentence `kin commit` prints after recording a change, and the one
# `kin commit --help` now ends with. Held here as the literal the product
# emits: a grader that rebuilt it from parts would keep passing while the two
# surfaces drifted, which is the whole defect FIR-2627 reports.
AUTHORITY_LINE = (
    "Recorded in Kin authority, not in git. `git status` stays dirty until "
    "you run `kin eject` or push this branch to a Kin remote."
)

# A line that predates this change and is not about authority at all. Its job is
# to prove the grader is reading help rather than an empty string, because empty
# input satisfies every negative assertion in the check.
HELP_CONTROL = "Commit message"

# A phrase nothing in Kin has ever printed. If this matches, the grader is
# matching on something other than what it claims to.
HELP_NEVER_WRITTEN = "writes through to git"


def grade_commit_help(help_text):
    """(ok, detail) for `kin commit --help` carrying the authority paragraph."""
    flat = flatten(help_text)
    if not flat:
        return None, "help output was empty, so nothing could be graded"
    if HELP_CONTROL not in flat:
        return None, (
            "the control line %r is absent, so this is not the commit help and a "
            "verdict about it would be about the wrong text" % HELP_CONTROL
        )
    if HELP_NEVER_WRITTEN in flat:
        return None, (
            "the never-written control phrase %r matched, so the grader is not "
            "reading what it claims to" % HELP_NEVER_WRITTEN
        )
    if flatten(AUTHORITY_LINE) not in flat:
        return False, (
            "help carries the control line but not the commit-time authority "
            "sentence, so a reader still forms the write-through assumption here"
        )
    missing = [
        word
        for word in ("not in Git", "git status", "kin eject")
        if word not in flat
    ]
    if missing:
        return False, "help omits %s" % ", ".join(repr(m) for m in missing)
    return True, "help carries the authority sentence verbatim beside the control line"


# Everything the FIR-2629 remediation owes a reader whose install died on the
# network. Grouped by what each one answers: why, how to fix it, what it costs.
NETWORK_DIAGNOSIS = "the network refusing"
PROXY_VARIABLES = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
DEGRADED_MODE = "Kin runs without this server"
# The other half the ticket asks for by name: a way to a working server that
# does not need the network that just refused.
OFFLINE_PATH = "no registry is needed either"

# The failure line itself. Without it the run never reached the install path and
# the absence of a diagnosis says nothing about the classifier.
INSTALL_FAILURE = "could not install the"

# The remedy for the OTHER cause. A network failure handed the permission fix is
# a classifier that cannot tell its two cases apart.
PERMISSION_REMEDY = "npm config set prefix"


# npm's and rustup's own words for a network that refused them. Read as the
# precondition rather than as the answer: if the install died of something else,
# the classifier was never asked the question this check is about, and a verdict
# would be about the wrong failure. These come from the installer, never from
# this script, which is what keeps the check able to fail: a product that stops
# diagnosing still leaves ECONNREFUSED in the reported reason.
NETWORK_SIGNATURES = (
    "ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND", "EAI_AGAIN", "ECONNRESET",
    "network request to", "ERR_SOCKET_TIMEOUT",
)


# The offline-path line as the product prints it, held here so the self-test
# can delete exactly it and require the grader to notice.
OFFLINE_FIXTURE_LINE = (
    "      no registry is needed either: Kin looks for `pyright-langserver` or "
    "`pylsp` on PATH and starts whichever it finds\n"
)


def grade_network_diagnosis(output):
    """(ok, detail) for a language-server install that died on the network."""
    flat = flatten(output)
    if not flat:
        return None, "the run produced no output, so nothing could be graded"
    if INSTALL_FAILURE not in flat:
        return None, (
            "no language-server install failure was reported, so the run never "
            "reached the classifier and its silence is not evidence"
        )
    if not any(signature in flat for signature in NETWORK_SIGNATURES):
        return None, (
            "the install failed for a reason the installer did not describe in "
            "network terms, so this probe never asked the question FIR-2629 is "
            "about: %s" % flat[flat.find(INSTALL_FAILURE):][:220]
        )
    if NETWORK_DIAGNOSIS not in flat:
        return False, (
            "the failure was reported without naming the environment as the "
            "suspected cause, which is the bare failure FIR-2629 is about"
        )
    absent = [name for name in PROXY_VARIABLES if name not in flat]
    if absent:
        return False, (
            "the diagnosis names the network but not the variables that would "
            "route it: %s absent" % ", ".join(absent)
        )
    if DEGRADED_MODE not in flat:
        return False, (
            "nothing states that Kin works without the servers, so a reader "
            "cannot tell whether this failure ended their install"
        )
    if OFFLINE_PATH not in flat:
        return False, (
            "the degraded mode is stated but not the offline path, so a reader "
            "on a host that will never reach the registry is left with no route "
            "to a working server at all"
        )
    if PERMISSION_REMEDY in flat:
        return False, (
            "a network failure was handed the permission remedy (%r), so the two "
            "causes are not being told apart" % PERMISSION_REMEDY
        )
    return True, "the failure names the environment, the proxy variables and the degraded mode"


SH_BLOCK = re.compile(r"```sh\n(.*?)```", re.DOTALL)

PUBLISHED_SPEC = "@kinlab/kin"


def localize(line, tarball):
    """One README command, pointed at the local tarball instead of the registry.

    `npx` takes the command to run from the package spec, and a tarball path is
    not a command name, so the spec has to move to `--package` with the bin
    named explicitly. Nothing else in the line is touched: the flags, the
    ordering and the PATH export stay the reader's, because those are what this
    check is grading.
    """
    localized = line.replace(
        "npx -y %s" % PUBLISHED_SPEC,
        'npx -y --package="file:%s" kin' % tarball,
    )
    return localized.replace(PUBLISHED_SPEC, tarball)


def leading_install_block(readme_text):
    """The first ```sh block in the npm README, as a list of command lines.

    The rule is deliberately positional. FIR-2628's ask is that the install
    section LEAD with the path that needs no writable global prefix, and "leads
    with" is exactly "is the first shell block a reader meets".
    """
    match = SH_BLOCK.search(readme_text or "")
    if not match:
        return []
    return [line for line in match.group(1).splitlines() if line.strip()]


def grade_install_block(lines):
    """(ok, detail) for a leading block that a refused global prefix cannot stop.

    Graded on the text before it is run, so a block that would obviously need
    the prefix is named as the defect rather than as a shell failure.
    """
    if not lines:
        return None, "the README carries no ```sh block, so there is nothing to grade"
    joined = "\n".join(lines)
    if re.search(r"^\s*(sudo|npm\s+install\s+-g)\b", joined, re.MULTILINE):
        return False, (
            "the first install block still leads with a command needing root or a "
            "writable global npm prefix, which is the wall FIR-2628 reports: %r"
            % lines[0]
        )
    return True, "the leading block needs neither sudo nor a writable global prefix"


# ---------------------------------------------------------------------- checks


def check_0(suite):
    """FIR-2627: `kin commit --help` says where the commit lands."""
    res = Result("0", "FIR-2627", "kin commit --help names Kin authority and the git relationship")
    rc, out, err = run([suite.kin, "commit", "--help"], env=suite.base_env(), timeout=120)
    if rc != 0:
        res.unknown("`kin commit --help` exited %d: %s" % (rc, flatten(err)[:200]))
        return res
    ok, detail = grade_commit_help(out + "\n" + err)
    if ok is None:
        res.unknown(detail)
    elif ok:
        res.ok(detail)
    else:
        res.bad(detail)

    # The CLI reference is the other surface the ticket names, and it is written
    # by hand. A page that stopped quoting the sentence would leave the fix half
    # landed on the surface a reader reaches from a browser.
    page = os.path.join(suite.repo_root, "docs", "cli-reference.md")
    try:
        with open(page) as handle:
            text = handle.read()
    except IOError as exc:
        res.unknown("docs/cli-reference.md unreadable: %s" % exc)
        return res
    flat = flatten(text)
    if "### `kin commit`" not in text:
        res.unknown("docs/cli-reference.md carries no `kin commit` section to grade")
    elif flatten(AUTHORITY_LINE) not in flat:
        res.bad("docs/cli-reference.md no longer quotes the commit authority line")
    else:
        res.ok("docs/cli-reference.md quotes the same sentence")
    return res


def check_1(suite):
    """FIR-2628: the documented install works where the global prefix is refused."""
    res = Result("1", "FIR-2628", "a non-root install with no writable npm prefix reaches kin --version")
    npm = shutil.which("npm")
    if not npm:
        res.unknown("npm is not on PATH, so the install path cannot be exercised")
        return res

    package = os.path.join(suite.repo_root, "packages", "kin")
    try:
        with open(os.path.join(package, "README.md")) as handle:
            readme = handle.read()
    except IOError as exc:
        res.unknown("packages/kin/README.md unreadable: %s" % exc)
        return res

    lines = leading_install_block(readme)
    ok, detail = grade_install_block(lines)
    if ok is None:
        res.unknown(detail)
        return res
    if not ok:
        res.bad(detail)
        return res
    res.ok(detail)

    work = suite.scratch("install")
    home = os.path.join(work, "home")
    refused = os.path.join(work, "refused-prefix")
    os.makedirs(home)
    os.makedirs(os.path.join(refused, "lib"))

    # Pack the package under test rather than fetching the published one: this
    # check is about the bytes in the pull request, and a network fetch would
    # grade the last release.
    rc, out, err = run([npm, "pack", "--pack-destination", work, package],
                       cwd=work, env=suite.npm_env(home), timeout=600)
    tarballs = [f for f in os.listdir(work) if f.endswith(".tgz")]
    if rc != 0 or not tarballs:
        res.unknown("npm pack failed (%d): %s" % (rc, flatten(err)[:200]))
        return res
    tarball = os.path.join(work, tarballs[0])

    # The wall itself. npm reads `prefix` from the user's .npmrc, which is what
    # a container's root-owned /usr/local prefix looks like from inside.
    with open(os.path.join(home, ".npmrc"), "w") as handle:
        handle.write("prefix=%s\n" % refused)
    os.chmod(refused, stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)

    env = suite.npm_env(home)
    rc, out, err = run([npm, "install", "-g", tarball], cwd=work, env=env, timeout=900)
    combined = flatten(out + " " + err)
    if rc == 0:
        # Running as root, or on a filesystem that ignores the mode. The probe
        # cannot see the wall it is about, and saying so is the honest outcome;
        # reporting PASS here would be a check that cannot fail.
        res.unknown(
            "the global install SUCCEEDED against a prefix this probe made "
            "unwritable (uid %d), so the refusal this check is about was never "
            "reproduced" % os.getuid()
        )
        return res
    if "EACCES" not in combined and "permission denied" not in combined.lower():
        res.unknown("the global install failed for a reason that is not the "
                    "refusal under test: %s" % combined[:200])
        return res
    res.ok("npm install -g is refused here exactly as it is in the stranger's container")

    # Now follow the README, and only the README. The published package spec is
    # rewritten to the local tarball so nothing is fetched and the bytes under
    # test are the ones in this pull request; every other token is the reader's.
    script = "\n".join(localize(line, tarball) for line in lines)
    seeded = os.path.join(home, ".kin", "bin")
    os.makedirs(seeded)
    for name in ("kin", "kin-daemon"):
        source = suite.kin if name == "kin" else suite.daemon
        if source and os.path.exists(source):
            shutil.copy2(source, os.path.join(seeded, name))
    if not os.path.exists(os.path.join(seeded, "kin")):
        res.unknown("no kin binary to stand in for the provisioned one")
        return res

    # KIN_NO_PROVISION stubs the download, and the seeded directory stands in
    # for what it would have written. What stays under test is the part this
    # check is about: whether the documented first path can run at all on a
    # machine whose global npm prefix refuses it. The download itself is proven
    # by the release install proof, not here, and the CHECK line says so.
    env = suite.npm_env(home)
    env["KIN_NO_PROVISION"] = "1"
    # The block runs with no kin on PATH, so the only `kin` it can reach is the
    # one its own commands put there. Without this the probe resolves the
    # operator's installed kin and passes a block that installs nothing.
    env["PATH"] = suite.sanitized_path(work)
    rc, out, err = run(["bash", "-euo", "pipefail", "-c", script],
                       cwd=work, env=env, timeout=900)
    said = flatten(out + " " + err)
    if rc != 0:
        res.bad("the README's leading install block failed (%d) on a host whose "
                "global npm prefix is refused: %s" % (rc, said[:250]))
        return res
    if not re.search(r"\bkin\b.*\d+\.\d+\.\d+", said):
        res.bad("the block ran but never printed a kin version: %s" % said[:250])
        return res
    res.ok("the README's leading block reached a working kin --version with the "
           "global prefix refused (download stubbed by KIN_NO_PROVISION)")
    return res


def check_2(suite):
    """FIR-2629: a language-server install that dies on the network says so.

    Driven through `kin setup --install-language-servers`, not through the
    `kin doctor --fix --install-language-servers` the ticket names, and every
    CHECK line this returns says so. Doctor only reaches the installer when its
    `reference_edge_coverage` row is Pending or Stale, which needs a Kin
    repository, a daemon and an observed gap; outside one the row is
    Unsupported and no install is attempted, so a doctor probe here would grade
    silence. Both surfaces call one `apply_language_server_provisioning`, whose
    remediation is pinned separately by the unit tests in
    `crates/kin-cli/src/commands/language_servers.rs`. What this check owns is
    that a real installer, refused by a real closed port, reaches that
    remediation and prints it.
    """
    res = Result(
        "2", "FIR-2629",
        "a black-holed network gets the named diagnosis and the degraded mode, "
        "through kin setup --install-language-servers")
    npm = shutil.which("npm")
    if not npm:
        res.unknown("npm is not on PATH, so no install can be attempted or fail")
        return res

    work = suite.scratch("proxy")
    home = os.path.join(work, "home")
    prefix = os.path.join(work, "prefix")
    os.makedirs(home)
    os.makedirs(os.path.join(prefix, "lib"))

    # A PATH with the installers on it and no language server, so the recipes
    # read as missing and the installer reads as available. Built rather than
    # inherited, because a runner that happens to carry pyright would take the
    # AlreadyPresent branch and this check would grade nothing.
    binpath = suite.sanitized_path(work)

    env = suite.base_env()
    env["HOME"] = home
    env["PATH"] = binpath
    env["KIN_HOME"] = os.path.join(home, ".kin")
    # A real npm against a port nothing listens on: the error text is npm's own,
    # not this script's. A stubbed npm printing the words the classifier looks
    # for would be a check that cannot fail.
    env["npm_config_registry"] = "http://127.0.0.1:9/"
    env["npm_config_prefix"] = prefix
    # Retries only, never a timeout knob: npm refuses a maxtimeout below its own
    # default mintimeout, and that refusal is not a network failure, so a probe
    # that set one would grade a config error as the defect under test.
    env["npm_config_fetch_retries"] = "0"
    env["npm_config_audit"] = "false"
    env["npm_config_fund"] = "false"

    rc, out, err = run(
        [suite.kin, "setup", "--no-interactive", "--skip-mcp-check",
         "--install-language-servers"],
        cwd=work, env=env, timeout=1800,
    )
    ok, detail = grade_network_diagnosis(out + "\n" + err)
    # Every verdict names the surface it was taken on, because the ticket is
    # written about `kin doctor` and this is not that command.
    detail = "%s [surface: kin setup --install-language-servers]" % detail
    if ok is None:
        res.unknown(detail)
    elif ok:
        res.ok(detail)
    else:
        res.bad(detail)
    return res


def doctor_report(suite, extra_env=None):
    """(report, detail) from one `kin doctor --json` run outside a repository.

    Outside, deliberately. The row FIR-2787 grades is the one that has to answer
    before `kin init` runs, and every other memory row on that page reads n/a
    there, so a run inside a repository would grade a different question
    entirely. FIR-2919 grades the same page's roll-up, and outside a repository
    is where that page carries the most `unsupported` rows, which is exactly the
    shape its join has to get right.
    """
    env = suite.base_env()
    if extra_env:
        env.update(extra_env)
    work = os.path.join(suite.workdir, "no-repository")
    if not os.path.isdir(work):
        os.makedirs(work)
    rc, out, err = run([suite.kin, "doctor", "--json"], cwd=work, env=env, timeout=600)
    if not out.strip():
        return None, "`kin doctor --json` exited %d and printed nothing: %s" % (
            rc, flatten(err)[:200])
    try:
        return json.loads(strip_ansi(out)), ""
    except ValueError as exc:
        return None, "`kin doctor --json` did not print JSON: %s" % exc


def doctor_rows(suite, extra_env=None):
    """(rows_by_id, detail) from one `kin doctor --json` run outside a repository."""
    report, detail = doctor_report(suite, extra_env)
    if report is None:
        return None, detail
    return {row.get("id"): row for row in report.get("checks", [])}, ""



# ---------------------------------------------------------------- the roll-up
#
# FIR-2919. `kin doctor --json` emitted per-check rows that were honest and a
# top-level `"healthy": true` that was not. On a fresh Windows install the page
# carried 19 `unsupported` rows, `embedding_model` `pending` and `memory_floor`
# `degraded`, printed "2 checks need attention" as its own last line, and told a
# machine reader the install was ready. The release's install proof threw on the
# contradiction and fenced v0.6.1.
#
# The rule, in one place here as it is in one place in the product: a check is
# out of scope only when the platform or the context puts it out of scope, which
# is exactly `unsupported`. Every other status is a component not answering at
# full strength. `ready` requires that none of them exists; `failing` is
# reserved for a broken install so that `healthy: false` cannot mean two things.

HEALTH_VERDICTS = ("ready", "needs_attention", "failing")
HEALTH_STATUSES = ("healthy", "missing", "stale", "misconfigured", "pending",
                   "degraded", "unsupported")
READINESS_ID = "semantic_query_readiness"


def health_needs_attention(row):
    return row.get("status") not in ("healthy", "unsupported")


def health_blocks_readiness(row):
    return (row.get("status") in ("missing", "misconfigured")
            or (row.get("id") == READINESS_ID and row.get("status") == "stale"))


def health_join(rows):
    """The verdict a report's own rows support."""
    if any(health_blocks_readiness(row) for row in rows):
        return "failing"
    return "needs_attention" if any(health_needs_attention(row) for row in rows) else "ready"


def grade_health_rollup(report):
    """(ok, detail) for whether a health report's roll-up matches its own rows.

    Reads the report the product emitted rather than composing an expected one,
    so the grader cannot pass by agreeing with itself. Returns None where the
    payload cannot answer the question at all, which includes a report carrying
    no `verdict`: that is what pre-FIR-2919 bytes emit, and grading their
    aggregate against either rule would be a claim those bytes cannot carry.
    """
    if not isinstance(report, dict):
        return None, "the doctor payload is not an object"
    rows = report.get("checks")
    if not isinstance(rows, list) or not rows:
        return None, "the doctor payload carries no checks array"
    unknown = sorted({row.get("status") for row in rows} - set(HEALTH_STATUSES))
    if unknown:
        return None, ("the report carries statuses this grader does not know (%s), so the "
                      "join it computes would be a guess" % ", ".join(map(str, unknown)))
    if "healthy" not in report:
        return None, "the report carries no top-level `healthy` field"
    if report.get("verdict") not in HEALTH_VERDICTS:
        return None, ("the report carries no readable `verdict` (%r), so these bytes predate "
                      "FIR-2919 and their roll-up cannot be graded"
                      % report.get("verdict"))

    waiting = [row for row in rows if health_needs_attention(row)]
    named = ", ".join("%s=%s" % (row.get("id"), row.get("status")) for row in waiting) or "none"
    expected = health_join(rows)
    if report["verdict"] != expected:
        return False, ("the page reports verdict %s while its own rows support %s; rows "
                       "needing attention: %s"
                       % (report["verdict"], expected, named))
    if report["healthy"] is not (expected == "ready"):
        return False, ("the page reports healthy=%s while its own rows support %s; rows "
                       "needing attention: %s"
                       % (report["healthy"], expected, named))
    return True, ("the roll-up is %s over %d rows, %d of which need attention: %s"
                  % (expected, len(rows), len(waiting), named))



# The row set a fresh Windows install emitted on the v0.6.1 release run, lifted
# from that run's own `install-proof-windows-latest-33235776577` artifact
# (`kin-windows-health.json`) rather than composed here. 33 rows: 12 healthy, 19
# unsupported, `embedding_model` pending and `memory_floor` degraded. The
# shipped payload carried `"healthy": true` beside them and no `verdict` field
# at all.
#
# No host that runs this suite can produce that row set, and it does not need
# to: the rule is platform-independent and the rows are the platform's whole
# contribution, so replaying the rows replays the case.
WINDOWS_V061_ROWS = [
    {"id": "kin_binary", "status": "healthy"},
    {"id": "kin_daemon_binary", "status": "healthy"},
    {"id": "supervisor_startup_protocol", "status": "healthy"},
    {"id": "daemon_running", "status": "unsupported"},
    {"id": "daemon_idle_window", "status": "unsupported"},
    {"id": "vfs_projection", "status": "unsupported"},
    {"id": "projection_mode", "status": "unsupported"},
    {"id": "repo_init", "status": "unsupported"},
    {"id": "session_runtime", "status": "unsupported"},
    {"id": "shell_path", "status": "healthy"},
    {"id": "registry_authority", "status": "unsupported"},
    {"id": "mcp_client_claude", "status": "healthy"},
    {"id": "mcp_client_cursor", "status": "healthy"},
    {"id": "mcp_client_gemini", "status": "healthy"},
    {"id": "mcp_client_windsurf", "status": "healthy"},
    {"id": "setup_ledger", "status": "healthy"},
    {"id": "editor", "status": "unsupported"},
    {"id": "kinlab_connect", "status": "unsupported"},
    {"id": "semantic_query_readiness", "status": "unsupported"},
    {"id": "reference_edge_coverage", "status": "unsupported"},
    {"id": "relation_census", "status": "unsupported"},
    {"id": "parse_coverage", "status": "unsupported"},
    {"id": "background_work", "status": "unsupported"},
    {"id": "embedding_model", "status": "pending"},
    {"id": "memory_floor", "status": "degraded"},
    {"id": "commit_memory_headroom", "status": "unsupported"},
    {"id": "daemon_kill_record", "status": "unsupported"},
    {"id": "interrupted_init", "status": "healthy"},
    {"id": "suspended_sweep", "status": "unsupported"},
    {"id": "host_memory_pressure", "status": "unsupported"},
    {"id": "retrieval_profile", "status": "healthy"},
    {"id": "update_policy", "status": "healthy"},
    {"id": "binary_assessment_load", "status": "unsupported"},
]


# --------------------------------------------------------- toolchain-free repair
#
# The 2026-08-28 walkthrough's finding 2. A stranger followed the documented
# install, initialized a Rust repository, and got imports 0/1085 with "no
# language server found". The product named its own repair and the repair
# refused because `rustup` was absent. Nothing in that chain lied; the outcome
# was that a developer who is not a Rust developer could not get reference edges
# for a Rust repository by following the product's own instructions.
#
# What this grades is one question: did the repair need a toolchain this host
# does not have. It does NOT grade whether the installed server works, because
# the fixture served here is a stub and a stub cannot complete an LSP handshake.
# A run that gets as far as "installed and did not start" has answered this
# check's question and is a PASS, which is why the two are told apart below
# rather than collapsed into "did the row go green".
#
# The two failing branches carry DIFFERENT sentences on purpose, and the
# self-test asserts which one answered. They overlap on the text 0.6.0 actually
# shipped, which carried both the refusal and the remedy, and two branches that
# can each catch one input hide each other's absence: a mutation that merely
# redirects between them leaves the verdict unchanged and reads as a surviving
# check. Each branch therefore also gets an input only it can catch.

TOOLCHAIN_REFUSAL = "is not installed on this host"
TOOLCHAIN_REMEDY = "install 'rustup'"
PRESCRIBES_TOOLCHAIN = "prescribes a toolchain install"
ENDED_ON_ABSENCE = "ended on rustup being absent"
DOWNLOAD_EVIDENCE = "sha256:"


def grade_toolchain_free_repair(output):
    """(ok, detail) for a language-server repair run on a host with no rustup."""
    flat = flatten(output)
    if not flat:
        return None, "the run produced no output, so nothing could be graded"
    if "rust" not in flat.lower():
        return None, (
            "the run never mentioned the rust language server, so it did not "
            "reach the question this check is about"
        )
    if TOOLCHAIN_REMEDY in flat:
        return False, (
            "the repair %s, telling a reader to install a toolchain in order to "
            "read somebody else's code: %s"
            % (PRESCRIBES_TOOLCHAIN, flat[flat.find(TOOLCHAIN_REMEDY):][:180])
        )
    if "rustup" in flat and TOOLCHAIN_REFUSAL in flat:
        return False, (
            "the repair %s, so a host without the toolchain still gets no route "
            "to a server" % ENDED_ON_ABSENCE
        )
    if DOWNLOAD_EVIDENCE not in flat:
        return None, (
            "no route was taken and no toolchain refusal was reported either, "
            "so this run establishes nothing either way: %s" % flat[:220]
        )
    return True, (
        "the repair took a route that needs no toolchain and disclosed the "
        "digest it verified"
    )


def check_3(suite):
    """FIR-2787: the memory this box affords is on the page before `kin init` runs.

    The stranger converting two mid-sized repositories inside a 12 GiB container
    was told four separate things, on four surfaces, after each had already cost
    them something. `kin doctor` on that box flagged two rows and neither was
    that the daemons would not fit, because every memory row there needs a store
    and no store existed yet.

    What this grades, and what it does not. The row's shape and its presence
    outside a repository are graded here, on whatever host runs the suite. The
    MEMORY band, the one that separates a 12 GiB container from a 32 GiB laptop,
    is not: nothing on this host can move the ceiling `MemoryEvidence` reads, and
    a check that pretended to constrain it would be grading its own stand-in. The
    bands are pinned instead by the unit tests in
    `crates/kin-cli/src/commands/health.rs`, against the container's exact
    readings, and this check exists to prove the wiring those tests cannot see.

    The tier band IS constrained here, because `KIN_LOCATE_PROFILE` is a real
    lever a reader can set, and it moves the row for a reason a reader can act
    on. Its control is the same command with the tier forced the other way: a
    row that warned under both would be wallpaper, which is the failure mode
    this ticket is about in the first place.
    """
    res = Result("3", "FIR-2787",
                 "kin doctor states this machine's memory floor before any repository exists")

    rows, detail = doctor_rows(suite)
    if rows is None:
        res.unknown(detail)
        return res
    row = rows.get("memory_floor")
    if row is None:
        res.bad("`kin doctor` outside a repository carries no memory_floor row; the page still "
                "says nothing about memory until a store exists, which is FIR-2787 itself")
        return res
    res.ok("the row answers outside a repository, where every other memory row reads n/a")

    flat = flatten(row.get("detail", ""))
    for wanted, why in (
            ("of memory here", "the ceiling this process runs under"),
            ("repository daemon is allowed", "what one daemon will hold inside it"),
            ("two of them are allowed", "what a second converted repository comes to"),
            ("multihop", "what the capability tier does to retrieval"),
    ):
        if wanted in flat:
            res.ok("the row states %s" % why)
        else:
            res.bad("the row does not state %s (looked for %r in: %s)" % (why, wanted, flat[:400]))

    # Every non-green row on this page carries the fix it needs, and every green
    # one offers none. That pairing is the doctor's own register, and a row that
    # broke it in either direction would read as a defect in the page rather
    # than in the machine.
    green = row.get("status") == "healthy"
    has_fix = bool(row.get("manual_fix"))
    if green and has_fix:
        res.bad("a green row offers a repair for a machine that needs none: %r"
                % row.get("manual_fix"))
    elif not green and not has_fix:
        res.bad("the row needs attention (%s) and carries no fix: %s"
                % (row.get("status"), flat[:300]))
    else:
        res.ok("the row holds the page's register: %s, fix %s"
               % (row.get("status"), "present" if has_fix else "absent"))

    # The constrained fixture, and its control. `minimal` narrows the multihop
    # budget for real, so the row has to say so and hand back a move; forcing
    # the full tier removes exactly that reason to warn.
    narrowed, detail = doctor_rows(suite, {"KIN_LOCATE_PROFILE": "minimal"})
    if narrowed is None:
        res.unknown("the constrained arm could not be read: %s" % detail)
        return res
    row = narrowed.get("memory_floor") or {}
    fix = flatten(row.get("manual_fix") or "")
    if row.get("status") == "healthy":
        res.bad("a machine pinned to the minimal tier reads green, so the row cannot report a "
                "narrowed retrieval budget at all: %s" % flatten(row.get("detail", ""))[:300])
    elif "multihop" not in fix:
        res.bad("the constrained row's fix does not name the narrowed budget: %r" % fix)
    else:
        res.ok("a tier pinned below the line reads %s and its fix names the multihop budget"
               % row.get("status"))

    full, detail = doctor_rows(suite, {"KIN_LOCATE_PROFILE": "performance"})
    if full is None:
        res.unknown("the control arm could not be read: %s" % detail)
        return res
    row = full.get("memory_floor") or {}
    fix = flatten(row.get("manual_fix") or "")
    if "multihop" in fix:
        res.bad("the row still asks for a bigger machine after the tier reason is gone, so it "
                "warns whatever the host is: %r" % fix)
    elif row.get("status") == "healthy":
        res.ok("with the tier at full budget this host's row is green and silent")
    else:
        # Honest rather than green: this host's own ceiling is under a measured
        # commit total. That is the row working, not failing, and saying so
        # beats grading the suite on which laptop ran it.
        res.ok("the tier reason is gone and this host's remaining reason is its own ceiling: %s"
               % flatten(row.get("detail", ""))[:200])
    return res


def check_4(suite):
    """The language-server repair works on a host with no rustup.

    Driven against a fixture the suite serves itself, so the check needs no
    network and cannot fail on a bad morning at a release host. What the fixture
    replaces is the URL and the digest, both taken as arguments by the install;
    the download, the verification, the unpack, the executable bit and the
    registration are the shipped code on both paths.

    `rustup` is scrubbed from PATH rather than assumed absent, because the
    runner that builds this suite installs a Rust toolchain and a check that
    merely hoped for its absence would silently grade the rustup route instead.
    The scrub is asserted before the repair runs.
    """
    res = Result("4", "cold-walk-2026-08-28",
                 "kin doctor --fix --install-language-servers needs no toolchain the host lacks")

    stub = b"#!/bin/sh\necho 'rust-analyzer 0.0.0-fixture'\n"
    archive = io.BytesIO()
    with gzip.GzipFile(fileobj=archive, mode="wb", mtime=0) as raw:
        raw.write(stub)
    body = archive.getvalue()
    digest = hashlib.sha256(body).hexdigest()

    served = _serve_asset(body)
    if served is None:
        res.unknown("could not bind a loopback port for the fixture asset")
        return res
    base, httpd, thread = served
    try:
        home = suite.scratch("toolchain-free-home")
        env = suite.base_env()
        env["HOME"] = home
        env["KIN_HOME"] = os.path.join(home, ".kin")
        env["KIN_LANGUAGE_SERVER_ASSET_BASE"] = base
        env["KIN_LANGUAGE_SERVER_ASSET_SHA256"] = digest
        # Every PATH entry carrying rustup is dropped, then the drop is checked.
        # A scrub that missed one would grade the route this check exists to
        # avoid, and would do it silently.
        kept = [entry for entry in env.get("PATH", "").split(os.pathsep)
                if entry and not os.path.exists(os.path.join(entry, "rustup"))]
        env["PATH"] = os.pathsep.join(kept)
        still_there = [entry for entry in kept
                       if os.path.exists(os.path.join(entry, "rustup"))]
        if still_there:
            res.unknown("the PATH scrub left rustup reachable at %s" % still_there[0])
            return res

        work = suite.scratch("toolchain-free-repo")
        rc, out, err = run([suite.kin, "init", "."], cwd=work, env=env, timeout=900)
        if rc != 0:
            res.unknown("kin init exited %d in the fixture repository: %s"
                        % (rc, flatten(err)[:220]))
            return res
        rc, out, err = run(
            [suite.kin, "doctor", "--fix", "--install-language-servers"],
            cwd=work, env=env, timeout=900)
        combined = (out or "") + "\n" + (err or "")

        ok, detail = grade_toolchain_free_repair(combined)
        if ok is None:
            res.unknown(detail)
            return res
        if not ok:
            res.bad(detail)
            return res

        installed = os.path.join(env["KIN_HOME"], "tools", "bin", "rust-analyzer")
        if not os.path.exists(installed):
            res.bad("the run disclosed a digest and wrote no binary to %s" % installed)
            return res
        if not os.access(installed, os.X_OK):
            res.bad("the binary at %s is not executable, so `which` walks past it"
                    % installed)
            return res
        on_disk = hashlib.sha256(open(installed, "rb").read()).hexdigest()
        if on_disk != hashlib.sha256(stub).hexdigest():
            res.bad("the installed bytes are not the unpacked asset")
            return res
        res.ok("%s, and the unpacked binary is executable at %s" % (detail, installed))
    finally:
        httpd.shutdown()
        thread.join(timeout=5)
    return res


# --------------------------------------------------- an unbound MCP server
#
# The 2026-08-28 walkthrough's finding 5. The install page hands every client
# the same MCP entry, `{"command":"npx","args":["-y","@kinlab/kin-mcp"]}`, and
# the wrapper behind it refused before `kin mcp start` ever ran when the launch
# directory held no `.kin/`. The page's own ordering guarantees the failure: it
# says to point a client at the server and then run `kin init`, so a first-time
# user restarts their client before any repository exists. Measured on 0.6.0:
# EOF on `initialize` with the process gone in 862 ms.
#
# What this grades is the handshake, on the wrapper the install page names,
# in a directory with no `.kin/`. The binary is supplied explicitly, because the
# wrapper's own provisioning path downloads a release asset and a check that
# needed the network would fail on a bad morning rather than on a defect.

MCP_SERVED = "SERVED"
MCP_EOF = "EOF_NO_RESPONSE"
MCP_TIMEOUT = "TIMEOUT_NO_RESPONSE"
MCP_PROBE_ID = 4242

# Two sentences the notice owes a reader who is about to be served nothing.
UNBOUND_NOTICE = "no repository is bound yet"
UNBOUND_REPAIR = "kin init ."


def mcp_initialize(command, cwd, env, timeout=180):
    """Hand one `initialize` frame to a stdio MCP server and read the answer.

    (verdict, stdout_lines, stderr_text, alive_after_answer). The verdict is
    matched on this request's own JSON-RPC id rather than on something coming
    back, because a server that writes a banner and dies would otherwise read as
    one that answered. `alive` is read at the moment the answer arrives: the
    defect is a wrapper that exits, and a served response from a process that
    then died is not a server a client can use.
    """
    request = json.dumps({
        "jsonrpc": "2.0",
        "id": MCP_PROBE_ID,
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "first-contact-honesty", "version": "1"}},
    })
    try:
        proc = subprocess.Popen(
            command, cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, bufsize=1)
    except OSError as exc:
        return "SPAWN_FAILED", [], "could not execute %s: %s" % (command[0], exc), False

    lines = []
    errors = []
    answered = []

    def drain_stderr():
        for chunk in proc.stderr:
            errors.append(chunk)

    def read_stdout():
        for line in proc.stdout:
            lines.append(line)
            try:
                message = json.loads(line.strip())
            except ValueError:
                continue
            if message.get("id") == MCP_PROBE_ID:
                answered.append(message)
                return

    err_thread = threading.Thread(target=drain_stderr)
    err_thread.daemon = True
    err_thread.start()
    out_thread = threading.Thread(target=read_stdout)
    out_thread.daemon = True
    out_thread.start()

    try:
        proc.stdin.write(request + "\n")
        proc.stdin.flush()
    except (IOError, OSError, ValueError):
        # A process that has already gone takes the write with it. That is a
        # reading, not an error: the verdict below reports EOF.
        pass

    out_thread.join(timeout)
    alive = proc.poll() is None
    if answered:
        verdict = MCP_SERVED
    elif out_thread.is_alive():
        verdict = MCP_TIMEOUT
    else:
        verdict = MCP_EOF

    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001 - a stuck child must not fail the suite
        pass
    err_thread.join(timeout=5)
    return verdict, lines, "".join(errors), alive


def grade_unbound_start(verdict, alive, stderr_text, stdout_lines, kin_created):
    """(ok, detail) for a wrapper started where no repository exists."""
    if verdict == MCP_TIMEOUT:
        return None, ("the server neither answered `initialize` nor exited inside the "
                      "budget, so this run says nothing about either behaviour")
    if verdict.startswith("SPAWN_FAILED"):
        return None, "the wrapper could not be started at all: %s" % flatten(stderr_text)[:200]
    if verdict == MCP_EOF:
        return False, (
            "`initialize` got EOF with no response in a directory holding no `.kin/`, which "
            "is the advertised MCP entry dying before a first-time user has a repository: %s"
            % flatten(stderr_text)[:220])
    if not alive:
        return False, ("`initialize` was answered and the process was gone immediately after, "
                       "so a client gets one frame and a dead server")
    if kin_created:
        return False, ("starting unbound initialized a repository behind the user; "
                       "KIN_MCP_AUTO_INIT is what asks for that")
    body = [line for line in stdout_lines if line.strip()]
    if not body:
        return None, "the server answered but wrote nothing this probe could read back"
    try:
        json.loads(body[0].strip())
    except ValueError:
        return False, ("the first thing on stdout is not a JSON-RPC frame, so prose is being "
                       "written to the protocol channel: %r" % body[0][:120])
    flat = flatten(stderr_text)
    if UNBOUND_NOTICE not in flat:
        return False, ("the server started and never said that no repository is bound, so the "
                       "user is served an empty graph with no explanation: %s" % flat[:220])
    if UNBOUND_REPAIR not in flat:
        return False, ("the notice states the gap and not the repair, so a reader is told "
                       "something is wrong and not what to run: %s" % flat[:220])
    return True, ("`initialize` was served, the process stayed up, no repository was created "
                  "behind the user, and the notice named the gap and the repair on stderr")


def check_5(suite):
    """The advertised MCP entry serves `initialize` outside a repository.

    Probed through `packages/kin-mcp/bin/kin-mcp.js`, which is what
    `npx -y @kinlab/kin-mcp` runs, rather than through `kin mcp start`: the
    finding is about the wrapper, and the binary underneath it already served
    this case. A probe pointed at the convenient surface would have reported the
    product healthy.

    The prober is proven able to say both words before either reading is
    believed. A node process that exits without answering must read EOF, and a
    four-line stub that answers any frame must read SERVED; without that pair, a
    prober stuck on one verdict grades every wrapper as whatever it is stuck on.
    """
    res = Result("5", "cold-walk-2026-08-28",
                 "the npx MCP wrapper serves initialize in a directory with no .kin/")

    node = shutil.which("node")
    if node is None:
        res.unknown("no node on PATH, so the npm wrapper cannot be started here")
        return res
    wrapper = os.path.join(suite.repo_root, "packages", "kin-mcp", "bin", "kin-mcp.js")
    if not os.path.exists(wrapper):
        res.unknown("no wrapper at %s" % wrapper)
        return res

    work = suite.scratch("unbound-mcp")
    home = suite.scratch("unbound-mcp-home")
    env = suite.base_env()
    env["HOME"] = home
    env["KIN_HOME"] = os.path.join(home, ".kin")
    # The wrapper's own provisioning downloads a release asset for its package
    # version. Held fixed rather than measured, because this check is about the
    # refusal in front of the server and not about how the binary arrives.
    env["KIN_MCP_KIN_BINARY"] = suite.kin
    env.pop("KIN_MCP_AUTO_INIT", None)

    verdict, _, _, _ = mcp_initialize([node, "-e", "process.exit(2)"], work, env, timeout=60)
    if verdict != MCP_EOF:
        res.unknown("the negative control (a node process that answers nothing) read %s, so "
                    "this prober cannot report a server that never answered" % verdict)
        return res
    answering_stub = (
        'let buf="";process.stdin.on("data",d=>{buf+=d;const parts=buf.split("\\n");'
        'buf=parts.pop();for(const line of parts){if(!line.trim())continue;'
        'const m=JSON.parse(line);'
        'process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:m.id,result:{}})+"\\n");}});'
        'setTimeout(()=>{},60000);'
    )
    verdict, _, _, alive = mcp_initialize([node, "-e", answering_stub], work, env, timeout=60)
    if verdict != MCP_SERVED or not alive:
        res.unknown("the positive control (a stub that answers every frame) read %s alive=%s, "
                    "so this prober cannot report a server that did answer" % (verdict, alive))
        return res
    res.ok("the prober tells a served handshake from a process that exits, proven both ways "
           "before the product was read")

    verdict, out_lines, err, alive = mcp_initialize([node, wrapper], work, env, timeout=300)
    kin_created = os.path.exists(os.path.join(work, ".kin"))
    ok, detail = grade_unbound_start(verdict, alive, err, out_lines, kin_created)
    if ok is None:
        res.unknown(detail)
        return res
    if not ok:
        res.bad(detail)
        return res
    res.ok(detail)
    return res


# ------------------------------------------- a sweep that skipped a language
#
# The 2026-08-28 walkthrough's finding 6. `kin init` on `tokio-rs/axum`, on a
# macOS host that DID carry rustup and rust-analyzer, printed `cross-file
# enrichment complete (5/303 files)`, and the same store's next `kin graph
# status` read `imports 0/1085 (0%)` and `cross-file reference and override
# edges unavailable for rust: no language server found`. The five files were
# JavaScript. One store cannot say both things.
#
# Arranging it needs one language served while another is not, and the adapters'
# server commands are constants in kin-lsp. PATH is the lever anyway:
# `kin_lsp::lifecycle::LspServer::start` spawns them with `Command::new(command)`
# on the bare name. So this scrubs `rust-analyzer` off PATH the way check 4
# scrubs `rustup`, and puts a stub server on it under the TypeScript adapter's
# name. The stub is what makes the check hermetic: no host is asked to have a
# real language server, and the served language is served by bytes this file
# writes.
#
# The control is the same fixture with the same stub reachable under BOTH names.
# One PATH entry apart, one sweep must refuse the word `complete` and one must
# use it. Without that pair a check that always reports a skipped language would
# pass on a product that always reported one.

# Rust files in the fixture below, which is the count the skipped-language row
# has to report back. Named once so the fixture and the assertion cannot drift.
RUST_FIXTURE_FILES = 3

STUB_LSP_SERVER = r'''#!/usr/bin/env python3
"""A stdio LSP server that completes the handshake and answers nothing else.

Enough of the protocol for a sweep to count a file as visited. It declares the
capabilities the daemon's readiness probe keys on and answers `workspace/symbol`
at once, so readiness returns on the first poll instead of sleeping out its
budget, and it answers every other request with a null result, so no query waits
for a timeout. It resolves no reference and produces no edge: what it stands in
for is a server that STARTS, which is the whole difference this check measures.
"""
import json
import sys


def read_message(stream):
    length = None
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    if length is None:
        return None
    return json.loads(stream.read(length).decode("utf-8"))


def write_message(stream, payload):
    body = json.dumps(payload).encode("utf-8")
    stream.write(b"Content-Length: %d\r\n\r\n" % len(body))
    stream.write(body)
    stream.flush()


def main():
    if "--version" in sys.argv[1:]:
        sys.stdout.write("kin-acceptance-stub 0.0.0\n")
        return 0
    while True:
        message = read_message(sys.stdin.buffer)
        if message is None:
            return 0
        if "id" not in message:
            if message.get("method") == "exit":
                return 0
            continue
        if message.get("method") == "initialize":
            result = {"capabilities": {
                "referencesProvider": True,
                "definitionProvider": True,
                "typeDefinitionProvider": True,
                "workspaceSymbolProvider": True,
                "callHierarchyProvider": True,
                "typeHierarchyProvider": True,
            }}
        else:
            result = None
        write_message(sys.stdout.buffer,
                      {"jsonrpc": "2.0", "id": message["id"], "result": result})


if __name__ == "__main__":
    sys.exit(main())
'''

# Both surfaces this check grades, in both their wordings. `kin init` and
# `kin daemon sweep` share one function now, but they did not: the sweep printed
# `sweep complete (3/6 files)` and nothing else. Keying the precondition on the
# post-fix phrasing alone would grade the pre-fix sweep as a run that never
# reached the phase, which reports UNREADABLE over a live completion claim.
OUTCOME_MARKERS = ("cross-file enrichment", "sweep complete", "sweep finished")
COMPLETION_CLAIMS = ("cross-file enrichment complete", "sweep complete")
SKIP_ROW = re.compile(r"rust: (\d+) files? not enriched, because")


def _outcome_reported(flat):
    """The offset of the sweep's own outcome line, or None if it never printed one."""
    found = [flat.find(marker) for marker in OUTCOME_MARKERS if marker in flat]
    return min(found) if found else None


def grade_skipped_language_outcome(output, expected_files=None):
    """(ok, detail) for a sweep that served one language and not the other.

    `expected_files` is the fixture's own count of files in the skipped
    language. The daemon tallies one per blocked file, and a tally that stopped
    after the first would report `1 file` for a language that lost hundreds:
    that number reaches a user in a sentence, and nothing else in this suite or
    in the unit tests reads it off a real sweep.
    """
    flat = flatten(output)
    if not flat:
        return None, "the run produced no output, so nothing could be graded"
    at = _outcome_reported(flat)
    if at is None:
        return None, ("the run never reported a sweep outcome at all, so its silence about a "
                      "skipped language is not evidence: %s" % flat[-220:])
    claimed = [claim for claim in COMPLETION_CLAIMS if claim in flat]
    if claimed:
        return False, ("the pass reported a completion while a language went unserved, which "
                       "is the sentence the walkthrough caught: %s"
                       % flat[flat.find(claimed[0]):][:200])
    row = SKIP_ROW.search(flat)
    if row is None:
        return False, ("the outcome never names the language it could not serve and how many "
                       "files that cost, so a reader is told a count and nothing else: %s"
                       % flat[at:][:260])
    if "rust-analyzer" not in flat:
        return False, ("the outcome names the language but not what the daemon observed when "
                       "it tried, so the reason is left to be guessed: %s" % flat[at:][:260])
    if expected_files is not None and int(row.group(1)) != expected_files:
        return False, ("the outcome's count for the language is %s where this fixture holds %d "
                       "files, so the count a user reads is not the count that was blocked: %s"
                       % (row.group(1), expected_files, flat[at:][:260]))
    return True, ("the pass refused the word complete and named the language, its %s files and "
                  "the reason the daemon observed" % row.group(1))


def grade_served_sweep_outcome(output):
    """(ok, detail) for the control: every language met was served."""
    flat = flatten(output)
    if not flat:
        return None, "the control run produced no output"
    at = _outcome_reported(flat)
    if at is None:
        return None, ("the control never reported a sweep outcome at all, so it constrains "
                      "nothing: %s" % flat[-220:])
    if SKIP_ROW.search(flat):
        return False, ("the control names a skipped language on a run where every server "
                       "started, so the outcome reports a skip whatever happened: %s"
                       % flat[at:][:260])
    if not any(claim in flat for claim in COMPLETION_CLAIMS):
        return False, ("a sweep that served every language it met still did not report a "
                       "completion, so the ban on the word is satisfied by never saying "
                       "anything: %s" % flat[at:][:260])
    return True, "with both servers reachable the same fixture reports a completion"


def _fixture_repository(suite, name):
    """A git repository of three Rust and three TypeScript files, or None.

    Both languages produce entities, so both reach the sweep's per-file loop.
    Nothing else is added: a file whose extension no server here serves is
    blocked for a different reason, and this check is about the language that
    had one and could not use it.
    """
    git = shutil.which("git")
    if git is None:
        return None, "no git on PATH, so no repository can be admitted"
    work = suite.scratch(name)
    hooks = suite.scratch(name + "-nohooks")
    os.makedirs(os.path.join(work, "src"))
    os.makedirs(os.path.join(work, "web"))
    for letter in ("a", "b", "c"):
        with open(os.path.join(work, "src", "%s.rs" % letter), "w") as handle:
            handle.write("pub fn %s_one() -> u32 { 1 }\n"
                         "pub fn %s_two() -> u32 { %s_one() + 1 }\n"
                         % (letter, letter, letter))
    for letter in ("x", "y", "z"):
        with open(os.path.join(work, "web", "%s.ts" % letter), "w") as handle:
            handle.write("export function %sOne(): number { return 1; }\n"
                         "export function %sTwo(): number { return %sOne() + 1; }\n"
                         % (letter, letter, letter))
    # The operator's own hooks are pointed away from, so a fixture commit cannot
    # be refused by a policy that has nothing to do with this check.
    common = [git, "-c", "core.hooksPath=%s" % hooks,
              "-c", "user.email=acceptance@kin.invalid", "-c", "user.name=kin acceptance",
              "-c", "commit.gpgsign=false"]
    for args in (["init", "-q", "."], ["add", "-A"], ["commit", "-q", "-m", "fixture"]):
        rc, _, err = run(common + args, cwd=work, timeout=300)
        if rc != 0:
            return None, "could not build the fixture repository (%s): %s" % (args[0],
                                                                             flatten(err)[:200])
    return work, "three Rust and three TypeScript files under one commit"


def _stub_server_path(suite, name, names):
    """A bin directory carrying the stub LSP server under each of `names`."""
    binpath = suite.scratch(name)
    source = os.path.join(binpath, "stub-language-server.py")
    with open(source, "w") as handle:
        handle.write(STUB_LSP_SERVER)
    os.chmod(source, os.stat(source).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    for served in names:
        os.symlink(source, os.path.join(binpath, served))
    return binpath


def _path_without_rust_analyzer(env):
    """(PATH, complaint). Every entry that could resolve rust-analyzer is dropped.

    `rustup` is dropped with it, because a rustup shim resolves `rust-analyzer`
    through a proxy this scrub would otherwise walk straight past. The drop is
    asserted rather than hoped for: the runner that builds this suite installs a
    Rust toolchain, and a check that merely hoped for its absence would grade a
    run where the real server started.
    """
    kept = [entry for entry in env.get("PATH", "").split(os.pathsep)
            if entry
            and not os.path.exists(os.path.join(entry, "rust-analyzer"))
            and not os.path.exists(os.path.join(entry, "rustup"))]
    path = os.pathsep.join(kept)
    if shutil.which("rust-analyzer", path=path) is not None:
        return None, ("the scrub left rust-analyzer reachable at %s"
                      % shutil.which("rust-analyzer", path=path))
    return path, ""


def check_6(suite):
    """A sweep that could not serve a language never calls the pass complete.

    Two `kin init` runs on the same fixture, one PATH entry apart. In the first,
    a stub language server is reachable under the TypeScript adapter's name and
    `rust-analyzer` is not reachable at all, so three files are enriched and
    three are not: the walkthrough's exact shape. In the second the same stub is
    reachable under both names, so nothing is skipped and the completion line is
    required. A ban on one word is satisfied by saying nothing, which is what the
    second run is for.

    `kin daemon sweep` is graded on the same store afterwards, because it is the
    command the pending line tells a reader to run next and it printed
    `sweep complete (3/6 files)` off the same status object that named rust.
    """
    res = Result("6", "cold-walk-2026-08-28",
                 "a sweep that could not serve a language names it instead of reporting complete")

    if shutil.which("python3") is None:
        res.unknown("no python3 on PATH to run the stub language server")
        return res

    env = suite.base_env()
    path, complaint = _path_without_rust_analyzer(env)
    if path is None:
        res.unknown(complaint)
        return res
    res.ok("rust-analyzer is unreachable on the scrubbed PATH, asserted rather than assumed")

    work, detail = _fixture_repository(suite, "skipped-language-repo")
    if work is None:
        res.unknown(detail)
        return res

    home = suite.scratch("skipped-language-home")
    served_only = _stub_server_path(suite, "skipped-language-bin",
                                    ["typescript-language-server"])
    skipped_env = dict(env)
    skipped_env["HOME"] = home
    skipped_env["KIN_HOME"] = os.path.join(home, ".kin")
    skipped_env["PATH"] = os.pathsep.join([served_only, path])

    rc, out, err = run([suite.kin, "init", "."], cwd=work, env=skipped_env, timeout=1800)
    combined = (out or "") + "\n" + (err or "")
    if rc != 0:
        res.unknown("kin init exited %d on the fixture: %s" % (rc, flatten(err)[-260:]))
        return res
    ok, detail = grade_skipped_language_outcome(combined, RUST_FIXTURE_FILES)
    if ok is None:
        res.unknown(detail)
        return res
    if not ok:
        res.bad("`kin init`: %s" % detail)
        return res
    res.ok("`kin init`: %s" % detail)

    # The sibling command, on the store that run just built. It holds the whole
    # status object and used to read two numbers out of it.
    rc, out, err = run([suite.kin, "daemon", "sweep"], cwd=work, env=skipped_env, timeout=1800)
    sweep_output = (out or "") + "\n" + (err or "")
    if rc != 0:
        res.unknown("kin daemon sweep exited %d: %s" % (rc, flatten(err)[-260:]))
        return res
    ok, detail = grade_skipped_language_outcome(sweep_output, RUST_FIXTURE_FILES)
    if ok is None:
        res.unknown("`kin daemon sweep`: %s" % detail)
        return res
    if not ok:
        res.bad("`kin daemon sweep`: %s" % detail)
        return res
    res.ok("`kin daemon sweep`: %s" % detail)

    control, detail = _fixture_repository(suite, "served-language-repo")
    if control is None:
        res.unknown("the control fixture could not be built: %s" % detail)
        return res
    control_home = suite.scratch("served-language-home")
    both = _stub_server_path(suite, "served-language-bin",
                             ["typescript-language-server", "rust-analyzer"])
    control_env = dict(env)
    control_env["HOME"] = control_home
    control_env["KIN_HOME"] = os.path.join(control_home, ".kin")
    control_env["PATH"] = os.pathsep.join([both, path])

    rc, out, err = run([suite.kin, "init", "."], cwd=control, env=control_env, timeout=1800)
    control_output = (out or "") + "\n" + (err or "")
    if rc != 0:
        res.unknown("the control kin init exited %d: %s" % (rc, flatten(err)[-260:]))
        return res
    ok, detail = grade_served_sweep_outcome(control_output)
    if ok is None:
        res.unknown(detail)
        return res
    if not ok:
        res.bad(detail)
        return res
    res.ok(detail)
    return res


def _serve_asset(body):
    """A loopback HTTP server answering any path with `body`.

    Returns (base_url, httpd, thread), or None when no port could be bound.
    """
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    try:
        httpd = HTTPServer(("127.0.0.1", 0), Handler)
    except OSError:
        return None
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()
    return "http://127.0.0.1:%d" % httpd.server_address[1], httpd, thread


def check_7(suite):
    """`kin doctor --json` does not claim more than its own rows support.

    Graded outside a repository, where the page carries the most `unsupported`
    rows and where the join therefore has the most chances to get it wrong in
    both directions: counting an out-of-scope row as a shortfall would refuse
    every correct install, and not counting a `pending` or `degraded` row is the
    overclaim that fenced v0.6.1.

    Whatever this host's own rows happen to be is not the subject. The subject
    is agreement, between the roll-up and the rows and between the machine
    report and the human page, so the check answers the same way on a warming
    laptop and on a settled one. The `--self-test` arms carry the shipped
    Windows row set, which no host here can reproduce.
    """
    res = Result("7", "FIR-2919",
                 "kin doctor's roll-up agrees with the rows it summarizes")

    report, detail = doctor_report(suite)
    if report is None:
        res.unknown(detail)
        return res

    ok, detail = grade_health_rollup(report)
    if ok is None:
        res.unknown(detail)
        return res
    if not ok:
        res.bad(detail)
        return res
    res.ok(detail)

    # The same run's human page. The two renderings are one report, and the
    # defect was that they disagreed: the printed line counted the pending and
    # degraded rows while the JSON beside it did not. Graded on the closing
    # line, which is the sentence a reader trusts.
    env = suite.base_env()
    work = os.path.join(suite.workdir, "no-repository")
    if not os.path.isdir(work):
        os.makedirs(work)
    rc, out, err = run([suite.kin, "doctor"], cwd=work, env=env, timeout=600)
    page = flatten(strip_ansi(out or ""))
    if not page:
        res.unknown("`kin doctor` exited %d and printed no page: %s" % (rc, flatten(err)[:200]))
        return res
    claims_ready = "First-run ready" in page
    if claims_ready != bool(report.get("healthy")):
        res.bad("the printed page and the JSON disagree: the page %s claim first-run ready "
                "while `healthy` is %s. Page tail: %s"
                % ("does" if claims_ready else "does not", report.get("healthy"), page[-300:]))
        return res
    res.ok("the printed page and the JSON agree: first-run ready %s, healthy=%s"
           % ("claimed" if claims_ready else "withheld", report.get("healthy")))
    return res


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2), ("3", check_3),
          ("4", check_4), ("5", check_5), ("6", check_6), ("7", check_7)]


# ----------------------------------------------------------------------- suite


class Suite(object):
    def __init__(self, kin, daemon, workdir, repo_root, verbose=False):
        self.kin = kin
        self.daemon = daemon
        self.workdir = workdir
        self.repo_root = repo_root
        self.verbose = verbose

    def scratch(self, name):
        path = os.path.join(self.workdir, name)
        if os.path.exists(path):
            shutil.rmtree(path)
        os.makedirs(path)
        return path

    def base_env(self):
        env = dict(os.environ)
        # The same posture the other suites hold: no inference, no projection,
        # and nothing that could reach an operator's real store.
        env["KIN_DAEMON_AUTO_EMBED"] = "0"
        env["KIN_EMBED_BACKEND"] = "cpu"
        env["KIN_VFS_DISABLE"] = "1"
        env["NO_COLOR"] = "1"
        return env

    # Every tool a README install block or a language-server install can need,
    # and nothing else. `kin` is deliberately absent: this host has
    # ~/.kin/bin on PATH, and a probe that inherited it would resolve the
    # OPERATOR'S installed kin instead of the one the block was supposed to
    # produce. That is not hypothetical. It made check 1 pass a mutant whose
    # install block never put anything on PATH at all.
    TOOLS = ("npm", "npx", "node", "sh", "bash", "env", "uname", "dirname",
             "basename", "mkdir", "rm", "cp", "ln", "chmod", "tar", "sed",
             "grep", "cat", "ls", "git", "which")

    def sanitized_path(self, work):
        """A bin directory carrying the tools and no kin of any kind."""
        binpath = os.path.join(work, "probe-bin")
        if not os.path.isdir(binpath):
            os.makedirs(binpath)
        for tool in self.TOOLS:
            found = shutil.which(tool)
            if not found:
                continue
            link = os.path.join(binpath, tool)
            if not os.path.exists(link):
                os.symlink(found, link)
        return binpath

    def npm_env(self, home):
        env = self.base_env()
        env["HOME"] = home
        env["KIN_HOME"] = os.path.join(home, ".kin")
        env["npm_config_audit"] = "false"
        env["npm_config_fund"] = "false"
        env["npm_config_update_notifier"] = "false"
        # npm's own prefix resolution must come from the home this probe wrote,
        # never from the operator's environment.
        env.pop("npm_config_prefix", None)
        env.pop("NPM_CONFIG_PREFIX", None)
        env.pop("PREFIX", None)
        return env


# ------------------------------------------------------------------- self test


def self_test():
    """Every grader against the defect it is about and against its inverse."""
    failures = []

    def expect(label, got, want):
        if got != want:
            failures.append("%s: got %r, wanted %r" % (label, got, want))

    shipped_help = (
        "Create an exact semantic and artifact commit\n\n"
        "Options:\n  -m, --message <MESSAGE>\n          Commit message\n"
    )
    fixed_help = (
        "Create an exact semantic and artifact commit.\n\n"
        "The commit lands in Kin's own authority, not in Git. Nothing is written\n"
        "to `.git`, so `git status` still lists every file this commit recorded.\n"
        "Hand it back with `kin eject`.\n\n" + AUTHORITY_LINE + "\n\n"
        "Options:\n  -m, --message <MESSAGE>\n          Commit message\n"
    )
    expect("shipped 0.5.49 help must FAIL", grade_commit_help(shipped_help)[0], False)
    expect("the fixed help must PASS", grade_commit_help(fixed_help)[0], True)
    expect("empty help is UNREADABLE", grade_commit_help("")[0], None)
    expect("help without the control line is UNREADABLE",
           grade_commit_help(AUTHORITY_LINE)[0], None)
    # The renderer wraps, and a wrapped sentence is still the sentence.
    wrapped = fixed_help.replace("`git status` stays dirty", "`git status`\nstays dirty")
    expect("a wrapped authority line still PASSes", grade_commit_help(wrapped)[0], True)

    bare = (
        "  x could not install the python language server: `npm install -g pyright` "
        "exited with 1: npm error code ECONNREFUSED\n"
        "      run `npm install -g pyright` yourself to see the installer's own error\n"
    )
    named = (
        "  x could not install the python language server: `npm install -g pyright` "
        "exited with 1: npm error code ECONNREFUSED\n"
        "      this is the network refusing `npm install -g pyright`, not Kin and not "
        "the package: a connection that never completed\n"
        "      export HTTPS_PROXY=http://proxy.example:3128 HTTP_PROXY=http://proxy.example:3128\n"
        "      export NO_PROXY=localhost,127.0.0.1\n"
        + OFFLINE_FIXTURE_LINE
        + "      Kin runs without this server. Parsing, search, history, review and "
        "commits are unaffected.\n"
    )
    expect("the shipped bare failure must FAIL", grade_network_diagnosis(bare)[0], False)
    expect("the named diagnosis must PASS", grade_network_diagnosis(named)[0], True)
    expect("a run that never installed is UNREADABLE",
           grade_network_diagnosis("Summary: 9 passed")[0], None)
    expect("no output is UNREADABLE", grade_network_diagnosis("")[0], None)
    expect("a diagnosis missing the proxy variables must FAIL",
           grade_network_diagnosis(
               named.replace("export HTTPS_PROXY=http://proxy.example:3128 "
                             "HTTP_PROXY=http://proxy.example:3128\n", "")
           )[0], False)
    expect("a diagnosis missing the degraded mode must FAIL",
           grade_network_diagnosis(
               named.replace("Kin runs without this server. ", "")
           )[0], False)
    expect("a diagnosis missing the offline path must FAIL",
           grade_network_diagnosis(named.replace(OFFLINE_FIXTURE_LINE, ""))[0], False)
    expect("a network failure handed the permission remedy must FAIL",
           grade_network_diagnosis(named + "      npm config set prefix ~/.npm-global\n")[0],
           False)
    expect("a failure with no network signature is UNREADABLE",
           grade_network_diagnosis(
               "  x could not install the python language server: `npm install -g "
               "pyright` exited with 1: npm error minTimeout is greater than maxTimeout\n"
           )[0], None)

    # FIR-2919, both directions, on the row set that fenced v0.6.1.
    #
    # The overclaim must fail, the honest emission of the SAME rows must pass,
    # and the shipped payload, which carried no verdict at all, must read
    # unreadable rather than either. Without the third arm the grader would
    # report a clean product on the exact bytes the defect shipped in.
    honest = {
        "platform": "windows",
        "checks": WINDOWS_V061_ROWS,
        "healthy": False,
        "verdict": "needs_attention",
    }
    overclaim = dict(honest, healthy=True, verdict="ready")
    shipped = {"platform": "windows", "checks": WINDOWS_V061_ROWS, "healthy": True}
    expect("the honest degraded roll-up must PASS",
           grade_health_rollup(honest)[0], True)
    expect("the v0.6.1 roll-up violation must FAIL",
           grade_health_rollup(overclaim)[0], False)
    expect("the shipped payload carries no verdict and is UNREADABLE",
           grade_health_rollup(shipped)[0], None)
    # The failure has to name the rows, or a reader gets a verdict mismatch with
    # nothing to act on. 19 unsupported rows are not among them.
    overclaim_detail = grade_health_rollup(overclaim)[1]
    for wanted in ("embedding_model=pending", "memory_floor=degraded"):
        if wanted not in overclaim_detail:
            failures.append("the roll-up failure must name %s: %s" % (wanted, overclaim_detail))
    for unwanted in ("daemon_running", "binary_assessment_load"):
        if unwanted in overclaim_detail:
            failures.append("the roll-up failure must not list out-of-scope rows (%s): %s"
                            % (unwanted, overclaim_detail))

    # The other three ways the roll-up can lie, each with the honest twin beside
    # it so a rule that refused everything could not pass this block.
    only_unsupported = {
        "checks": [{"id": "kin_binary", "status": "healthy"},
                   {"id": "vfs_projection", "status": "unsupported"}],
        "healthy": True, "verdict": "ready",
    }
    expect("unsupported rows must not disqualify a ready roll-up",
           grade_health_rollup(only_unsupported)[0], True)
    expect("a ready roll-up over an unsupported row must not be refused",
           grade_health_rollup(dict(only_unsupported, healthy=False,
                                    verdict="needs_attention"))[0], False)
    broken = {
        "checks": [{"id": "kin_binary", "status": "healthy"},
                   {"id": "shell_path", "status": "missing"}],
        "healthy": False, "verdict": "failing",
    }
    expect("a broken install reports failing, not needs_attention",
           grade_health_rollup(broken)[0], True)
    expect("calling a broken install merely warming must FAIL",
           grade_health_rollup(dict(broken, verdict="needs_attention"))[0], False)
    expect("a payload with no checks is UNREADABLE",
           grade_health_rollup({"healthy": True, "verdict": "ready", "checks": []})[0], None)
    expect("a status this grader does not know is UNREADABLE",
           grade_health_rollup({"healthy": True, "verdict": "ready",
                                "checks": [{"id": "x", "status": "warming"}]})[0], None)

    expect("npx keeps its flags and gains an explicit bin name",
           localize("npx -y @kinlab/kin --version", "/tmp/p.tgz"),
           'npx -y --package="file:/tmp/p.tgz" kin --version')
    expect("a line with no package spec is untouched",
           localize('export PATH="$HOME/.kin/bin:$PATH"', "/tmp/p.tgz"),
           'export PATH="$HOME/.kin/bin:$PATH"')
    expect("a bare install spec still localizes",
           localize("npm install -g @kinlab/kin", "/tmp/p.tgz"),
           "npm install -g /tmp/p.tgz")

    shipped_readme = "# @kinlab/kin\n\n```sh\nnpm install -g @kinlab/kin\nkin --version\n```\n"
    fixed_readme = ("# @kinlab/kin\n\n```sh\nnpx -y @kinlab/kin --version\n"
                    "export PATH=\"$HOME/.kin/bin:$PATH\"\nkin --version\n```\n")
    expect("the 0.5.49 README lead must FAIL",
           grade_install_block(leading_install_block(shipped_readme))[0], False)
    expect("the no-sudo lead must PASS",
           grade_install_block(leading_install_block(fixed_readme))[0], True)
    expect("a README with no shell block is UNREADABLE",
           grade_install_block(leading_install_block("# nothing here"))[0], None)
    expect("a sudo lead must FAIL",
           grade_install_block(["sudo npm install -g @kinlab/kin"])[0], False)
    expect("the block parser reads the FIRST block only",
           leading_install_block(fixed_readme + "```sh\nnpm install -g @kinlab/kin\n```\n"),
           ["npx -y @kinlab/kin --version",
            "export PATH=\"$HOME/.kin/bin:$PATH\"",
            "kin --version"])


    # The 0.6.0 refusal, verbatim from the walkthrough, and its inverse. The
    # shipped text trips BOTH failing branches, so it cannot tell them apart on
    # its own; the two inputs after it can, and the detail is asserted rather
    # than only the verdict.
    shipped_refusal = (
        "  x install the rust language server: 'rustup' is not installed on this host\n"
        "      install 'rustup', then run 'rustup component add rust-analyzer'\n"
    )
    only_remedy = (
        "  x install the rust language server: run `rustup component add rust-analyzer`\n"
        "      install 'rustup', then run 'rustup component add rust-analyzer'\n"
    )
    only_absence = (
        "  x install the rust language server: rustup is not installed on this host\n"
    )
    routed = (
        "  v installed the rust language server (`download rust-analyzer 2026-08-24 from the "
        "rust-lang/rust-analyzer release binaries`)\n"
        "      source:   http://127.0.0.1:9/2026-08-24/rust-analyzer-fixture.gz\n"
        "      sha256:   " + ("a" * 64) + " (verified before install)\n"
        "      installed to: /root/.kin/tools/bin/rust-analyzer\n"
    )
    expect("the shipped 0.6.0 refusal must FAIL",
           grade_toolchain_free_repair(shipped_refusal)[0], False)
    expect("a routed install must PASS", grade_toolchain_free_repair(routed)[0], True)
    expect("no output is UNREADABLE", grade_toolchain_free_repair("")[0], None)
    expect("a run that never mentioned rust is UNREADABLE",
           grade_toolchain_free_repair("Summary: 9 passed")[0], None)
    expect("a silent no-op is UNREADABLE",
           grade_toolchain_free_repair("  - skipped the rust language server\n")[0], None)
    expect("installed-but-unusable still PASSes",
           grade_toolchain_free_repair(
               routed + "  x the rust language server installed but did not start\n")[0], True)
    # Only the remedy branch can catch this one: it prescribes rustup without
    # ever saying rustup is absent.
    expect("a prescription with no refusal must FAIL",
           grade_toolchain_free_repair(only_remedy)[0], False)
    expect("and it must be the prescription branch that answered",
           PRESCRIBES_TOOLCHAIN in grade_toolchain_free_repair(only_remedy)[1], True)
    # Only the absence branch can catch this one: it reports rustup absent with
    # no remedy sentence at all.
    expect("a bare absence must FAIL", grade_toolchain_free_repair(only_absence)[0], False)
    expect("and it must be the absence branch that answered",
           ENDED_ON_ABSENCE in grade_toolchain_free_repair(only_absence)[1], True)


    # The wrapper's notice, verbatim from `noRepositoryNotice` in
    # packages/kin-mcp/src/index.js, and the 0.6.0 refusal it replaced. Held as
    # literals the product emits rather than rebuilt from parts, because a
    # grader fed a fixture this file invented cannot tell you what the wrapper
    # says.
    shipped_refusal_stderr = (
        "No .kin/ found. Run `kin init .` first, or set KIN_MCP_AUTO_INIT=1 to allow "
        "this wrapper to initialize the repo.\n"
    )
    fixed_notice_stderr = (
        "kin-mcp: no .kin/ found in /tmp/empty, so no repository is bound yet.\n"
        "Starting anyway. The MCP transport comes up, `initialize` and `tools/list` are served,\n"
        "and a graph tool called before a repository exists answers by naming the gap and telling\n"
        "the caller to run `kin init .` rather than failing silently.\n"
        "Run `kin init .` in the repository you want served, or point this client's workspace\n"
        "roots at one. This server re-resolves its repository on later tool calls, so nothing here\n"
        "needs a restart. Set KIN_MCP_AUTO_INIT=1 to let this wrapper run `kin init .` for you.\n"
    )
    served_frame = ['{"jsonrpc":"2.0","id":4242,"result":{"protocolVersion":"2024-11-05"}}\n']
    expect("the 0.6.0 wrapper dying on initialize must FAIL",
           grade_unbound_start(MCP_EOF, False, shipped_refusal_stderr, [], False)[0], False)
    expect("the fixed wrapper must PASS",
           grade_unbound_start(MCP_SERVED, True, fixed_notice_stderr, served_frame, False)[0],
           True)
    expect("a server that neither answered nor exited is UNREADABLE",
           grade_unbound_start(MCP_TIMEOUT, True, "", [], False)[0], None)
    expect("an answer from a process that is already gone must FAIL",
           grade_unbound_start(MCP_SERVED, False, fixed_notice_stderr, served_frame, False)[0],
           False)
    expect("starting unbound and initializing the repository anyway must FAIL",
           grade_unbound_start(MCP_SERVED, True, fixed_notice_stderr, served_frame, True)[0],
           False)
    expect("the notice on the protocol channel must FAIL",
           grade_unbound_start(MCP_SERVED, True, "",
                               [fixed_notice_stderr] + served_frame, False)[0], False)
    expect("a silent start with no notice at all must FAIL",
           grade_unbound_start(MCP_SERVED, True, "", served_frame, False)[0], False)
    expect("a notice naming the gap and not the repair must FAIL",
           grade_unbound_start(MCP_SERVED, True,
                               "kin-mcp: no .kin/ found in /tmp/empty, so no repository is "
                               "bound yet.\n", served_frame, False)[0], False)

    # The walkthrough's own sentence, and the one this suite requires instead.
    # Both are what the product printed: the first on 0.6.0 against axum, the
    # second on a three-Rust three-TypeScript fixture with rust-analyzer off
    # PATH.
    walkthrough_completion = (
        "Enriching cross-file references (language server)...\n"
        "  enriched 5/303 files\n"
        "  cross-file enrichment complete (5/303 files)\n"
    )
    named_skip = (
        "Enriching cross-file references (language server)...\n"
        "  enriched 3/6 files\n"
        "  cross-file enrichment ended having enriched 3 of 6 files, leaving 1 language "
        "unserved:\n"
        "    rust: 3 files not enriched, because the `rust-analyzer` language server did not "
        "start (server failed to start: rust-analyzer: No such file or directory (os error 2)), "
        "so nothing in this language was enriched\n"
    )
    expect("the walkthrough's completion sentence must FAIL",
           grade_skipped_language_outcome(walkthrough_completion)[0], False)
    expect("the named skip must PASS", grade_skipped_language_outcome(named_skip)[0], True)
    expect("the named skip with the fixture's own count must PASS",
           grade_skipped_language_outcome(named_skip, 3)[0], True)
    # The tally that stopped counting after the first blocked file. The sentence
    # is otherwise perfect, which is why only the number can catch it.
    expect("a row reporting one file for a language that lost three must FAIL",
           grade_skipped_language_outcome(
               named_skip.replace("rust: 3 files", "rust: 1 file"), 3)[0], False)
    expect("no output is UNREADABLE", grade_skipped_language_outcome("")[0], None)
    expect("a run that never enriched anything is UNREADABLE",
           grade_skipped_language_outcome("Initialized Kin repository authority at /tmp/x\n")[0],
           None)
    expect("an outcome that names no language must FAIL",
           grade_skipped_language_outcome(
               "Enriching cross-file references (language server)...\n"
               "  cross-file enrichment ended having enriched 3 of 6 files\n")[0], False)
    expect("an outcome that names the language and not the reason must FAIL",
           grade_skipped_language_outcome(
               "  cross-file enrichment ended having enriched 3 of 6 files, leaving 1 language "
               "unserved:\n"
               "    rust: 3 files not enriched, because the server was unavailable\n")[0], False)
    # The pre-fix `kin daemon sweep`, which shares no wording with `kin init`.
    # Its completion claim must be caught as a completion, never reported as a
    # run that produced no outcome.
    expect("the pre-fix sweep's own sentence must FAIL",
           grade_skipped_language_outcome("  enriched 3/6 files\nsweep complete (3/6 files)\n")[0],
           False)
    # The control's own grader, which is what stops "never say complete" from
    # passing a product that never says anything.
    expect("the control must PASS on a sweep that served every language",
           grade_served_sweep_outcome(
               "Enriching cross-file references (language server)...\n"
               "  cross-file enrichment complete (6/6 files)\n")[0], True)
    expect("the control must FAIL when a skip is reported on a clean run",
           grade_served_sweep_outcome(named_skip)[0], False)
    expect("the control must FAIL when the outcome claims neither",
           grade_served_sweep_outcome(
               "  cross-file enrichment covered 6 of 8 files:\n"
               "    2 files blocked for a reason this sweep did not attribute to a language\n"
           )[0], False)
    expect("the control on progress lines alone is UNREADABLE",
           grade_served_sweep_outcome("  enriched 6/6 files\n")[0], None)
    expect("the control on no output is UNREADABLE",
           grade_served_sweep_outcome("")[0], None)

    for line in failures:
        print("SELF-TEST FAIL %s" % line)
    print("first-contact-honesty self-test: %d grader case(s) failed" % len(failures))
    return 1 if failures else 0


# ------------------------------------------------------------------------ main


def repo_root_from(script_path):
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(script_path))))


def main(argv):
    parser = argparse.ArgumentParser(
        add_help=True, description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin")
    parser.add_argument("--daemon",
                        help="kin-daemon binary (default: the sibling of --kin)")
    parser.add_argument("--workdir")
    parser.add_argument("--repo-root")
    parser.add_argument("--label", default="")
    parser.add_argument("--only", default="")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        sys.stderr.write("--kin is required (or pass --self-test)\n")
        return 3
    kin = os.path.abspath(os.path.expanduser(opts.kin))
    if not os.path.exists(kin):
        sys.stderr.write("kin binary not found: %s\n" % kin)
        return 3
    daemon = opts.daemon and os.path.abspath(os.path.expanduser(opts.daemon))
    if daemon is None:
        sibling = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = sibling if os.path.exists(sibling) else None

    repo_root = os.path.abspath(opts.repo_root or repo_root_from(__file__))
    if not os.path.isdir(os.path.join(repo_root, "packages", "kin")):
        sys.stderr.write("repo root %s carries no packages/kin\n" % repo_root)
        return 3

    workdir = opts.workdir or tempfile.mkdtemp(prefix="kin-first-contact-")
    if not os.path.isdir(workdir):
        os.makedirs(workdir)

    rc, out, _ = run([kin, "--version"], timeout=600)
    version = strip_ansi(out).strip().splitlines()[-1] if out.strip() else "unknown"

    suite = Suite(kin, daemon, workdir, repo_root, verbose=opts.verbose)
    print("kin-first-contact-honesty: %s" % version)
    print("kin-first-contact-honesty: binary %s" % kin)
    print("kin-first-contact-honesty: repo root %s" % repo_root)
    print("kin-first-contact-honesty: workdir %s" % workdir)

    wanted = [w.strip() for w in opts.only.split(",") if w.strip()] or None
    results = []
    for check_id, fn in CHECKS:
        if wanted and check_id not in wanted:
            continue
        try:
            res = fn(suite)
        except Exception as exc:  # noqa: BLE001 - a harness fault is never a pass
            res = Result(check_id, "?", "harness failure")
            res.unknown("%s: %s" % (type(exc).__name__, str(exc)[:200]))
        results.append(res)
        print("CHECK %s %s %s %s" % (res.id, res.ticket, res.status, res.detail))
        if opts.verbose:
            for a in res.asserts:
                print("      %-11s %s" % (a["status"], a["detail"]))

    failed = [r for r in results if r.status == FAIL]
    unread = [r for r in results if r.status == UNREADABLE]
    print("kin-first-contact-honesty: %d pass, %d fail, %d unreadable"
          % (len(results) - len(failed) - len(unread), len(failed), len(unread)))

    if opts.json_out:
        with open(opts.json_out, "w") as handle:
            json.dump({"label": opts.label, "kin": kin, "version": version,
                       "workdir": workdir, "daemon": daemon,
                       "results": [{"id": r.id, "ticket": r.ticket, "title": r.title,
                                    "status": r.status, "detail": r.detail,
                                    "asserts": r.asserts} for r in results]},
                      handle, indent=2)
            handle.write("\n")

    if not opts.keep and not opts.workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    if failed:
        return 1
    if unread:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
