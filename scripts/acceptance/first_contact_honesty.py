#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""First-contact honesty: what a stranger meets before the graph answers anything.

Three defects the npm0549 green stranger hit on shipped 0.5.49, each on a surface
that runs before any semantic question is asked, and none of them visible to the
suites that grade answers:

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
                      variables that would route it, or the fact that Kin works
                      without the servers.

A new suite rather than three rows bolted onto the graph suites, for one reason:
none of these needs a store, a daemon or a corpus, and all three are minutes
faster without one. The CHECK line format, the exit codes and the JSON shape are
the same as every other suite here, because scripts/acceptance/gate.py reads all
of them through one contract.

Exit status: 1 when any check fails, 2 when none fail but some are unreadable, 3
on a setup error, 0 only when every selected check passes.
"""

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
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
    "Recorded in Kin authority, not in git — `git status` stays dirty until "
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
    """FIR-2629: a language-server install that dies on the network says so."""
    res = Result("2", "FIR-2629", "a black-holed network gets the named diagnosis and the degraded mode")
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
    if ok is None:
        res.unknown(detail)
    elif ok:
        res.ok(detail)
    else:
        res.bad(detail)
    return res


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2)]


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
        "      Kin runs without this server. Parsing, search, history, review and "
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
    expect("a network failure handed the permission remedy must FAIL",
           grade_network_diagnosis(named + "      npm config set prefix ~/.npm-global\n")[0],
           False)
    expect("a failure with no network signature is UNREADABLE",
           grade_network_diagnosis(
               "  x could not install the python language server: `npm install -g "
               "pyright` exited with 1: npm error minTimeout is greater than maxTimeout\n"
           )[0], None)

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
