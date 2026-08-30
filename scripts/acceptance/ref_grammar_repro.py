#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove kin diff resolves the refs its sibling read surfaces resolve.

FIR-3015. The npm-mode stranger run called this the dominant friction of its
version control arm. `kin diff` refused three endpoint forms in a row, each with
the same sentence, while `kin blame --ref` took two of them and `kin history`
printed the third itself:

  kin diff d4a944b9 479aa9b9
    Error: resolve diff base
    Caused by: diff endpoint 'd4a944b9' is not an authority ref, semantic
    change, Git object, HEAD, or WORKSPACE
  kin diff 1971f659d7aa 479aa9b94288      same sentence, and that twelve-hex
                                          form is what `kin history` prints
  kin diff HEAD~1 HEAD                    same sentence, while
                                          `kin blame --ref HEAD~1` answers

None of those refusals is wrong about the graph. Each is a correct statement
that the string handed in is not a form that resolver knows. What is wrong is
that Kin had two resolvers and never said so: `kin diff` parsed endpoints in
`diff.rs` and `kin blame`/`kin history` parsed refs in `ref_lookup.rs`, with no
code in common, so the grammar a user learns on one surface is not the grammar
the next surface speaks.

So this suite never grades a single form against a list written here. A list
written here is a third grammar, and it would drift from the product the same
way the first two drifted from each other. It grades the JOIN: it drives every
candidate form through `kin blame --ref` first, takes the set blame actually
accepted, and requires `kin diff` to accept each member of that measured set.
The reference set is a measurement, not a constant, so a form added to either
surface alone fails here rather than passing quietly.

Five checks, one seeded repository, run in order because the fixture is built up
by the early ones.

  printed_id   the twelve-hex id `kin history` prints is accepted by `kin diff`.
               This is the sharpest form of the defect, because the value came
               out of Kin's own mouth one command earlier. Its control is a
               fabricated twelve-hex of the same shape, which must be REFUSED
               and must be named in the refusal, so a `kin diff` that accepted
               everything could not pass this
  relative     `kin diff HEAD~1 HEAD` reports content. Its control is `HEAD~99`
               on a three-commit history, which must be refused: without it a
               diff that silently fell back to HEAD would pass
  parity       every form `kin blame --ref` accepted, `kin diff` accepts. The
               reference set is measured from blame in this same run. Its
               control is the set blame REFUSED, which diff must refuse too, so
               a diff that accepted every string cannot pass
  refusal_names_it  a refusal quotes the selector the user typed. A shared
               grammar that refused with a generic sentence would leave an
               operator no way to tell which of two endpoints was the bad one
  ambiguity    a prefix short enough to match more than one change is refused as
               ambiguous rather than resolved to whichever came first. Reported
               UNREADABLE, not FAIL, when the fixture's history happens to
               produce no colliding prefix, because a check that grades an
               absence it did not construct grades nothing

Exit status is 0 when every check passed, 1 when one failed, 2 when none failed
but one could not be read, and 3 when the run could not be set up. `--self-test`
drives every grader against the literal pre-fix output the stranger saw and the
post-fix output beside it, and needs no binary, so a grader that cannot fail is
a failure here rather than a silent pass in CI.
"""
from __future__ import print_function

import argparse
import functools
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

TICKET = "FIR-3015"

print = functools.partial(print, flush=True)

TRACKED_MODULE = "ledger.py"

# Three bodies, each adding one declaration, so the fixture has three changes and
# `biggest` has a history to blame. Declarations are added rather than only
# edited so `kin history biggest` has rows to print ids from.
MODULE_ONE = '''"""A tiny expense ledger."""


def parse_line(line):
    return line.strip().split(",")
'''

MODULE_TWO = '''"""A tiny expense ledger."""


def parse_line(line):
    return [field.strip() for field in line.split(",")]


def biggest(rows):
    return max(rows)
'''

MODULE_THREE = '''"""A tiny expense ledger."""


def parse_line(line):
    return [field.strip() for field in line.split(",")]


def biggest(rows):
    return max(rows, key=lambda row: int(row[1]))
'''

# The literal the stranger saw, quoted rather than invented. Every grader below
# is driven against this text in --self-test, because a grader tested only
# against strings written by the same hand cannot tell you what the product says.
REFUSAL_BEFORE = (
    "Error: resolve diff base\n"
    "\n"
    "Caused by:\n"
    "    diff endpoint '1971f659d7aa' is not an authority ref, semantic change, "
    "Git object, HEAD, or WORKSPACE\n"
)

# What the same command prints once diff and blame share one resolver. Taken from
# the shape `kin diff` already uses for an endpoint it does resolve.
DIFF_CONTENT_AFTER = (
    "Diff 1971f659d7aa..WORKSPACE\n"
    "Artifacts: +0 ~1 -0\n"
    "  ~ ledger.py\n"
    "Entities: +1 ~1 -0\n"
)

# A refusal from the shared resolver: still a refusal, still names what was typed.
REFUSAL_FABRICATED_AFTER = (
    "Error: resolve diff base\n"
    "\n"
    "Caused by:\n"
    "    no semantic change in this repository's history begins with 'deadbeefcafe'\n"
)


def run(cmd, cwd=None, env=None, timeout=600):
    process = subprocess.Popen(
        cmd, cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        return 124, out or "", err or ""
    return process.returncode, out or "", err or ""


def diff_carries_content(text):
    """Whether a `kin diff` answer is a report rather than a refusal.

    Anchored on the `Artifacts:` tally every diff report carries rather than on
    the absence of the word error, because an absence is satisfied by empty
    output and by a timeout alike.
    """
    return "Artifacts:" in (text or "")


def grade_printed_id_is_accepted(printed_id, answer_text, control_id, control_text):
    """The id Kin printed one command earlier must be an id Kin accepts.

    Two arms, and the control is not decoration. Without it a `kin diff` that
    resolved every string it was handed would pass this check, which is the
    exact failure mode of a grammar widened by deleting a guard rather than by
    adding a form.
    """
    if not printed_id:
        return UNREADABLE, "kin history printed no abbreviated change id to feed back"
    if not diff_carries_content(answer_text):
        return FAIL, (
            "kin history printed change id %s and kin diff will not take it back: %s"
            % (printed_id, " ".join((answer_text or "").split())[:220])
        )
    if diff_carries_content(control_text):
        return FAIL, (
            "kin diff answered for fabricated id %s, so it resolves strings that name "
            "nothing and accepting %s proves nothing" % (control_id, printed_id)
        )
    if control_id not in (control_text or ""):
        return FAIL, (
            "kin diff refused fabricated id %s without naming it, so an operator "
            "diffing two endpoints cannot tell which one was bad: %s"
            % (control_id, " ".join((control_text or "").split())[:220])
        )
    return PASS, (
        "kin diff resolves the id kin history printed (%s) and still refuses a "
        "fabricated one, naming it (%s)" % (printed_id, control_id)
    )


def grade_relative_ref_resolves(near_text, far_selector, far_text):
    """`kin diff HEAD~1 HEAD` answers, and a hop past the root does not.

    The control matters more than it looks: a resolver that ignored the hop
    suffix entirely would answer for HEAD~1 by silently diffing HEAD against
    HEAD, which reports content and reads exactly like success.
    """
    if not diff_carries_content(near_text):
        return FAIL, (
            "kin diff HEAD~1 HEAD reports no content while kin blame --ref HEAD~1 "
            "answers: %s" % " ".join((near_text or "").split())[:220]
        )
    if diff_carries_content(far_text):
        return FAIL, (
            "kin diff answered for %s on a three-change history, so the hop suffix is "
            "being dropped rather than walked and HEAD~1 passed for the wrong reason"
            % far_selector
        )
    return PASS, (
        "kin diff walks parent hops (HEAD~1 answers) and refuses a hop past the root (%s)"
        % far_selector
    )


def grade_surfaces_agree(measured):
    """The join, over the set blame actually accepted in this run.

    `measured` is a list of (form, value, blame_accepted, diff_accepted). The
    reference set is measured rather than written here, because a list written
    here is a third grammar and would drift from the product exactly the way the
    first two drifted from each other.

    Both directions are graded. The forms blame refused are the control: if diff
    accepts those too, then diff accepts everything and its agreement on the
    first set is worth nothing.
    """
    if not measured:
        return UNREADABLE, "no endpoint form was measured on either surface"
    blame_took = [row for row in measured if row[2]]
    blame_refused = [row for row in measured if not row[2]]
    if not blame_took:
        return UNREADABLE, (
            "kin blame --ref accepted no form at all, so this run measured no reference "
            "set and diff had nothing to be graded against"
        )
    if not blame_refused:
        return UNREADABLE, (
            "kin blame --ref accepted every form offered, including the fabricated ones, "
            "so the control arm is empty and agreement would prove nothing"
        )
    missing = [row for row in blame_took if not row[3]]
    over = [row for row in blame_refused if row[3]]
    if missing:
        return FAIL, (
            "kin blame --ref resolves %d form(s) kin diff refuses: %s"
            % (len(missing), ", ".join("%s (%s)" % (row[0], row[1]) for row in missing))
        )
    if over:
        return FAIL, (
            "kin diff resolves %d form(s) kin blame --ref refuses, so the two surfaces "
            "still disagree: %s"
            % (len(over), ", ".join("%s (%s)" % (row[0], row[1]) for row in over))
        )
    return PASS, (
        "both surfaces agree on all %d measured form(s): %d resolved by each, %d refused "
        "by each" % (len(measured), len(blame_took), len(blame_refused))
    )


def grade_refusal_names_the_selector(selector, text):
    """A refusal quotes what was typed.

    `kin diff` takes two endpoints. A refusal that does not say which of them it
    could not resolve leaves the operator to guess, and the pre-fix message got
    this right; the point here is that a rewritten resolver must not lose it.
    """
    body = text or ""
    if diff_carries_content(body):
        return UNREADABLE, (
            "kin diff answered for %s, so this run produced no refusal to read" % selector
        )
    if selector in body:
        return PASS, "the refusal names the endpoint that failed: %s" % selector
    return FAIL, (
        "kin diff refused %s without naming it, so which of the two endpoints was bad "
        "is not in the message: %s" % (selector, " ".join(body.split())[:220])
    )


def grade_ambiguous_prefix_is_refused(prefix, text, collisions):
    """A prefix matching more than one change is refused, not silently picked.

    UNREADABLE rather than FAIL when this fixture's history produced no
    colliding prefix. A check that grades an absence it did not construct grades
    nothing, and three short changes rarely collide even at four hex characters.
    """
    if collisions < 2:
        return UNREADABLE, (
            "no prefix in this fixture matches two changes (%d candidate(s) for %r), so "
            "the ambiguous case was never reached" % (collisions, prefix)
        )
    if diff_carries_content(text):
        return FAIL, (
            "prefix %r matches %d changes and kin diff resolved it anyway, so it picked "
            "one without saying which" % (prefix, collisions)
        )
    if prefix not in (text or ""):
        return FAIL, (
            "kin diff refused ambiguous prefix %r without naming it: %s"
            % (prefix, " ".join((text or "").split())[:220])
        )
    return PASS, "ambiguous prefix %r (%d changes) is refused and named" % (prefix, collisions)


HEX12 = re.compile(r"\b[0-9a-f]{12}\b")
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")

# A fabricated twelve-hex of exactly the shape `kin history` prints. It must be
# refused, and it is written once and used by both the live control and the
# self-test so the two cannot drift apart.
FABRICATED_12 = "deadbeefcafe"
FABRICATED_64 = "de" * 32


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home)
        # kin refuses to invent an author, which is correct. The run isolates
        # HOME so it cannot read the machine's identity, so it brings its own.
        with open(os.path.join(self.home, ".gitconfig"), "w") as handle:
            handle.write("[user]\n\tname = ref-grammar-repro\n"
                         "\temail = repro@example.invalid\n"
                         "[commit]\n\tgpgsign = false\n")
        self.env = dict(os.environ)
        self.env["HOME"] = self.home
        self.env["USERPROFILE"] = self.home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env["KIN_REGISTRY_PATH"] = os.path.join(self.home, "registry.toml")
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DAEMON_URL", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self._repo = None
        self._measured = None
        self._printed_id = None
        self._changes = None

    def kin_run(self, args, timeout=600):
        rc, out, err = run([self.kin] + args, cwd=self.repo(), env=self.env, timeout=timeout)
        if self.verbose:
            print("  $ kin %s -> rc=%s" % (" ".join(args), rc))
        return rc, out, err

    def answer(self, args):
        """Command output with stderr folded in, because a refusal lands there."""
        rc, out, err = self.kin_run(args)
        return rc, (out or "") + (err or "")

    def repo(self):
        if self._repo:
            return self._repo
        path = os.path.realpath(os.path.join(self.workdir, "ledger"))
        os.makedirs(path)
        self._repo = path
        # `kin init` refuses a non-empty directory for a non-Git repository, so
        # the store comes first and the files are written into it.
        rc, out, err = run([self.kin, "init"], cwd=path, env=self.env, timeout=600)
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % ((err or out)[-400:]))
        for body, message in ((MODULE_ONE, "Add ledger line parsing"),
                              (MODULE_TWO, "Add a biggest() helper"),
                              (MODULE_THREE, "Key biggest() on the amount column")):
            target = os.path.join(path, TRACKED_MODULE)
            with open(target, "w") as handle:
                handle.write(body)
            rc, out, err = self.kin_run(["commit", "-m", message])
            if rc != 0:
                raise RuntimeError("seeding commit %r failed: %s"
                                   % (message, (err or out)[-400:]))
        return path

    def printed_id(self):
        """The abbreviated change id `kin history` puts on the operator's screen."""
        if self._printed_id is not None:
            return self._printed_id
        _, text = self.answer(["history", "biggest"])
        found = HEX12.findall(text)
        self._printed_id = found[0] if found else ""
        return self._printed_id

    def changes(self):
        """Every full change id this fixture's log holds, newest first."""
        if self._changes is not None:
            return self._changes
        _, text = self.answer(["log", "-n", "20"])
        seen = []
        for value in HEX64.findall(text):
            if value not in seen:
                seen.append(value)
        self._changes = seen
        return self._changes

    def measured(self):
        """Drive every candidate form through blame first, then diff.

        Blame runs first on purpose: its answer is the reference set, so it is
        taken from the product in this same run rather than from a constant.
        """
        if self._measured is not None:
            return self._measured
        head = self.changes()[0] if self.changes() else None
        forms = [
            ("HEAD", "HEAD"),
            ("parent hop", "HEAD~1"),
            ("caret hop", "HEAD^"),
            ("bare branch", "main"),
            ("branch: prefix", "branch:main"),
            ("printed 12-hex", self.printed_id()),
            ("fabricated 12-hex", FABRICATED_12),
            ("fabricated 64-hex", FABRICATED_64),
        ]
        if head:
            forms.extend([
                ("full change id", head),
                ("kin: prefix", "kin:%s" % head),
                ("change: prefix", "change:%s" % head),
                ("8-hex prefix", head[:8]),
            ])
        rows = []
        for label, value in forms:
            if not value:
                continue
            blame_rc, _ = self.answer(["blame", "biggest", "--ref", value])
            _, diff_text = self.answer(["diff", value, "HEAD"])
            rows.append((label, value, blame_rc == 0, diff_carries_content(diff_text)))
        self._measured = rows
        return rows


class Result(object):
    def __init__(self, ident, status, detail):
        self.ident = ident
        self.status = status
        self.detail = detail


def check_printed_id(suite):
    printed = suite.printed_id()
    _, answer = suite.answer(["diff", printed, "HEAD"]) if printed else (1, "")
    _, control = suite.answer(["diff", FABRICATED_12, "HEAD"])
    status, detail = grade_printed_id_is_accepted(printed, answer, FABRICATED_12, control)
    return Result("printed_id", status, "%s %s" % (TICKET, detail))


def check_relative(suite):
    _, near = suite.answer(["diff", "HEAD~1", "HEAD"])
    _, far = suite.answer(["diff", "HEAD~99", "HEAD"])
    status, detail = grade_relative_ref_resolves(near, "HEAD~99", far)
    return Result("relative", status, "%s %s" % (TICKET, detail))


def check_parity(suite):
    status, detail = grade_surfaces_agree(suite.measured())
    return Result("parity", status, "%s %s" % (TICKET, detail))


def check_refusal_names_it(suite):
    _, text = suite.answer(["diff", FABRICATED_64, "HEAD"])
    status, detail = grade_refusal_names_the_selector(FABRICATED_64, text)
    return Result("refusal_names_it", status, "%s %s" % (TICKET, detail))


def check_ambiguity(suite):
    changes = suite.changes()
    prefix, collisions = "", 0
    # The shortest prefix this fixture's own ids collide on, if any. Derived from
    # the fixture rather than assumed, because three changes usually do not
    # collide and asserting they do would grade a coincidence.
    for width in range(1, 8):
        buckets = {}
        for value in changes:
            buckets.setdefault(value[:width], []).append(value)
        clashing = [(key, group) for key, group in buckets.items() if len(group) > 1]
        if clashing:
            prefix, group = clashing[0]
            collisions = len(group)
            break
    text = ""
    if collisions >= 2:
        _, text = suite.answer(["diff", prefix, "HEAD"])
    status, detail = grade_ambiguous_prefix_is_refused(prefix, text, collisions)
    return Result("ambiguity", status, "%s %s" % (TICKET, detail))


CHECKS = (
    ("printed_id", check_printed_id),
    ("relative", check_relative),
    ("parity", check_parity),
    ("refusal_names_it", check_refusal_names_it),
    ("ambiguity", check_ambiguity),
)


def report_payload(results):
    # The key is `results` because that is the one `gate.py:load_report` reads.
    # Five suites have now shipped it as `checks` and gone ungraded; the join is
    # proven below by handing this payload to the real loader rather than by
    # naming the key a second time.
    return {
        "ticket": TICKET,
        "results": [
            {"id": result.ident, "status": result.status, "detail": result.detail}
            for result in results
        ],
    }


def absolute_binary(path):
    if not path:
        return None
    resolved = os.path.abspath(path)
    return resolved if os.path.exists(resolved) else path


def check_the_gate_reads_this_suites_report():
    """Hand this suite's own report to `gate.py`'s loader and require it back.

    Asserting the literal key would write the string twice and drift the same
    way it drifted in the five suites that shipped their rows under `checks`.
    Importing the real consumer cannot: if the gate stops reading `results`, or
    this file stops writing it, this goes red.

    Returns (cases_run, broken).
    """
    ran = 0
    broken = 0

    def expect(name, got, want):
        nonlocal ran, broken
        ran += 1
        ok = got == want
        if not ok:
            broken += 1
        print("SELFTEST %s %s expected=%s got=%s"
              % (name, "ok" if ok else "BROKEN", want, got))

    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    if not os.path.exists(gate_path):
        print("SELFTEST gate/beside BROKEN gate.py is not beside this file, "
              "so the report shape went unchecked")
        return 1, 1

    spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)

    scratch = tempfile.mkdtemp(prefix="ref-grammar-selftest-")
    try:
        rows = [Result(ident, UNREADABLE, "%s check raised: fabricated" % TICKET)
                for ident, _ in CHECKS]
        good = os.path.join(scratch, "good.json")
        with open(good, "w") as handle:
            json.dump(report_payload(rows), handle)
        try:
            loaded = gate.load_report(good)
            expect("gate/reads-every-row", sorted(loaded),
                   sorted(ident for ident, _ in CHECKS))
            expect("gate/reads-a-status", loaded[CHECKS[0][0]].get("status"), UNREADABLE)
        except Exception as exc:  # noqa: BLE001 - a refusal is the finding
            ran += 1
            broken += 1
            print("SELFTEST gate/reads-every-row BROKEN the gate refused this "
                  "suite's own report: %s" % exc)

        # CONTROL: the shape that shipped in five other suites must still be
        # refused, or the two assertions above would pass over any payload.
        bad = os.path.join(scratch, "bad.json")
        with open(bad, "w") as handle:
            json.dump({"ticket": TICKET,
                       "checks": [{"id": ident, "status": UNREADABLE}
                                  for ident, _ in CHECKS]}, handle)
        try:
            gate.load_report(bad)
            refused = False
        except Exception:  # noqa: BLE001 - the refusal is what is wanted
            refused = True
        expect("gate/CONTROL-still-refuses-the-checks-shape", refused, True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return ran, broken


def self_test():
    """Drive every grader against a payload that must pass and one that must fail.

    The pre-fix rows carry the literal text the stranger's run produced. A grader
    that cannot go red over that text is a grader that would have passed the
    defect, and this is the only place that gets checked.
    """
    ran = 0
    broken = 0

    def expect(name, got, want):
        nonlocal ran, broken
        ran += 1
        status = got[0] if isinstance(got, tuple) else got
        ok = status == want
        if not ok:
            broken += 1
        print("SELFTEST %s %s expected=%s got=%s%s"
              % (name, "ok" if ok else "BROKEN", want, status,
                 "" if ok else (" detail=%s" % (got[1] if isinstance(got, tuple) else ""))))

    printed = "1971f659d7aa"

    # printed_id: the literal refusal must FAIL, the fixed answer must PASS.
    expect("printed_id/BEFORE-refuses-its-own-id",
           grade_printed_id_is_accepted(printed, REFUSAL_BEFORE,
                                        FABRICATED_12, REFUSAL_FABRICATED_AFTER), FAIL)
    expect("printed_id/AFTER-resolves-it",
           grade_printed_id_is_accepted(printed, DIFF_CONTENT_AFTER,
                                        FABRICATED_12, REFUSAL_FABRICATED_AFTER), PASS)
    # CONTROL: a diff that answers for a fabricated id must not pass, or the
    # AFTER row above would be satisfied by a resolver that accepts anything.
    expect("printed_id/CONTROL-accepts-everything-fails",
           grade_printed_id_is_accepted(printed, DIFF_CONTENT_AFTER,
                                        FABRICATED_12, DIFF_CONTENT_AFTER), FAIL)
    # CONTROL: a refusal that does not name the fabricated id must not pass.
    expect("printed_id/CONTROL-unnamed-refusal-fails",
           grade_printed_id_is_accepted(printed, DIFF_CONTENT_AFTER, FABRICATED_12,
                                        "Error: resolve diff base\nCaused by: not found\n"),
           FAIL)
    expect("printed_id/no-id-printed-is-unreadable",
           grade_printed_id_is_accepted("", DIFF_CONTENT_AFTER,
                                        FABRICATED_12, REFUSAL_FABRICATED_AFTER), UNREADABLE)

    # relative
    expect("relative/BEFORE-refuses-HEAD~1",
           grade_relative_ref_resolves(REFUSAL_BEFORE, "HEAD~99", REFUSAL_BEFORE), FAIL)
    expect("relative/AFTER-walks-the-hop",
           grade_relative_ref_resolves(DIFF_CONTENT_AFTER, "HEAD~99", REFUSAL_BEFORE), PASS)
    # CONTROL: dropping the hop suffix answers for both, which must not pass.
    expect("relative/CONTROL-hop-ignored-fails",
           grade_relative_ref_resolves(DIFF_CONTENT_AFTER, "HEAD~99", DIFF_CONTENT_AFTER),
           FAIL)

    # parity, driven over measured rows rather than over text.
    before_rows = [("HEAD", "HEAD", True, True),
                   ("parent hop", "HEAD~1", True, False),
                   ("fabricated 12-hex", FABRICATED_12, False, False)]
    after_rows = [("HEAD", "HEAD", True, True),
                  ("parent hop", "HEAD~1", True, True),
                  ("fabricated 12-hex", FABRICATED_12, False, False)]
    over_rows = [("HEAD", "HEAD", True, True),
                 ("fabricated 12-hex", FABRICATED_12, False, True)]
    expect("parity/BEFORE-diff-lacks-the-hop", grade_surfaces_agree(before_rows), FAIL)
    expect("parity/AFTER-agrees", grade_surfaces_agree(after_rows), PASS)
    expect("parity/CONTROL-diff-accepts-a-form-blame-refuses",
           grade_surfaces_agree(over_rows), FAIL)
    expect("parity/no-rows-is-unreadable", grade_surfaces_agree([]), UNREADABLE)
    # CONTROL: with nothing refused there is no control arm, so agreement over
    # the accepted set proves nothing and must read UNREADABLE, not PASS.
    expect("parity/CONTROL-empty-refused-arm-is-unreadable",
           grade_surfaces_agree([("HEAD", "HEAD", True, True)]), UNREADABLE)

    # refusal_names_it
    expect("refusal/BEFORE-named-it",
           grade_refusal_names_the_selector("1971f659d7aa", REFUSAL_BEFORE), PASS)
    expect("refusal/CONTROL-generic-refusal-fails",
           grade_refusal_names_the_selector(
               "1971f659d7aa",
               "Error: resolve diff base\nCaused by: endpoint did not resolve\n"), FAIL)
    expect("refusal/content-is-unreadable",
           grade_refusal_names_the_selector("1971f659d7aa", DIFF_CONTENT_AFTER), UNREADABLE)

    # ambiguity
    expect("ambiguity/no-collision-is-unreadable",
           grade_ambiguous_prefix_is_refused("abcd", "", 1), UNREADABLE)
    expect("ambiguity/AFTER-refuses-and-names",
           grade_ambiguous_prefix_is_refused(
               "abcd", "Error: 'abcd' matches 2 changes; use more characters\n", 2), PASS)
    expect("ambiguity/CONTROL-silently-resolved-fails",
           grade_ambiguous_prefix_is_refused("abcd", DIFF_CONTENT_AFTER, 2), FAIL)
    expect("ambiguity/CONTROL-unnamed-refusal-fails",
           grade_ambiguous_prefix_is_refused(
               "abcd", "Error: that prefix matches more than one change\n", 2), FAIL)

    gate_ran, gate_broken = check_the_gate_reads_this_suites_report()
    ran += gate_ran
    broken += gate_broken

    print("SELFTEST %s %d case(s), %d broken" % (TICKET, ran, broken))
    if broken:
        return 1
    # A self-test that graded nothing is a failure, not a pass. The floor is the
    # count of expect() calls above, so deleting one has to be deliberate.
    if ran < 22:
        print("SELFTEST %s BROKEN only %d case(s) ran; the self-test lost coverage"
              % (TICKET, ran))
        return 1
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN") or shutil.which("kin"))
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"))
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        print("SETUP no kin binary: pass --kin or set KIN_BIN")
        return 3
    opts.kin = absolute_binary(opts.kin)
    opts.daemon = absolute_binary(opts.daemon)

    workdir = tempfile.mkdtemp(prefix="ref-grammar-")
    suite = Suite(opts.kin, workdir, daemon=opts.daemon, verbose=opts.verbose)
    try:
        results = []
        for ident, check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a setup failure is not a verdict
                results.append(Result(ident, UNREADABLE, "%s check raised: %s" % (TICKET, error)))
        for result in results:
            print("CHECK %s %s %s %s" % (result.ident, TICKET, result.status, result.detail))
        asked = [ident for ident, _ in CHECKS]
        answered = [result.ident for result in results]
        # Written before the asked/answered guard. UNREADABLE rows are a verdict
        # the gate can name; a missing report is one it can only refuse.
        if opts.json_path:
            directory = os.path.dirname(os.path.abspath(opts.json_path))
            if directory:
                try:
                    os.makedirs(directory)
                except OSError:
                    pass
            with open(opts.json_path, "w") as handle:
                json.dump(report_payload(results), handle, indent=2)
        if answered != asked:
            print("SETUP asked for %r and %r answered" % (asked, answered))
            return 3
        if any(result.status == FAIL for result in results):
            return 1
        if any(result.status == UNREADABLE for result in results):
            return 2
        return 0
    finally:
        try:
            if suite._repo:
                run([opts.kin, "daemon", "stop"], cwd=suite._repo, env=suite.env, timeout=180)
        except Exception:  # noqa: BLE001 - teardown must not change the verdict
            pass
        if not opts.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print("kept fixtures under %s" % workdir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
