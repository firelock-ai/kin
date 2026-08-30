#!/usr/bin/env python3
"""FIR-2961: blame and history must attribute to the entity, not the file.

Two findings, one suite, because they share a surface and a failure mode.

**The over-report.** `reconciler.rs` stamps the whole FILE's blob hash into every
entity's metadata and commit compares the complete `Entity`, so every entity in a
touched file mints a revision. Measured on 2026-08-30 with a fixture whose commit
messages document it: a function written once and never edited was credited with
two later changes whose messages say, in as many words, that they edited a
different function.

**The control that decides everything here.** In the same fixture, a function
that DID change twice also reports 3. The right answer and the wrong answer are
the same number, so **a check that counts revisions cannot grade this**. Every
check below therefore asserts the pair: the untouched entity trims and names what
it withheld, AND the edited one does not.

**The unreadable-change surface.** A published merge is not reachable from the
running daemon's live graph, so blame and history fail on it while `kin log` and
`kin diff` still read it. That failure must name what the caller asked for and a
remedy that works, rather than leaking an internal id in a 500.

Each check prints `CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>`.
Exit 0 all pass, 1 any FAIL, 2 any UNREADABLE, 3 setup.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

PASS, FAIL, UNREADABLE = "PASS", "FAIL", "UNREADABLE"
TICKET = "FIR-2961"

REVISION_ROW = re.compile(r"^[0-9a-f]{64}\s", re.M)
HISTORY_ROW = re.compile(r"^  [0-9a-f]{12}\s", re.M)
WITHHELD = re.compile(r"^(\d+) file-level revision", re.M)


def run(cmd, cwd=None, env=None, timeout=600):
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill(); out, err = p.communicate(); return 124, out, err
    return p.returncode, out, err


def tail(text, limit=220):
    text = (text or "").strip()
    return text if len(text) <= limit else text[-limit:]


def counts(text, row_re):
    """(rows, withheld) from a rendered listing."""
    rows = len(row_re.findall(text or ""))
    m = WITHHELD.search(text or "")
    return rows, (int(m.group(1)) if m else 0)


# ---------------------------------------------------------------- graders

def grade_attribution_is_per_entity(untouched, edited, row_re):
    """The untouched entity trims and names it; the edited one does not.

    Both halves are required. Asserting only the first would pass a change that
    truncated every listing, and asserting only the second would pass the
    unfixed product, since the edited entity's 3 is correct today.
    """
    u_rows, u_withheld = counts(untouched, row_re)
    e_rows, e_withheld = counts(edited, row_re)
    if u_rows == 0 or e_rows == 0:
        return UNREADABLE, ("a listing carried no revision rows at all "
                            "(untouched=%d, edited=%d), so this cannot grade"
                            % (u_rows, e_rows))
    if u_rows == 1 and u_withheld == 2 and e_rows == 3 and e_withheld == 0:
        return PASS, ("attribution is per entity: the untouched function lists 1 and names 2 "
                      "withheld, the edited one lists 3 and withholds none")
    if u_rows == e_rows and u_withheld == 0 and e_withheld == 0:
        return FAIL, ("both functions report %d revisions and neither names a withheld one, so "
                      "a file-level change is still credited to an entity it did not touch"
                      % u_rows)
    if e_rows != 3 or e_withheld != 0:
        return FAIL, ("the edited function reports %d rows and %d withheld where 3 and 0 are "
                      "correct, so the trim is dropping real changes" % (e_rows, e_withheld))
    return FAIL, ("the untouched function reports %d rows and %d withheld where 1 and 2 are "
                  "correct" % (u_rows, u_withheld))


def grade_all_revisions_restores(trimmed, full, row_re):
    """`--all-revisions` must restore exactly what the default withheld."""
    t_rows, t_withheld = counts(trimmed, row_re)
    f_rows, f_withheld = counts(full, row_re)
    if t_rows == 0 or f_rows == 0:
        return UNREADABLE, "a listing carried no revision rows, so this cannot grade"
    if f_withheld != 0:
        return FAIL, "--all-revisions still names %d withheld revisions" % f_withheld
    if f_rows != t_rows + t_withheld:
        return FAIL, ("--all-revisions shows %d rows where the default showed %d and withheld "
                      "%d, so the withheld count does not describe what it hid"
                      % (f_rows, t_rows, t_withheld))
    if f_rows == t_rows:
        return FAIL, "--all-revisions changed nothing, so the flag hides no information"
    return PASS, ("--all-revisions restores exactly what the default withheld: %d = %d + %d"
                  % (f_rows, t_rows, t_withheld))


def grade_unreadable_change_is_named(text):
    """A replay miss must name the ref, stay out of 5xx, and give a real remedy."""
    if "refused" not in (text or "") and "Error" not in (text or ""):
        return UNREADABLE, "the command did not fail, so there is no refusal to grade"
    if "HTTP 500" in text:
        return FAIL, ("the refusal is a 500, so a caller-visible lookup miss is reported as an "
                      "internal fault: %s" % tail(text))
    missing = [p for p in ("ref '", "does not hold", "kin daemon stop") if p not in text]
    if missing:
        return FAIL, ("the refusal does not name %s, so it cannot be acted on: %s"
                      % (", ".join(repr(m) for m in missing), tail(text)))
    if "run `kin status`" in text:
        return FAIL, ("the refusal names `kin status` as the remedy, which does not clear this "
                      "state; only restarting the daemon does")
    return PASS, "the refusal names the ref, the cause, and a remedy that works"


def grade_surfaces_agree(blame_text, history_text):
    """blame and history must give the same answer for the same entity.

    Deliberately green on BOTH the pre-fix and post-fix product, because before
    the fix the two surfaces agreed on the wrong number. This check is about
    agreement, not correctness: the attribution graders above own correctness,
    and this one goes red only when a fix reaches one surface and not the other.

    That makes it a check whose green proves less than the others', so it carries
    its own self-test rows below rather than being trusted because it is short.
    """
    b_rows, b_withheld = counts(blame_text, REVISION_ROW)
    h_rows, h_withheld = counts(history_text, HISTORY_ROW)
    if b_rows == 0 or h_rows == 0:
        return UNREADABLE, ("a surface carried no rows (blame=%d, history=%d)"
                            % (b_rows, h_rows))
    if (b_rows, b_withheld) != (h_rows, h_withheld):
        return FAIL, ("blame says %d rows and %d withheld while history says %d and %d, so the "
                      "two surfaces disagree about which revisions belong to the entity"
                      % (b_rows, b_withheld, h_rows, h_withheld))
    return PASS, "blame and history agree: %d rows, %d withheld" % (b_rows, b_withheld)


# ---------------------------------------------------------------- fixture

# The commit messages document the defect on their own: two of them say they
# edited a different function, and the pre-fix product credits both to
# untouched_fn.
def module(doc, body):
    return ('"""Two functions."""\n\n\n'
            'def untouched_fn(rows):\n'
            '    """Never edited after this commit."""\n'
            '    return len(rows)\n\n\n'
            'def edited_fn(rows):\n'
            '    """%s"""\n'
            '    return %s\n' % (doc, body))


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home)
        with open(os.path.join(self.home, ".gitconfig"), "w") as handle:
            handle.write("[user]\n\tname = blame-attribution-repro\n"
                         "\temail = repro@example.invalid\n[commit]\n\tgpgsign = false\n")
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

    def kin_run(self, args, timeout=600):
        rc, out, err = run([self.kin] + args, cwd=self.repo(), env=self.env, timeout=timeout)
        if self.verbose:
            print("  $ kin %s -> rc=%s" % (" ".join(args), rc))
        return rc, out, err

    def _write(self, relative, body):
        target = os.path.join(self.repo(), relative)
        directory = os.path.dirname(target)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(target, "w") as handle:
            handle.write(body)

    def repo(self):
        if self._repo:
            return self._repo
        path = os.path.realpath(os.path.join(self.workdir, "ledger"))
        os.makedirs(path)
        self._repo = path
        rc, out, err = run([self.kin, "init"], cwd=path, env=self.env, timeout=600)
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % tail((err or out), 400))
        for doc, body, message in (
            ("First.", "rows", "add both functions"),
            ("Second.", "sorted(rows)", "edit only edited_fn (1)"),
            ("Third.", "list(reversed(rows))", "edit only edited_fn (2)"),
        ):
            self._write("pkg/two.py", module(doc, body))
            rc, out, err = self.kin_run(["commit", "-m", message])
            if rc != 0:
                raise RuntimeError("commit %r failed: %s" % (message, tail((err or out), 400)))
        # The fixture is only meaningful with three changes on the file. A
        # listing graded against a two-change history would read as a trim.
        rc, out, err = self.kin_run(["log"])
        seen = out.count("\nchange ") + (1 if out.startswith("change ") else 0)
        if seen != 3:
            raise RuntimeError("expected 3 changes in the fixture, log shows %d" % seen)
        return path

    def blame(self, entity, extra=None):
        rc, out, err = self.kin_run(["blame", entity] + (extra or []))
        return out if rc == 0 else (out + err)

    def history(self, entity, extra=None):
        rc, out, err = self.kin_run(["history", entity] + (extra or []))
        return out if rc == 0 else (out + err)


# ---------------------------------------------------------------- checks

def check_blame_attribution(suite):
    status, detail = grade_attribution_is_per_entity(
        suite.blame("untouched_fn"), suite.blame("edited_fn"), REVISION_ROW)
    return ("blame_attribution", status, "%s %s" % (TICKET, detail))


def check_history_attribution(suite):
    status, detail = grade_attribution_is_per_entity(
        suite.history("untouched_fn"), suite.history("edited_fn"), HISTORY_ROW)
    return ("history_attribution", status, "%s %s" % (TICKET, detail))


def check_all_revisions_restores(suite):
    status, detail = grade_all_revisions_restores(
        suite.blame("untouched_fn"), suite.blame("untouched_fn", ["--all-revisions"]),
        REVISION_ROW)
    return ("all_revisions", status, "%s %s" % (TICKET, detail))


def check_surfaces_agree(suite):
    """blame and history must give the same answer for the same entity.

    They render differently and are two commands, but the question "which
    revisions are this entity's own" has one answer. Before the fix they agreed
    on the wrong number, which is why this is a check and not a comment: it goes
    red only if one surface is fixed and the other is not.
    """
    status, detail = grade_surfaces_agree(
        suite.blame("untouched_fn"), suite.history("untouched_fn"))
    return ("surfaces_agree", status, "%s %s" % (TICKET, detail))


CHECKS = (
    ("blame_attribution", check_blame_attribution),
    ("history_attribution", check_history_attribution),
    ("all_revisions", check_all_revisions_restores),
    ("surfaces_agree", check_surfaces_agree),
)


def report_payload(results):
    # `results`, because that is the key `gate.py:load_report` reads. Two suites
    # shipped `checks` here and the gate refused both reports whole.
    return {"ticket": TICKET,
            "results": [{"id": i, "status": s, "detail": d} for i, s, d in results]}


# ---------------------------------------------------------------- self-test

# Quoted from what the product printed on 2026-08-30, before and after, never
# invented: a grader driven only by text from the same hand cannot tell you what
# the product says.
def blame_listing(rows, withheld=0):
    out = "Blame for 'x' (Function, python) at abc:\n\nREVISION  CHANGE  TIMESTAMP  AUTHOR  MESSAGE\n"
    out += "-" * 40 + "\n"
    for i in range(rows):
        out += ("%064x  %064x  2026-08-30T00:00:00+00:00  a <a@b.invalid>  m%d\n" % (i + 1, i + 1, i))
    out += "\n%d version(s) found.\n" % rows
    if withheld:
        out += ("%d file-level revision%s did not change this entity; --all-revisions lists them\n"
                % (withheld, "" if withheld == 1 else "s"))
    return out


def history_listing(rows, withheld=0):
    out = "History for 'x' (Function, python) at abc:\n"
    for i in range(rows):
        out += "  %012x  2026-08-30  a  m%d\n" % (i + 1, i)
    if withheld:
        out += ("%d file-level revision%s did not change this entity; --all-revisions lists them\n"
                % (withheld, "" if withheld == 1 else "s"))
    return out


REFUSAL_500 = ("Error: daemon blame failed\n\nCaused by:\n    kin blame refused (HTTP 500): "
               "change not found: f008953ef2b403ca8b276afbc5bc1eeca574c8a3db6140b2b96367db18b5f032\n")
REFUSAL_409 = ("Error: daemon blame failed\n\nCaused by:\n    kin blame refused (HTTP 409): "
               "ref 'HEAD' resolves to semantic change d3cc227202431d65, which this daemon's live "
               "graph projection does not hold, so its history cannot be replayed; durable history "
               "is intact and `kin log` and `kin diff` still read it. Restart the repository "
               "daemon with `kin daemon stop` and run the command again. Underlying cause: "
               "change not found: c4176820f9fd320b\n")
# The old 400. Right status, and it names a remedy that does not clear the state.
REFUSAL_400_BAD_REMEDY = ("Error: daemon blame failed\n\nCaused by:\n    kin blame refused "
                          "(HTTP 400): cannot resolve ref 'HEAD': this repository's authority "
                          "resolves to semantic change 0c7f4d23, which the active graph projection "
                          "does not hold; run `kin status`, then `kin health` if it repeats\n")


def self_test():
    cases = []

    def add(name, got, want, detail=""):
        cases.append((name, got, want, detail))

    # attribution: the pre-fix shape, the post-fix shape, and the two ways a
    # partial fix could look right.
    for row_re, listing, label in ((REVISION_ROW, blame_listing, "blame"),
                                   (HISTORY_ROW, history_listing, "history")):
        add("%s/pre-fix" % label,
            grade_attribution_is_per_entity(listing(3), listing(3), row_re)[0], FAIL)
        add("%s/post-fix" % label,
            grade_attribution_is_per_entity(listing(1, 2), listing(3), row_re)[0], PASS)
        # The trap: a change that truncates EVERY listing. The untouched half
        # looks right and the edited one is now wrong.
        add("%s/truncates-everything" % label,
            grade_attribution_is_per_entity(listing(1, 2), listing(1, 2), row_re)[0], FAIL)
        # Trimmed but silent: no withheld line, so the reader loses information.
        add("%s/trims-silently" % label,
            grade_attribution_is_per_entity(listing(1), listing(3), row_re)[0], FAIL)
        add("%s/empty" % label,
            grade_attribution_is_per_entity("", listing(3), row_re)[0], UNREADABLE)

    add("all/restores", grade_all_revisions_restores(
        blame_listing(1, 2), blame_listing(3), REVISION_ROW)[0], PASS)
    add("all/does-nothing", grade_all_revisions_restores(
        blame_listing(1, 2), blame_listing(1, 2), REVISION_ROW)[0], FAIL)
    # Restores the wrong number: 1 + 2 must be 3, not 4.
    add("all/wrong-total", grade_all_revisions_restores(
        blame_listing(1, 2), blame_listing(4), REVISION_ROW)[0], FAIL)
    add("all/empty", grade_all_revisions_restores("", blame_listing(3), REVISION_ROW)[0],
        UNREADABLE)

    # The arm that proves surfaces_agree can fail: one surface fixed, the other
    # not, which is the only thing it exists to catch and which neither the
    # pre-fix nor the post-fix product exhibits.
    add("agree/one-surface-fixed",
        grade_surfaces_agree(blame_listing(1, 2), history_listing(3))[0], FAIL)
    add("agree/both-fixed", grade_surfaces_agree(blame_listing(1, 2), history_listing(1, 2))[0],
        PASS)
    add("agree/both-unfixed", grade_surfaces_agree(blame_listing(3), history_listing(3))[0], PASS)
    add("agree/empty", grade_surfaces_agree("", history_listing(3))[0], UNREADABLE)

    add("refusal/500", grade_unreadable_change_is_named(REFUSAL_500)[0], FAIL)
    add("refusal/409", grade_unreadable_change_is_named(REFUSAL_409)[0], PASS)
    add("refusal/bad-remedy", grade_unreadable_change_is_named(REFUSAL_400_BAD_REMEDY)[0], FAIL)
    add("refusal/no-failure", grade_unreadable_change_is_named(blame_listing(3))[0], UNREADABLE)

    failures = 0
    for name, got, want, _ in cases:
        ok = got == want
        failures += 0 if ok else 1
        print("SELFTEST %s %s expected=%s got=%s" % (name, "ok" if ok else "BROKEN", want, got))

    # The gate reads `results`. Import the real consumer rather than naming the
    # key a second time: a string written twice drifts the same way.
    import importlib.util
    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    if not os.path.exists(gate_path):
        print("SELFTEST gate/beside BROKEN gate.py is not beside this file")
        failures += 1
    else:
        spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        scratch = tempfile.mkdtemp(prefix="blame-attr-selftest-")
        try:
            good = os.path.join(scratch, "good.json")
            with open(good, "w") as handle:
                json.dump(report_payload([(i, UNREADABLE, "fabricated") for i, _ in CHECKS]),
                          handle)
            loaded = gate.load_report(good)
            ok = sorted(loaded) == sorted(i for i, _ in CHECKS)
            failures += 0 if ok else 1
            print("SELFTEST gate/reads-every-row %s" % ("ok" if ok else "BROKEN"))
            bad = os.path.join(scratch, "bad.json")
            with open(bad, "w") as handle:
                json.dump({"ticket": TICKET, "checks": [{"id": "x", "status": PASS}]}, handle)
            refused = False
            try:
                gate.load_report(bad)
            except Exception:  # noqa: BLE001 - refusing is the point
                refused = True
            failures += 0 if refused else 1
            print("SELFTEST gate/CONTROL-refuses-checks-shape %s" % ("ok" if refused else "BROKEN"))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    print("SELFTEST %d case(s), %d broken" % (len(cases) + 2, failures))
    return 1 if failures else 0


def absolute_binary(path):
    if not path:
        return None
    resolved = os.path.abspath(path)
    return resolved if os.path.exists(resolved) else path


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
    workdir = tempfile.mkdtemp(prefix="blame-attribution-")
    suite = Suite(opts.kin, workdir, daemon=opts.daemon, verbose=opts.verbose)
    results = []
    try:
        for ident, check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - setup failure is not a verdict
                results.append((ident, UNREADABLE, "%s check raised: %s" % (TICKET, error)))
        for ident, status, detail in results:
            print("CHECK %s %s %s %s" % (ident, TICKET, status, detail))
        if opts.json_path:
            directory = os.path.dirname(os.path.abspath(opts.json_path))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with open(opts.json_path, "w") as handle:
                json.dump(report_payload(results), handle, indent=2)
        asked = [i for i, _ in CHECKS]
        answered = [i for i, _, _ in results]
        if answered != asked:
            print("SETUP asked for %r and %r answered" % (asked, answered))
            return 3
        if any(s == FAIL for _, s, _ in results):
            return 1
        if any(s == UNREADABLE for _, s, _ in results):
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
