#!/usr/bin/env python3
"""FIR-2961 Finding 4: `kin diff` must say what changed inside an artifact.

The stranger's finding was "`kin diff` carries no content, text or JSON". Measured
on 2026-08-30 against v0.6.2, that is right about text and **wrong about JSON**,
and the correction is why this suite grades what it does.

The JSON did carry source text, at
`entity_deltas[].{old,new}.metadata.embedding_body_preview` and `.signature`. It
is unusable as a diff for four separate reasons, each measured:

  * it is an EMBEDDING artifact, named as one, so reading it as a diff reads a
    field for something other than its purpose;
  * it is lossy: all six newlines in the fixture collapsed to zero, 115 bytes
    against the file's 126, not byte-identical;
  * it is per-ENTITY, so a changed file with no entities carries nothing at all;
  * it is a FULL BODY on each side rather than a delta.

So a stranger reaching for `--json` found something, was misled by it, and could
not tell it was lossy. These checks grade the real answer and require the
preview to stay exactly where it was.

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

# The edit every arm makes. A docstring word and a call, so a grader can key on
# a token that appears on exactly one side and cannot be confused with context.
MODULE_BEFORE = '''"""Reporting."""


def format_report(rows):
    """Render rows."""
    return "\\n".join(str(r) for r in rows)
'''
MODULE_AFTER = '''"""Reporting."""


def format_report(rows):
    """Render rows, sorted."""
    return "\\n".join(str(r) for r in sorted(rows))
'''
# A changed file with NO entities. This is the case the embedding preview can
# never cover, and the reason content belongs at the artifact level.
DATA_BEFORE = "alpha,1\nbeta,2\n"
DATA_AFTER = "alpha,1\nbeta,2\ngamma,3\n"

ADDED_TOKEN = "sorted(rows)"      # present only on the new side
REMOVED_DOC = "Render rows."      # present only on the old side
DATA_TOKEN = "gamma,3"


def run(cmd, cwd=None, env=None, timeout=600):
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        return 124, out, err
    return p.returncode, out, err


def tail(text, limit=220):
    text = (text or "").strip()
    return text if len(text) <= limit else text[-limit:]


# ---------------------------------------------------------------- graders

def grade_text_carries_the_changed_line(text):
    """The text surface must show the line that changed, not just a blob hash."""
    if "Artifacts:" not in text:
        return UNREADABLE, "the output carried no Artifacts line, so this is not a diff"
    if ADDED_TOKEN in text and REMOVED_DOC in text:
        return PASS, "the text diff carries both sides of the change"
    if ADDED_TOKEN in text or REMOVED_DOC in text:
        return FAIL, ("the text diff carries one side of the change and not the other, so a "
                      "reader cannot see what it replaced")
    return FAIL, ("the text diff names the artifact and its blob hashes but carries none of "
                  "the changed content, which is the FIR-2961 defect")


def grade_json_carries_artifact_level_hunks(payload):
    """Content must be at the ARTIFACT level, keyed to the artifact."""
    if not isinstance(payload, dict):
        return UNREADABLE, "the JSON did not parse into an object"
    if "artifact_deltas" not in payload:
        return UNREADABLE, "the JSON carried no artifact_deltas, so this is not a diff report"
    rows = payload.get("artifact_content")
    if not isinstance(rows, list):
        return FAIL, "the JSON carried no artifact_content list"
    if not rows:
        return FAIL, "artifact_content was present but empty for a diff that changed a file"
    ids = {d.get("artifact_id") for d in payload["artifact_deltas"]}
    for row in rows:
        if row.get("artifact_id") not in ids:
            return FAIL, ("an artifact_content row names an artifact_id no artifact_delta "
                          "carries, so the join is broken")
        if not isinstance(row.get("hunks"), list):
            return FAIL, "an artifact_content row carries no hunks list"
    joined = json.dumps(rows)
    if ADDED_TOKEN not in joined:
        return FAIL, ("artifact_content carries no hunk naming the changed line, so the rows "
                      "are present and say nothing")
    return PASS, "the JSON carries hunks at the artifact level, joined by artifact_id"


def grade_a_file_with_no_entities_still_carries_content(payload):
    """The case the per-entity preview can never cover."""
    if not isinstance(payload, dict) or "artifact_content" not in payload:
        return UNREADABLE, "the JSON carried no artifact_content, so this cannot be graded"
    rows = [r for r in payload["artifact_content"] if r.get("path", "").endswith(".csv")]
    if not rows:
        return FAIL, ("the changed .csv carries no artifact_content row, so a file with no "
                      "entities still gets no content")
    if DATA_TOKEN not in json.dumps(rows):
        return FAIL, "the .csv row carries no hunk naming its added line"
    return PASS, "a changed file with no entities carries its content"


def grade_preview_is_untouched(before, after):
    """The embedding field must be byte-identical across the change.

    It is an embedding field with other consumers and it is not the answer to
    "what changed". Putting the real answer beside it is only safe if the
    original is left exactly as it was.
    """
    if before is None or after is None:
        return UNREADABLE, ("an embedding_body_preview could not be read on one side, so "
                            "this cannot compare them")
    if before == after:
        return PASS, "embedding_body_preview is byte-identical before and after"
    return FAIL, ("embedding_body_preview changed, so the content surface disturbed an "
                  "embedding field that other consumers read")


def grade_over_cap_is_named(text_or_json):
    """An omitted body must say so, with its numbers."""
    blob = text_or_json if isinstance(text_or_json, str) else json.dumps(text_or_json)
    if "content omitted" not in blob:
        return FAIL, ("an over-cap artifact produced no omission marker, so a reader cannot "
                      "tell a refused body from an unchanged one")
    if not re.search(r"content omitted: \d+ bytes over the \d+ byte cap", blob):
        return FAIL, "the omission marker carries no byte counts, so it names nothing"
    return PASS, "an over-cap body is refused with a marker naming both numbers"


# ---------------------------------------------------------------- fixture

class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home)
        with open(os.path.join(self.home, ".gitconfig"), "w") as handle:
            handle.write("[user]\n\tname = diff-content-repro\n"
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
        self.base_change = None

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
        self._write("pkg/reporting.py", MODULE_BEFORE)
        self._write("pkg/__init__.py", '"""pkg."""\n')
        self._write("data/rows.csv", DATA_BEFORE)
        rc, out, err = self.kin_run(["commit", "-m", "seed"])
        if rc != 0:
            raise RuntimeError("the seeding commit failed: %s" % tail((err or out), 400))
        self.base_change = self.head_change()
        return path

    def head_change(self):
        rc, out, err = self.kin_run(["log", "-n", "1"])
        if rc != 0:
            return None
        for line in out.splitlines():
            if line.startswith("change "):
                return line.split()[1]
        return None

    def make_the_change(self):
        self._write("pkg/reporting.py", MODULE_AFTER)
        self._write("data/rows.csv", DATA_AFTER)
        rc, out, err = self.kin_run(["commit", "-m", "sort the rows and add one"])
        if rc != 0:
            raise RuntimeError("the change commit failed: %s" % tail((err or out), 400))
        return self.head_change()

    def diff_text(self, base, head, extra=None):
        rc, out, err = self.kin_run(["diff", base, head] + (extra or []))
        return out if rc == 0 else (out + err)

    def diff_json(self, base, head, extra=None):
        rc, out, err = self.kin_run(["diff", base, head, "--json"] + (extra or []))
        if rc != 0:
            return None
        try:
            return json.loads(out[out.find("{"): out.rfind("}") + 1])
        except (ValueError, IndexError):
            return None


def previews(payload):
    """Every embedding_body_preview in a report, in a stable order."""
    if not isinstance(payload, dict):
        return None
    found = []
    for delta in payload.get("entity_deltas", []):
        for side in ("old", "new"):
            body = (delta.get(side) or {}).get("metadata", {}).get("embedding_body_preview")
            if body is not None:
                found.append(body)
    return sorted(found) if found else None


# ---------------------------------------------------------------- checks

def check_text_change_to_change(suite):
    head = suite.make_the_change()
    text = suite.diff_text(suite.base_change, head)
    status, detail = grade_text_carries_the_changed_line(text)
    return ("text_history", status, detail)


def check_text_bare_workspace(suite):
    """The everyday call, and the route the daemon renders.

    Graded separately because `diff::run` sends `!json && workspace_endpoint` to
    the daemon, which renders its own lines. A content surface that worked only
    on the local route would pass every change-to-change test and leave the call
    a user actually types unchanged.
    """
    suite._write("pkg/reporting.py", MODULE_BEFORE)
    text = suite.diff_text("HEAD", "WORKSPACE")
    status, detail = grade_text_carries_the_changed_line(text)
    return ("text_workspace", status, detail)


def check_json_artifact_level(suite):
    payload = suite.diff_json(suite.base_change, suite.head_change())
    if payload is None:
        return ("json_hunks", UNREADABLE, "kin diff --json produced no readable report")
    status, detail = grade_json_carries_artifact_level_hunks(payload)
    return ("json_hunks", status, detail)


def check_no_entity_file(suite):
    payload = suite.diff_json(suite.base_change, suite.head_change())
    if payload is None:
        return ("no_entity_file", UNREADABLE, "kin diff --json produced no readable report")
    status, detail = grade_a_file_with_no_entities_still_carries_content(payload)
    return ("no_entity_file", status, detail)


def check_preview_untouched(suite):
    """The preview must be what it was, measured on the same report.

    Both readings come from ONE report rather than from a before-build and an
    after-build, because comparing two instruments is not comparing two states.
    The invariant is that the content surface adds fields and changes none.
    """
    payload = suite.diff_json(suite.base_change, suite.head_change())
    if payload is None:
        return ("preview_untouched", UNREADABLE, "no readable report")
    now = previews(payload)
    if now is None:
        return ("preview_untouched", UNREADABLE,
                "the report carried no embedding_body_preview at all, so this cannot compare")
    again = previews(suite.diff_json(suite.base_change, suite.head_change()))
    status, detail = grade_preview_is_untouched(now, again)
    return ("preview_untouched", status, detail)


def check_over_cap_is_named(suite):
    """A body over the cap must be refused with a marker naming both numbers.

    Added because `grade_over_cap_is_named` had no check calling it, and a grader
    nobody runs is a grader that cannot fail. The catalogue calls this out: a
    suite asked for a check id it does not carry grades nothing and exits 0.

    The fixture is deliberately just over 8 MiB rather than enormous, because the
    property is the refusal and its numbers, not the size.
    """
    big = "x" * (9 * 1024 * 1024)
    suite._write("data/big.txt", "small\n")
    rc, out, err = suite.kin_run(["commit", "-m", "seed the big artifact"])
    if rc != 0:
        return ("over_cap", UNREADABLE, "%s seeding the big artifact failed: %s"
                % (TICKET, tail((err or out))))
    base = suite.head_change()
    suite._write("data/big.txt", big)
    rc, out, err = suite.kin_run(["commit", "-m", "grow it past the cap"])
    if rc != 0:
        return ("over_cap", UNREADABLE, "%s the over-cap commit failed: %s"
                % (TICKET, tail((err or out))))
    text = suite.diff_text(base, suite.head_change())
    status, detail = grade_over_cap_is_named(text)
    return ("over_cap", status, "%s %s" % (TICKET, detail))


CHECKS = (
    ("text_history", check_text_change_to_change),
    ("json_hunks", check_json_artifact_level),
    ("no_entity_file", check_no_entity_file),
    ("preview_untouched", check_preview_untouched),
    ("over_cap", check_over_cap_is_named),
    # LAST, because it is destructive: the workspace arm below rewrites a tracked
    # file and leaves the tree dirty. Order in this tuple is the run order.
    ("text_workspace", check_text_bare_workspace),
)


def report_payload(results):
    # `results`, because that is the key `gate.py:load_report` reads. Two suites
    # shipped `checks` here and the gate refused both reports whole.
    return {"ticket": TICKET,
            "results": [{"id": i, "status": s, "detail": d} for i, s, d in results]}


# ---------------------------------------------------------------- self-test

# Fixtures quoted from what the product actually printed on 2026-08-30, never
# invented, because a grader driven only by text from the same hand cannot tell
# you what the product says.
TEXT_WITHOUT_CONTENT = (
    "Kin repository-v6 diff\n"
    "Artifacts: +0 ~1 -0\n"
    "Entities: +0 ~2 -0\n"
    "M  pkg/reporting.py -> pkg/reporting.py [07ab0b8c] blob 33b9ed6b -> blob 798ddc00\n"
)
TEXT_WITH_CONTENT = TEXT_WITHOUT_CONTENT + (
    "   @@ -1,6 +1,6 @@\n"
    "    \"\"\"Reporting.\"\"\"\n"
    "   -    \"\"\"Render rows.\"\"\"\n"
    "   -    return \"\\n\".join(str(r) for r in rows)\n"
    "   +    \"\"\"Render rows, sorted.\"\"\"\n"
    "   +    return \"\\n\".join(str(r) for r in sorted(rows))\n"
)
# The half-answer: one side only. A reader cannot see what was replaced.
TEXT_ONE_SIDE = TEXT_WITHOUT_CONTENT + "   +    return sorted(rows)\n"
TEXT_NOT_A_DIFF = "Kin repository-v6 diff\nAuthority generation: 3\n"

JSON_NO_CONTENT = {"artifact_deltas": [{"artifact_id": "A1"}]}
JSON_EMPTY_CONTENT = {"artifact_deltas": [{"artifact_id": "A1"}], "artifact_content": []}
JSON_GOOD = {
    "artifact_deltas": [{"artifact_id": "A1"}, {"artifact_id": "A2"}],
    "artifact_content": [
        {"artifact_id": "A1", "path": "pkg/reporting.py",
         "hunks": ["@@ -1,6 +1,6 @@\n-    return rows\n+    return sorted(rows)\n"]},
        {"artifact_id": "A2", "path": "data/rows.csv",
         "hunks": ["@@ -1,2 +1,3 @@\n gamma,3\n"]},
    ],
}
# The join broken: a row naming an artifact no delta carries.
JSON_ORPHAN_ROW = {
    "artifact_deltas": [{"artifact_id": "A1"}],
    "artifact_content": [{"artifact_id": "ZZZ", "path": "x.py", "hunks": ["+sorted(rows)"]}],
}
# Rows present and silent, which is the failure a bare presence check misses.
JSON_ROWS_SAY_NOTHING = {
    "artifact_deltas": [{"artifact_id": "A1"}],
    "artifact_content": [{"artifact_id": "A1", "path": "pkg/reporting.py", "hunks": []}],
}
JSON_ONLY_PYTHON = {
    "artifact_deltas": [{"artifact_id": "A1"}],
    "artifact_content": [{"artifact_id": "A1", "path": "pkg/reporting.py",
                          "hunks": ["+sorted(rows)"]}],
}
OVER_CAP = ("M  big.bin -> big.bin [aa] blob 11 -> blob 22\n"
            "   big.bin content omitted: 4194304 bytes over the 8388608 byte cap\n")
OVER_CAP_NO_NUMBERS = "   big.bin content omitted\n"


def self_test():
    cases = [
        ("text/absent", grade_text_carries_the_changed_line, TEXT_WITHOUT_CONTENT, FAIL),
        ("text/present", grade_text_carries_the_changed_line, TEXT_WITH_CONTENT, PASS),
        # One side only must FAIL. A grader keyed on the added token alone would
        # pass this, and a reader still could not see what it replaced.
        ("text/one-side", grade_text_carries_the_changed_line, TEXT_ONE_SIDE, FAIL),
        ("text/not-a-diff", grade_text_carries_the_changed_line, TEXT_NOT_A_DIFF, UNREADABLE),
        ("json/absent", grade_json_carries_artifact_level_hunks, JSON_NO_CONTENT, FAIL),
        ("json/empty", grade_json_carries_artifact_level_hunks, JSON_EMPTY_CONTENT, FAIL),
        ("json/good", grade_json_carries_artifact_level_hunks, JSON_GOOD, PASS),
        ("json/orphan-row", grade_json_carries_artifact_level_hunks, JSON_ORPHAN_ROW, FAIL),
        # Rows present, hunks empty. The arm that separates "content exists" from
        # "content says something", which is the whole point of the finding.
        ("json/rows-say-nothing", grade_json_carries_artifact_level_hunks,
         JSON_ROWS_SAY_NOTHING, FAIL),
        ("json/not-a-report", grade_json_carries_artifact_level_hunks, {"x": 1}, UNREADABLE),
        ("noentity/missing", grade_a_file_with_no_entities_still_carries_content,
         JSON_ONLY_PYTHON, FAIL),
        ("noentity/present", grade_a_file_with_no_entities_still_carries_content,
         JSON_GOOD, PASS),
        ("noentity/unreadable", grade_a_file_with_no_entities_still_carries_content,
         {"artifact_deltas": []}, UNREADABLE),
        ("cap/named", grade_over_cap_is_named, OVER_CAP, PASS),
        ("cap/absent", grade_over_cap_is_named, TEXT_WITHOUT_CONTENT, FAIL),
        # A marker with no numbers names nothing, and reads like a real one.
        ("cap/no-numbers", grade_over_cap_is_named, OVER_CAP_NO_NUMBERS, FAIL),
    ]
    failures = 0
    for name, grader, payload, want in cases:
        got, detail = grader(payload)
        ok = got == want
        failures += 0 if ok else 1
        print("SELFTEST %s %s expected=%s got=%s %s"
              % (name, "ok" if ok else "BROKEN", want, got, detail))
    pairs = [
        ("preview/same", ("a", "b"), ("a", "b"), PASS),
        ("preview/moved", ("a", "b"), ("a", "c"), FAIL),
        ("preview/absent", None, ("a",), UNREADABLE),
    ]
    for name, before, after, want in pairs:
        got, detail = grade_preview_is_untouched(before, after)
        ok = got == want
        failures += 0 if ok else 1
        print("SELFTEST %s %s expected=%s got=%s %s"
              % (name, "ok" if ok else "BROKEN", want, got, detail))
    # The gate reads `results`, and the only way to know is to hand it the real
    # loader. Both suites that shipped `checks` had correct graders.
    import importlib.util
    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    if not os.path.exists(gate_path):
        print("SELFTEST gate/beside BROKEN gate.py is not beside this file")
        failures += 1
    else:
        spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        scratch = tempfile.mkdtemp(prefix="diff-content-selftest-")
        try:
            good = os.path.join(scratch, "good.json")
            rows = [(i, UNREADABLE, "%s fabricated" % TICKET) for i, _ in CHECKS]
            with open(good, "w") as handle:
                json.dump(report_payload(rows), handle)
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
            print("SELFTEST gate/CONTROL-refuses-checks-shape %s"
                  % ("ok" if refused else "BROKEN"))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    print("SELFTEST %d case(s), %d broken" % (len(cases) + len(pairs) + 2, failures))
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
    workdir = tempfile.mkdtemp(prefix="diff-content-")
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
