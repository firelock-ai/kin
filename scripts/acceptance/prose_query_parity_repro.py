#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""One English question, two daemon states, one answer required.

FIR-2918. `kin locate` has no daemonless arm: `capture` refuses
`KIN_LOCATE_FORCE_LOCAL` outright and every query goes to `POST /locate` on a
daemon, auto-starting one when none is up. So the two readings this ticket was
filed on are not two code paths. They are one path against two daemon states,
and the discriminator is which daemon process answers.

`kin init` stops the daemon its conversion phase started unless it borrowed a
live one (`stop_conversion_daemon` in crates/kin-cli/src/commands/init.rs), so
the long-lived process here is the one the first `kin commit` auto-starts, and it
stays up through every later commit. That is the daemon a stranger's first
English question reaches. The other state is a daemon opened after the content
already exists, which is what `kin daemon stop` plus one more command produces.

That distinction is the whole finding. If a prose-only term retrieves nothing
through the daemon that was live while the code was ingested, and retrieves its
file through one opened afterwards, the product told a stranger their code does
not mention something it does mention, and said nothing about why.

Two checks, and the second is underneath the first.

  `prose_parity` asks the behaviour question. One term that lives only in a
  docstring, asked through both daemon states, has to come back with the same
  files. Two controls decide whether the arm graded anything at all: a symbol
  the fixture defines must retrieve in both states, or the fixture was never
  ingested and an agreement at zero is agreement about nothing; and a fabricated
  term must retrieve in neither, or the row counter is counting something other
  than rows.

  `lexical_index_parity` asks the mechanism question the behaviour rests on.
  `kin support --json` is served by the daemon out of its own live graph, so
  `text_indexed_entity_count` is what the process answering the query can
  actually see. It is read after that daemon has answered, because the question
  is what the process serving queries holds, not what it held before anything
  asked it anything. Both daemon states must report the derived text index
  carrying documents, and the check reports both numbers whatever it decides,
  because a number in a detail line is evidence and a verdict alone is not.

Output shape matches the siblings:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit codes match too: 0 when every check graded, 3 when the suite could not
start. The verdict belongs to `scripts/acceptance/gate.py`, which reads the
`--json` report rather than the exit code.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

TICKET = "FIR-2918"
PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# The three queries, and only the first is the subject.
#
# `socket` appears in this fixture exactly once, in `pkg/overview.py`'s module
# docstring, and no module here defines a symbol by that name. So it can only be
# answered from the derived text index over graph-owned prose, which is the
# surface this ticket is about.
PROSE_QUERY = "socket"
# The positive control. `describe_layers` is defined in the same file the prose
# query should retrieve, and entity resolution answers it without the text index
# at all. A run where this returns nothing has not ingested the fixture, so the
# prose arm's zero would measure the fixture rather than the product.
SYMBOL_QUERY = "describe_layers"
# The negative control. Nothing in this fixture carries these letters. It must
# retrieve nothing in both daemon states, or `locate_paths` is reading something
# that is not a result row.
ABSENT_QUERY = "zzqxnotawordanywhere"

# How long to wait for the daemon `kin init` left to be answering before the
# first arm reads it. The daemon's own background persistence flushes on an
# idle interval (KIN_DAEMON_IDLE_FLUSH_SECS, default 2s) and a periodic one
# (KIN_DAEMON_PERIODIC_FLUSH_SECS, default 30s), so a wait comfortably past both
# means arm A is not measuring a race the product would win on its own a moment
# later. If the divergence survives this wait it is a state the product stays
# in, not a window it passes through.
SETTLE_SECONDS = int(os.environ.get("KIN_PROSE_PARITY_SETTLE_SECS", "40"))


print_ = print


def strip_ansi(text):
    return ANSI.sub("", text or "")


def tail(text, limit=400):
    text = strip_ansi(text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


# ------------------------------------------------------------------- fixture
#
# The `_build_answersurface` shape from scripts/acceptance/magic_repro.py, in its
# own copy so a change to check 24's fixture cannot silently move this suite's
# subject. `OVERVIEW_PY` is byte-identical to that file's, because the prose
# query is chosen against its exact words.

PARSING_PY = '''import re

LINK = re.compile(r"\\[\\[([^\\]]+)\\]\\]")


def normalize_title(raw):
    return raw.strip().lower().replace(" ", "-")


def parse_note(text):
    return {"links": [normalize_title(m) for m in LINK.findall(text)]}
'''

STORAGE_PY = '''from .parsing import parse_note


class Database:
    def __init__(self, path):
        self.path = path
        self.notes = {}

    def ingest_dir(self, files):
        for path, text in files.items():
            self.notes[path] = parse_note(text)

    def all_notes(self):
        return [dict(note, path=path) for path, note in self.notes.items()]
'''

LINKGRAPH_PY = '''from .parsing import normalize_title


class LinkGraph:
    def __init__(self, edges):
        self.edges = edges

    @classmethod
    def from_db(cls, db):
        edges = {}
        for note in db.all_notes():
            edges[normalize_title(note["path"])] = [normalize_title(link)
                                                    for link in note["links"]]
        return cls(edges)

    def backlinks(self, title):
        return [src for src, dsts in self.edges.items() if title in dsts]
'''

# `socket`, `server`, `network` and `deployment` appear here and nowhere else in
# this fixture, and this module defines no symbol by any of those names.
OVERVIEW_PY = '''"""How this package fits together, for a reader arriving cold.

The reading layer turns raw text into records, the holding layer keeps those
records in memory, and the traversal layer walks between them.

Nothing here opens a socket or speaks to a server over the network, so there is
no deployment step and nothing to keep running between calls.
"""


def describe_layers():
    return "reading, holding, traversal"
'''

# The file the prose query must retrieve, named once so a fixture rename cannot
# leave the assertion pointing at nothing.
PROSE_FILE = "pkg/overview.py"


# ------------------------------------------------------------------- graders
#
# Pure, so `--self-test` can falsify each one with no daemon, no repository and
# no binary. Every grader below is called from `self_test` with an input that
# must pass and an input that must fail.


def locate_paths(payload):
    """The file paths a `kin locate --json` payload ranked, or None.

    None means the payload could not be read, which is UNREADABLE and never
    zero. An absent `files` key and an empty one are different facts: the first
    says the response was not a locate result, the second says locate ranked
    nothing.
    """
    if not isinstance(payload, dict):
        return None
    files = payload.get("files")
    if not isinstance(files, list):
        return None
    paths = []
    for row in files:
        if not isinstance(row, dict):
            return None
        path = row.get("path")
        if not isinstance(path, str) or not path:
            return None
        paths.append(path)
    return paths


def text_index_gap_reported(payload):
    """Does this answer name a derived-text-index gap, in the ledger locate owns?

    `RetrievalDegradation` is the no-silent-degradation channel: the daemon logs
    every entry at WARN and the human surface renders it as a coverage note. An
    answer that could not read the lexical index has to appear here, because the
    alternative is `No relevant files found.` with nothing said.
    """
    if not isinstance(payload, dict):
        return False
    degradations = payload.get("degradations")
    if not isinstance(degradations, list):
        return False
    for entry in degradations:
        if isinstance(entry, dict) and entry.get("component") == "text_index":
            return True
    return False


def support_text_indexed(payload):
    """`text_indexed_entity_count` from a `kin support --json` payload, or None.

    None for a payload that does not carry the field or carries a non-count, so
    an unreadable support response is UNREADABLE rather than a zero that reads
    like a real measurement of an empty index. A bool is not a count: Python
    would otherwise accept True as 1.
    """
    if not isinstance(payload, dict):
        return None
    value = payload.get("text_indexed_entity_count")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def support_total_entities(payload):
    if not isinstance(payload, dict):
        return None
    value = payload.get("total_entities")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def paths_agree(left, right):
    """Do two arms name the same files, order aside?

    Order is a ranking decision and can legitimately differ under different
    daemon warmth. Membership cannot: a file one daemon state can retrieve and
    the other cannot is the defect.
    """
    if left is None or right is None:
        return False
    return sorted(set(left)) == sorted(set(right))


# ---------------------------------------------------------------- result type


class Result(object):
    def __init__(self, check_id, title):
        self.id = check_id
        self.title = title
        self.asserts = []

    def ok(self, detail):
        self.asserts.append({"status": PASS, "detail": detail})

    def bad(self, detail):
        self.asserts.append({"status": FAIL, "detail": detail})

    def unknown(self, detail):
        self.asserts.append({"status": UNREADABLE, "detail": detail})

    @property
    def status(self):
        graded = [a for a in self.asserts if a["status"] in (PASS, FAIL, UNREADABLE)]
        if any(a["status"] == FAIL for a in graded):
            return FAIL
        if any(a["status"] == UNREADABLE for a in graded):
            return UNREADABLE
        if not graded:
            return UNREADABLE
        return PASS

    @property
    def detail(self):
        for wanted in (FAIL, UNREADABLE):
            for a in self.asserts:
                if a["status"] == wanted:
                    return a["detail"]
        graded = [a["detail"] for a in self.asserts if a["status"] == PASS]
        return "; ".join(graded) if graded else "no assertion was reached"


class ProbeError(RuntimeError):
    """The probe could not produce a reading. UNREADABLE, never FAIL."""


# ------------------------------------------------------------------- the suite


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.daemon = daemon
        self.verbose = verbose
        self.repo = os.path.join(workdir, "repo")
        home = os.path.join(workdir, "home")
        os.makedirs(home, exist_ok=True)
        # kin refuses to invent an author, which is correct product behaviour and
        # not an obstacle. This suite isolates HOME so it cannot read the
        # machine's identity, so it brings one of its own; measured without it,
        # the first `kin commit` exits 1 on "kin has no author identity to record
        # for this change" and the whole suite grades nothing.
        with open(os.path.join(home, ".gitconfig"), "w") as handle:
            handle.write("[user]\n\tname = kin-prose-parity-repro\n"
                         "\temail = prose-parity@example.invalid\n"
                         "[commit]\n\tgpgsign = false\n")
        self.env = dict(os.environ)
        # Scratch HOME, KIN_HOME and registry, so this suite can never touch a
        # developer's real store and two concurrent runs cannot share one.
        self.env["HOME"] = home
        self.env["USERPROFILE"] = home
        self.env["KIN_HOME"] = os.path.join(workdir, "kin-home")
        self.env["KIN_REGISTRY_PATH"] = os.path.join(home, "registry.toml")
        # No vector index, like every sibling here. That is deliberate: with no
        # embeddings, retrieval for a prose term is lexical and graph only, so
        # the arm cannot be answered by a semantic signal standing in for the
        # text index this check is about.
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        # A CLI-autostarted daemon idles out after 60s by default. Without this,
        # the settle below would let the long-lived daemon exit and the first arm
        # would silently read a REPLACEMENT daemon, which is the one state where
        # this whole suite passes for the wrong reason. Held open well past the
        # settle, and the pid is asserted either way.
        self.env["KIN_DAEMON_IDLE_TIMEOUT_SECS"] = "900"
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DAEMON_URL", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        for path in (self.env["KIN_HOME"], self.repo):
            os.makedirs(path, exist_ok=True)
        self._arms = None
        self._setup_error = None

    # ------------------------------------------------------------- plumbing

    def run(self, args, timeout=900):
        proc = subprocess.run(
            [self.kin] + args,
            cwd=self.repo,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        out = strip_ansi(proc.stdout)
        err = strip_ansi(proc.stderr)
        if self.verbose:
            sys.stderr.write("$ kin %s\n%s\n%s\n" % (" ".join(args), tail(out, 1200), tail(err, 800)))
        return proc.returncode, out, err

    def git(self, args):
        base = ["git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=prose-parity@example.invalid",
                "-c", "user.name=kin-prose-parity-repro",
                "-c", "commit.gpgsign=false",
                "-c", "core.fsmonitor=false"]
        proc = subprocess.run(base + args, cwd=self.repo, env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=300, text=True)
        return proc.returncode, strip_ansi(proc.stdout)

    def write(self, rel, text):
        full = os.path.join(self.repo, rel)
        parent = os.path.dirname(full)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(full, "w") as handle:
            handle.write(text)

    # -------------------------------------------------------------- fixture

    def build(self):
        rc, out = self.git(["init", "-q", "."])
        if rc != 0:
            raise ProbeError("git init failed: %s" % tail(out))
        self.write(".gitignore", "*.db\n__pycache__/\n")
        self.write("pyproject.toml",
                   '[project]\nname = "nk"\nversion = "0.1.0"\n\n'
                   '[project.scripts]\nnk = "pkg.cli:main"\n')
        self.write("pkg/__init__.py", "")
        self.write("pkg/parsing.py", PARSING_PY)
        rc, out, err = self.run(["init", "."])
        if rc != 0:
            raise ProbeError("kin init exited %d: %s" % (rc, tail(err or out)))
        for rel, body, message in (
                (None, None, "Add parsing module"),
                ("pkg/storage.py", STORAGE_PY, "Add storage module"),
                ("pkg/linkgraph.py", LINKGRAPH_PY, "Add link graph module"),
                (PROSE_FILE, OVERVIEW_PY, "Add the package overview")):
            if rel:
                self.write(rel, body)
            rc, out, err = self.run(["commit", "-m", message])
            if rc != 0:
                raise ProbeError("kin commit %r exited %d: %s"
                                 % (message, rc, tail(err or out)))

    # --------------------------------------------------------------- probes

    def locate_json(self, query):
        rc, out, err = self.run(["locate", "--json", query])
        if rc != 0:
            raise ProbeError("kin locate --json %r exited %d: %s"
                             % (query, rc, tail(err or out)))
        try:
            return json.loads(out)
        except ValueError:
            raise ProbeError("kin locate --json %r did not emit JSON: %s"
                             % (query, tail(out, 200)))

    def support_json(self):
        rc, out, err = self.run(["support", "--json"])
        if rc != 0:
            raise ProbeError("kin support --json exited %d: %s" % (rc, tail(err or out)))
        try:
            return json.loads(out)
        except ValueError:
            raise ProbeError("kin support --json did not emit JSON: %s" % tail(out, 200))

    def daemon_pid(self):
        """The pid of the daemon serving this repository, or None.

        Read from `kin daemon status --json`'s `current_repo.pid` rather than
        parsed out of prose, and used to prove WHICH process answered an arm.
        The whole finding is about a difference between two daemon processes, so
        an arm that cannot name its own daemon has not measured one.
        """
        rc, out, err = self.run(["daemon", "status", "--json"], timeout=300)
        if rc != 0:
            raise ProbeError("kin daemon status --json exited %d: %s" % (rc, tail(err or out)))
        try:
            payload = json.loads(out)
        except ValueError:
            raise ProbeError("kin daemon status --json did not emit JSON: %s" % tail(out, 200))
        current = payload.get("current_repo")
        if not isinstance(current, dict):
            return None
        pid = current.get("pid")
        return pid if isinstance(pid, int) else None

    def read_arm(self, label):
        """One daemon state: which process, what it answered, what it then held.

        The support read comes AFTER the queries on purpose. The question check 2
        asks is whether the daemon that just answered holds a populated lexical
        index, not what it held before anything asked it anything, and reading it
        first would grade a moment no caller ever observes.
        """
        arm = {"label": label, "answers": {}}
        for query in (PROSE_QUERY, SYMBOL_QUERY, ABSENT_QUERY):
            arm["answers"][query] = self.locate_json(query)
        # After the queries, for two reasons. `kin daemon status` reads recorded
        # endpoints and starts nothing, so on the arm that follows
        # `kin daemon stop` there is no daemon to name until a query has started
        # one; and reading it here reports the process that actually answered
        # rather than one that could have been replaced since.
        arm["pid"] = self.daemon_pid()
        arm["support"] = self.support_json()
        return arm

    def arms(self):
        """Both daemon states, read once and shared by every check.

        Built lazily and cached: rebuilding the fixture per check would give each
        one a different daemon and make a disagreement between checks impossible
        to attribute.
        """
        if self._setup_error:
            raise ProbeError(self._setup_error)
        if self._arms is not None:
            return self._arms
        try:
            self.build()
            # The daemon the fixture was ingested through, named before the
            # settle so the arm below can prove it is the same process.
            born = self.daemon_pid()
            # Past both flush intervals, so a divergence here is a state and not
            # a race the daemon closes on its own a second later.
            time.sleep(SETTLE_SECONDS)
            warm = self.read_arm("the daemon that was live while the fixture was ingested")
            if born is None or warm["pid"] is None or born != warm["pid"]:
                raise ProbeError(
                    "the daemon serving this repository changed from pid %r to pid %r across "
                    "the %ds settle, so the first arm is a replacement daemon and this run "
                    "cannot grade the state the ticket is about"
                    % (born, warm["pid"], SETTLE_SECONDS))
            rc, out, err = self.run(["daemon", "stop"])
            if rc != 0:
                raise ProbeError("kin daemon stop exited %d: %s" % (rc, tail(err or out)))
            cold = self.read_arm("a daemon opened after the fixture already existed")
            if cold["pid"] is None or cold["pid"] == warm["pid"]:
                raise ProbeError(
                    "the second arm is served by pid %r, the same process as the first, so "
                    "`kin daemon stop` did not replace the daemon and the two arms are one "
                    "reading" % (cold["pid"],))
        except ProbeError as error:
            self._setup_error = str(error)
            raise
        self._arms = (warm, cold)
        return self._arms

    def stop_daemon(self):
        try:
            self.run(["daemon", "stop"], timeout=120)
        except Exception:  # noqa: BLE001 - teardown must never mask a verdict
            pass


# -------------------------------------------------------------------- checks


def check_prose_parity(suite):
    """One docstring-only term, asked through both daemon states.

    The rule is agreement or a named gap. Two daemon states that retrieve
    different files for one query mean the product's answer depends on which
    process happens to be up, and a caller has no way to know which reading it
    got. If an arm genuinely cannot read the lexical index, that is allowed, but
    it has to say so through the degradation ledger rather than answer thin.
    """
    res = Result("1", "a prose-only query answers the same through both daemon states")
    warm, cold = suite.arms()
    res.ok("two daemon processes answered: pid %s is %s, pid %s is %s"
           % (warm["pid"], warm["label"], cold["pid"], cold["label"]))

    warm_symbol = locate_paths(warm["answers"][SYMBOL_QUERY])
    cold_symbol = locate_paths(cold["answers"][SYMBOL_QUERY])
    if warm_symbol is None or cold_symbol is None:
        res.unknown("the symbol control produced an unreadable locate payload, so nothing "
                    "below can be attributed to the product")
        return res
    if not warm_symbol or not cold_symbol:
        res.unknown("the symbol control %r retrieved nothing (warm %d rows, cold %d rows), so "
                    "the fixture was not ingested and an agreement at zero would be agreement "
                    "about nothing" % (SYMBOL_QUERY, len(warm_symbol), len(cold_symbol)))
        return res

    warm_absent = locate_paths(warm["answers"][ABSENT_QUERY])
    cold_absent = locate_paths(cold["answers"][ABSENT_QUERY])
    if warm_absent is None or cold_absent is None:
        res.unknown("the absent control produced an unreadable locate payload")
        return res
    if warm_absent or cold_absent:
        res.unknown("the fabricated term %r retrieved %d and %d rows, so the row reader is "
                    "counting something other than results and no verdict below is safe"
                    % (ABSENT_QUERY, len(warm_absent), len(cold_absent)))
        return res
    res.ok("controls held: %r retrieved %d and %d rows, %r retrieved none in either state"
           % (SYMBOL_QUERY, len(warm_symbol), len(cold_symbol), ABSENT_QUERY))

    warm_prose = locate_paths(warm["answers"][PROSE_QUERY])
    cold_prose = locate_paths(cold["answers"][PROSE_QUERY])
    if warm_prose is None or cold_prose is None:
        res.unknown("the prose query produced an unreadable locate payload")
        return res

    if paths_agree(warm_prose, cold_prose):
        res.ok("%r retrieved the same %d file(s) through both daemon states: %s"
               % (PROSE_QUERY, len(warm_prose), ", ".join(sorted(set(warm_prose))) or "none"))
    else:
        thin = warm if not warm_prose else cold
        named = text_index_gap_reported(thin["answers"][PROSE_QUERY])
        res.bad("%r retrieved %r through %s and %r through %s; the thin answer %s the "
                "text-index gap"
                % (PROSE_QUERY, sorted(set(warm_prose)), warm["label"],
                   sorted(set(cold_prose)), cold["label"],
                   "named" if named else "said nothing about"))

    # The prose file has to be reachable at all, or "they agree" is two identical
    # empty answers and this check has graded a product that answers nothing.
    reachable = [arm["label"] for arm, paths in ((warm, warm_prose), (cold, cold_prose))
                 if PROSE_FILE in paths]
    if not reachable:
        res.bad("%r carries the only occurrence of %r in this fixture and neither daemon "
                "state retrieved it, so the agreement above is two identical silences"
                % (PROSE_FILE, PROSE_QUERY))
    else:
        res.ok("%s retrieved %s for the prose query" % (" and ".join(reachable), PROSE_FILE))
    return res


def check_lexical_index_parity(suite):
    """The mechanism under the behaviour: does the answering daemon hold the index?

    `kin support --json` is answered by the daemon out of its own live graph, so
    `text_indexed_entity_count` counts the documents the process serving queries
    can actually see. A daemon holding a graph full of entities and a text index
    holding none of them is the state a prose query cannot be answered from, and
    it is invisible from the answer alone.
    """
    res = Result("2", "a daemon that just answered holds a populated derived text index")
    warm, cold = suite.arms()

    warm_total = support_total_entities(warm["support"])
    cold_total = support_total_entities(cold["support"])
    if not warm_total or not cold_total:
        res.unknown("kin support reported %r and %r entities, so there is no graph to have "
                    "indexed and this check graded nothing" % (warm_total, cold_total))
        return res

    warm_indexed = support_text_indexed(warm["support"])
    cold_indexed = support_text_indexed(cold["support"])
    if warm_indexed is None or cold_indexed is None:
        res.unknown("kin support did not carry a readable text_indexed_entity_count "
                    "(warm %r, cold %r)" % (warm_indexed, cold_indexed))
        return res

    reading = ("warm %d of %d entities indexed, cold %d of %d"
               % (warm_indexed, warm_total, cold_indexed, cold_total))
    if warm_indexed == 0 or cold_indexed == 0:
        res.bad("a daemon serving %d entities has %d of them in its derived text index, so a "
                "lexical question cannot be answered from graph truth there: %s"
                % (warm_total if warm_indexed == 0 else cold_total,
                   min(warm_indexed, cold_indexed), reading))
    elif warm_indexed != cold_indexed:
        res.bad("the two daemon states disagree about how much of the graph is text indexed, "
                "which is the same divergence one layer down: %s" % reading)
    else:
        res.ok(reading)
    return res


CHECKS = [check_prose_parity, check_lexical_index_parity]


# ----------------------------------------------------------------- self-test


def self_test():
    """Hand every grader the input it must refuse, beside the one it must accept."""
    failures = []

    def want(label, condition):
        if not condition:
            failures.append(label)

    good = {"files": [{"path": "pkg/overview.py", "score": 1.0}]}
    want("a locate payload's paths are read",
         locate_paths(good) == ["pkg/overview.py"])
    want("an empty ranking reads as zero rows, not as unreadable",
         locate_paths({"files": []}) == [])
    want("a payload with no files key is unreadable, never zero",
         locate_paths({}) is None)
    want("a non-object payload is unreadable", locate_paths("files") is None)
    want("a files list of non-objects is unreadable",
         locate_paths({"files": ["pkg/overview.py"]}) is None)
    want("a row with no path is unreadable",
         locate_paths({"files": [{"score": 1.0}]}) is None)
    want("a row with an empty path is unreadable",
         locate_paths({"files": [{"path": ""}]}) is None)

    want("a text_index degradation is recognised",
         text_index_gap_reported(
             {"degradations": [{"component": "text_index", "reason": "empty"}]}))
    # The mutation that matters: a degradation ledger carrying some OTHER
    # component is not a report about the lexical index, and a grader that
    # accepted any degradation at all would pass on every query that ran with no
    # vector index, which is every query this suite makes.
    want("a vector_index degradation is not a text-index report",
         not text_index_gap_reported(
             {"degradations": [{"component": "vector_index", "reason": "absent"}]}))
    want("an answer with no degradations reports no gap",
         not text_index_gap_reported({"degradations": []}))
    want("a payload with no ledger reports no gap", not text_index_gap_reported({}))

    want("a support count is read", support_text_indexed({"text_indexed_entity_count": 7}) == 7)
    want("zero is a real count, not an unreadable one",
         support_text_indexed({"text_indexed_entity_count": 0}) == 0)
    want("a missing count is unreadable, never zero",
         support_text_indexed({}) is None)
    want("a boolean is not a count",
         support_text_indexed({"text_indexed_entity_count": True}) is None)
    want("a string is not a count",
         support_text_indexed({"text_indexed_entity_count": "7"}) is None)
    want("a negative count is unreadable",
         support_text_indexed({"text_indexed_entity_count": -1}) is None)
    want("total_entities is read the same way",
         support_total_entities({"total_entities": 12}) == 12)
    want("a boolean total is not a count",
         support_total_entities({"total_entities": True}) is None)

    want("two arms naming the same file agree",
         paths_agree(["a.py"], ["a.py"]))
    want("order is not disagreement",
         paths_agree(["a.py", "b.py"], ["b.py", "a.py"]))
    want("a file one arm cannot retrieve is a disagreement",
         not paths_agree(["a.py"], []))
    want("an extra file on one side is a disagreement",
         not paths_agree(["a.py"], ["a.py", "b.py"]))
    want("an unreadable arm never agrees with anything",
         not paths_agree(None, []))
    want("two empty arms agree, which is why check 1 also asserts reachability",
         paths_agree([], []))

    empty = Result("x", "x")
    want("a check that graded nothing is UNREADABLE", empty.status == UNREADABLE)
    mixed = Result("x", "x")
    mixed.ok("fine")
    mixed.bad("not fine")
    want("one FAIL outranks a pass", mixed.status == FAIL)
    unreadable = Result("x", "x")
    unreadable.ok("fine")
    unreadable.unknown("could not read")
    want("UNREADABLE outranks a pass", unreadable.status == UNREADABLE)

    if failures:
        print_("kin-prose-query-parity-repro: SELF-TEST FAILED")
        for label in failures:
            print_("  - %s" % label)
        return 1
    print_("kin-prose-query-parity-repro: self-test passed, "
           "every grader refused the input it must refuse")
    return 0


# ---------------------------------------------------------------------- main


def main(argv):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"),
                        help="the kin binary under test")
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"),
                        help="the kin-daemon beside it")
    parser.add_argument("--json", dest="json_path", default=None,
                        help="write the machine-readable report here, for scripts/acceptance/gate.py")
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL"),
                        help="an opaque run label recorded in the report")
    parser.add_argument("--keep", action="store_true", help="keep the fixture")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="falsify this suite's graders and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.kin:
        print_("kin-prose-query-parity-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    # Absolute, because every command below runs with cwd inside a fixture in a
    # temp directory, and a relative --daemon would resolve against that fixture.
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print_("kin-prose-query-parity-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-prose-query-parity-repro-")
    suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
    try:
        results = []
        for check in CHECKS:
            try:
                results.append(check(suite))
            except ProbeError as error:
                result = Result(getattr(check, "__name__", "check"), "probe could not read")
                result.unknown(str(error))
                results.append(result)
            except Exception as error:  # noqa: BLE001 - a crashed probe is UNREADABLE
                result = Result(getattr(check, "__name__", "check"), "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
        for result in results:
            print_("CHECK %s %s %s %s" % (result.id, TICKET, result.status, result.detail))
        failed = [r for r in results if r.status == FAIL]
        unreadable = [r for r in results if r.status == UNREADABLE]
        print_("kin-prose-query-parity-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
               % (len(results), len(results) - len(failed) - len(unreadable),
                  len(failed), len(unreadable)))
        if args.json_path:
            payload = {
                "suite": "prose_query_parity_repro",
                "ticket": TICKET,
                "label": args.label,
                "kin": kin,
                "results": [
                    {"id": r.id, "ticket": TICKET, "title": r.title,
                     "status": r.status, "detail": r.detail, "asserts": r.asserts}
                    for r in results
                ],
            }
            directory = os.path.dirname(os.path.abspath(args.json_path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(args.json_path, "w") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")
        return 0
    finally:
        suite.stop_daemon()
        if args.keep:
            print_("kin-prose-query-parity-repro: fixture kept at %s" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
