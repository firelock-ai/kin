#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove the product never states an all-clear about a working copy it has not read.

FIR-2820. The v0.6.1 candidate's yardstick run wrote a module, did not commit it,
and asked `find_references` about a constant inside it. Three surfaces answered
together and all three were wrong the same way:

  _kin.durability   "38 entities, 0 uncommitted", state `recorded`
  kin status        "12 artifacts, matching its base change"
  negative          safe_to_conclude_absent true, trust `structural_authoritative`

Fourteen uncommitted entities sat in the file, and `grep -n` found the constant on
two lines. The stranger's sentence: three surfaces agreeing on an answer a one-line
grep refutes.

The mechanism is one reading, read by all three. `untracked_path_count` is a record
a complete reconcile pass leaves behind, and an explicit seam records it EMPTY
because the seam admitted everything. Both are true when written and neither
expires, so a zero from the last commit answers for the rest of the daemon's life
and is indistinguishable from a zero measured this instant. The durability block
then turns a difference between two ENTITY counts, which cannot see a file the graph
never parsed, into a claim about the working tree.

The fixture writes a new directory while the daemon is down. Startup can first
report that source as unadmitted, then automatically admit it through checked
catch-up. Both observations are legitimate. The durability check requires the
original behind disclosure while the gap remains; it accepts the admitted state
only with an exact function body served from graph-owned source, its source base
bound to the complete fixture artifact digest, and an explicit live-uncommitted
count. A file's mere existence never proves graph admission.

Four checks, one seeded repository, run in order because the experiment is
destructive: the last one commits what the first three are about.

  durability  the durability block does not read `recorded` with zero uncommitted
              over a working copy holding a module authority does not carry, and
              names how many paths it cannot see, whether nothing admitted them
              or an admission took their bytes and still owes their parse; after
              automatic admission,
              exact graph source and live-uncommitted counts must prove that change
  status      `kin status` names that file, with the age of the measurement, so a
              reader is never shown authority truth alone and left to infer
  absence     `find_references` on a constant only that file declares either
              names the gap or proves the real use from admitted entity source
  committed   the control: once the tree is committed, the clean durability read
              is back with its zero intact, `kin status` reports nothing
              untracked, and an absence over a name nothing carries is still
              authoritative. Without this the other three are satisfied by a
              product that qualifies every answer it gives.

Exit status is 0 when every check passed, 1 when one failed, 2 when one could not
be read, and 3 when the run could not be set up. `--self-test` exercises every
grader against a payload that must pass and one that must fail, and needs no
binary, so a grader that cannot fail is a failure here rather than a silent pass
in CI.
"""
from __future__ import print_function

import argparse
import functools
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

TICKET = "FIR-2820"

print = functools.partial(print, flush=True)

# The constant the query is about. Declared once and used once, inside the module
# initially written while the daemon is stopped. Catch-up may admit it later.
SYMBOL = "RESOLVE_PREDICATE"

# A name nothing in the fixture declares, used as the control's absence. It has to
# be absent for a reason that is about the name rather than about the working copy,
# which is the distinction the whole suite turns on.
ABSENT_SYMBOL = "NOTHING_IN_THIS_REPOSITORY_CARRIES_THIS_NAME"

PARSING_SRC = '''STEM_SPLIT = "#"


def parse_key(raw):
    return raw.split(STEM_SPLIT)[0]
'''

STORAGE_SRC = '''from notekeeper.parsing import parse_key


def store(rows, raw):
    rows.append(parse_key(raw))
    return rows
'''

# Written into a directory graph truth has never met, while nothing is watching.
LINKGRAPH_SRC = '''%s = "(notes.key = links.target_key)"


def dangling_links(conn):
    return conn.execute("SELECT 1 FROM notes WHERE " + %s)


def resolve_key(conn, key):
    return conn.execute("SELECT 1 FROM notes WHERE key = ?", (key,))
''' % (SYMBOL, SYMBOL)

ADMITTED_FUNCTION_NAME = "dangling_links"
ADMITTED_FUNCTION_BODY = ('def dangling_links(conn):\n'
                          '    return conn.execute("SELECT 1 FROM notes WHERE " + %s)' % SYMBOL)


def run(cmd, cwd=None, env=None, timeout=600, stdin=None):
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env,
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    try:
        out, err = proc.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out, err
    return proc.returncode, out, err


# ── graders ────────────────────────────────────────────────────────────────
#
# Every grader takes parsed payloads or rendered text and returns (status, detail).
# Kept apart from the run so `--self-test` can hand each one an input that must
# pass and one that must fail, with no binary anywhere.


def durability_of(payload):
    """The durability block, or None when the response carries no envelope."""
    if not isinstance(payload, dict):
        return None
    envelope = payload.get("_kin")
    if not isinstance(envelope, dict):
        return None
    block = envelope.get("durability")
    return block if isinstance(block, dict) else None


def grade_durability_withholds_the_all_clear(payload):
    """The claim the fields make, not the sentence beside them.

    `state` and `live_only_entities` are what a caller branches on, and an
    earlier fix withdrew only the prose: the note explained that the reading
    could not be relied on while the two fields went on saying it could.
    """
    block = durability_of(payload)
    if block is None:
        return UNREADABLE, "the response carries no _kin.durability block"
    state = block.get("state")
    if state is None:
        return UNREADABLE, "the durability block carries no state: %r" % (block,)
    if state == "recorded":
        return FAIL, (
            "state %r over a working copy holding an unadmitted module; note %r"
            % (state, block.get("note"))
        )
    if block.get("live_only_entities") == 0:
        return FAIL, (
            "live_only_entities 0 beside state %r, which is the all-clear a caller "
            "reads off the field: %r" % (state, block)
        )
    # FIR-2499 withdrew the prose and left the fields; the first cut of the
    # FIR-2820 fix withdrew the fields and left prose stating the count they had
    # withdrawn. Envelope v2 sends no durability sentence at all, so any `note`
    # is the v1 shape back, and the one that restated a withdrawn count with it.
    if "note" in block:
        return FAIL, (
            "envelope v2 carries no durability sentence, and this one is the v1 shape: %r"
            % (block.get("note"),)
        )
    # Two ways for graph truth to sit behind the working copy, counted apart
    # because they send a reader to different commands. A path nothing admitted
    # is taken by `kin admit`; a path whose bytes are admitted and whose parse
    # is owed is already taken, so reporting it as never admitted names a
    # command that clears nothing. Either one is a gap this reading cannot see,
    # and the check is that the block names one of them rather than which.
    behind = ((payload or {}).get("_kin") or {}).get("behind") or {}
    counted = {}
    for key in ("unadmitted_paths", "underived_paths"):
        value = behind.get(key, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return FAIL, "_kin.behind carries a non-count %s: %r" % (key, behind)
        counted[key] = value
    if sum(counted.values()) < 1:
        return FAIL, "_kin.behind does not name the paths this reading cannot see: %r" % (
            behind,
        )
    return PASS, (
        "state %r, live_only_entities %r, _kin.behind names %d never-admitted path(s) and "
        "%d admitted path(s) still owed a parse"
        % (state, block.get("live_only_entities"),
           counted["unadmitted_paths"], counted["underived_paths"])
    )


def grade_durability_after_admission(payload, source, expected_path):
    """An admitted source is proved by graph bytes, never by missing `behind`."""
    if not isinstance(source, dict) or not isinstance(payload, dict):
        return UNREADABLE, "no graph source/status proof of automatic admission"
    envelope = payload.get("_kin") or {}
    source_envelope = source.get("_kin") or {}
    block = durability_of(payload) or {}
    counts = [block.get(key) for key in
              ("live_entities", "durable_entities", "live_only_entities")]
    if (block.get("state") != "live_uncommitted"
            or any(type(value) is not int or value < 0 for value in counts)
            or counts[2] <= 0 or counts[0] - counts[1] != counts[2]):
        return FAIL, "admitted uncommitted module has no truthful live delta: %r" % block
    if "note" in block or "behind" in envelope:
        return FAIL, "admitted control still carries a durability note or behind gap"
    base = source.get("source_base") or {}
    context = base.get("context") or {}
    expected_body = ADMITTED_FUNCTION_BODY.encode("utf-8")
    expected_start = LINKGRAPH_SRC.encode("utf-8").index(expected_body)
    expected_end = expected_start + len(expected_body)
    expected_digest = hashlib.sha256(LINKGRAPH_SRC.encode("utf-8")).hexdigest()
    expected_body_digest = hashlib.sha256(expected_body).hexdigest()
    digest = base.get("source_blob_hash")
    if (source.get("file_path") != expected_path or source.get("kind") != "Function"
            or source.get("name") != ADMITTED_FUNCTION_NAME
            or source.get("body") != ADMITTED_FUNCTION_BODY
            or source.get("span_coherence") != "digest_verified"
            or not source.get("id") or base.get("entity_id") != source.get("id")
            or base.get("schema") != "kin.entity.source_base.v1"
            or not base.get("artifact_id")
            or source.get("start_byte") != expected_start or source.get("end_byte") != expected_end
            or base.get("start_byte") != expected_start or base.get("end_byte") != expected_end
            or not isinstance(digest, str) or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or digest != expected_digest
            or base.get("body_hash") != expected_body_digest):
        return FAIL, "graph function source does not prove its body and complete fixture artifact"
    if (envelope.get("runtime") != "repo-daemon"
            or source_envelope.get("runtime") != "repo-daemon"
            or not context.get("repository_id")
            or context.get("repository_id") != (envelope.get("answered_by") or {}).get("repo_id")
            or not context.get("workspace_tree_hash")):
        return FAIL, "graph source and status do not identify the same live repository"
    for observed in (envelope, source_envelope):
        freshness = observed.get("freshness") or {}
        if (freshness.get("state") != "recorded" or not freshness.get("at")
                or type(freshness.get("age_seconds")) is not int
                or freshness["age_seconds"] < 0):
            return FAIL, "automatic admission has no recorded observation"
    return PASS, "exact graph function binds the admitted fixture artifact; live_uncommitted, %d live-only entities" % counts[2]


def grade_durability_reads_clean_over_a_committed_tree(payload):
    """The control. A disclosure that always fires is noise nobody reads."""
    block = durability_of(payload)
    if block is None:
        return UNREADABLE, "the response carries no _kin.durability block"
    if block.get("state") != "recorded":
        return FAIL, (
            "a fully committed tree still does not read recorded: %r" % (block,)
        )
    if block.get("live_only_entities") != 0:
        return FAIL, (
            "a fully committed tree does not report zero uncommitted: %r" % (block,)
        )
    return PASS, "recorded, 0 uncommitted, which is what a committed tree is"


# A verdict that names what it rests on. Any ONE of these means the line said
# where its answer came from; none of them means it stated a bare verdict, which
# is the shape FIR-2820 exists to forbid.
_STATUS_BASIS = (
    "as admitted ",                          # an admission ran, and when
    "not measured against the working copy",  # none could, and why
    "no complete admission",                  # no durable marker at all
    "will not parse",                         # the marker is unreadable
)


def grade_status_never_all_clears_an_unread_working_copy(text, expected_path):
    """FIR-2820's rule, asserted directly rather than through its first remedy.

    The rule is that the product never states an all-clear about a working copy it
    has not read. When this check was written, the only way to honour that was to
    NAME the unadmitted file, because `kin status` could not read the working copy
    at all: it reported durable authority and nothing else.

    kin#1258 changed the mechanism. `kin status` now admits before it reads, so the
    working copy IS read and the all-clear is earned rather than assumed. The old
    assertion became unreachable: with a daemon there is no unadmitted file left to
    name, and without one the line says "not measured; no daemon is running", which
    is FIR-2820's own fifth arm and an honest answer rather than the quiet product
    that arm was written to expose.

    So this grades the rule in both worlds. An all-clear must be earned by a basis
    the line states. A gap must be named. A bare verdict fails either way, which is
    what the original defect looked like and what the control below still proves
    this catches.
    """
    if not isinstance(text, str) or "Kin repository-v6 status" not in text:
        return UNREADABLE, "this is not a kin status rendering"
    tree = None
    untracked = None
    for candidate in text.splitlines():
        if candidate.startswith("Tree: "):
            tree = candidate
        elif candidate.startswith("Untracked host content:"):
            untracked = candidate
    if tree is None:
        return UNREADABLE, "kin status carries no Tree: line"
    if untracked is None:
        # The original FIR-2820 defect: authority truth alone, with nothing at all
        # said about host content. Still a failure and still caught here.
        return FAIL, "kin status carries no untracked host content line at all"

    stated_basis = next((token for token in _STATUS_BASIS if token in tree), None)
    if stated_basis is None:
        return FAIL, (
            "the Tree verdict states no basis, so an all-clear rests on nothing a reader "
            "can see: %r" % (tree,)
        )

    # The old world, and the control keeps it graded: when the working copy holds a
    # path authority has not taken, saying so is the answer.
    if expected_path and expected_path in untracked:
        return PASS, "names the unadmitted path, and the verdict states its basis: %r" % (tree,)

    unread = "not measured against the working copy" in tree
    if "not measured" in untracked:
        if not unread:
            return FAIL, (
                "the untracked count was not measured while the verdict claims an admission, "
                "so two lines about one working copy disagree: %r / %r" % (tree, untracked)
            )
        return PASS, "nothing read the working copy and both lines say so: %r" % (untracked,)
    if unread:
        return FAIL, (
            "the verdict says nothing measured the working copy while the untracked line "
            "reports on it anyway: %r / %r" % (tree, untracked)
        )
    return PASS, "the all-clear is earned by a stated basis: %r / %r" % (tree, untracked)


def grade_status_reports_nothing_untracked(text):
    """The control for the line above, on the same surface."""
    if not isinstance(text, str) or "Kin repository-v6 status" not in text:
        return UNREADABLE, "this is not a kin status rendering"
    for candidate in text.splitlines():
        if candidate.startswith("Untracked host content:"):
            if "none, measured" in candidate:
                return PASS, candidate
            return FAIL, "a committed tree still reports untracked content: %r" % (candidate,)
    return FAIL, "kin status carries no untracked host content line at all"


def negative_of(payload):
    if not isinstance(payload, dict):
        return None
    block = payload.get("negative")
    if isinstance(block, dict):
        return block
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("negative"), dict):
        return data["negative"]
    return None


_WITHHELD_GAPS = (
    "graph_behind_working_tree",
    "cross_file_edges_absent",
    "reference_enrichment",
)


def grade_absence_names_the_gap_it_is_withheld_for(payload):
    """An absence over a graph with a gap is not authoritative, and says which gap.

    The `negative` block was never the wrong part on its own: the name really is
    not in the graph. What it may not do is present that as settled while something
    it has not read could carry the name.

    Written first against `graph_behind_working_tree`, which was the only gap that
    could produce it: a module on disk the graph had never met. kin#1258 closed
    that one by admitting before reading, so the honest reason on this fixture
    moved to `cross_file_edges_absent`, the enrichment gap underneath. The rule did
    not move. So this grades the rule: never certified over a gap, and when
    withheld, the reason names which gap rather than leaving a reader to guess.
    """
    block = negative_of(payload)
    if block is None:
        return UNREADABLE, "the response carries no negative block"
    if "safe_to_conclude_absent" not in block:
        return UNREADABLE, "the negative block does not answer the absence question"
    if block.get("safe_to_conclude_absent") is True:
        return FAIL, (
            "the absence is certified over a graph with an unread gap: trust %r, reason %r"
            % (block.get("trust"), block.get("trust_reason"))
        )
    reason = "%s %s" % (block.get("trust_reason") or "", block.get("advice") or "")
    named = next((gap for gap in _WITHHELD_GAPS if gap in reason), None)
    if named is None:
        return FAIL, (
            "the answer is withheld without naming which gap it is withheld for: %r"
            % (block.get("trust_reason"),)
        )
    return PASS, "not certified, and the reason names %s" % named


def reports_positive_references(payload):
    """A populated or purportedly populated answer must pass the positive guard.

    A malformed positive must never fall through to a named-gap exemption.
    Candidates alone do not prove a reference and stay on the absence path.
    """
    if not isinstance(payload, dict):
        return False
    negative = negative_of(payload) or {}
    return bool(payload.get("references") or payload.get("total_upstream")
                or negative.get("result_count")
                or negative.get("kind") == "qualified_answer"
                or negative.get("interpretation") == "qualified_answer")


def grade_admitted_reference(payload, focal_source, caller_source, expected_path, expected_repo):
    """Accept the fixture's actual use, never a count or a declaration-only hit."""
    if not isinstance(payload, dict):
        return UNREADABLE, "no reference payload"
    negative = negative_of(payload) or {}
    envelope = payload.get("_kin") or {}
    verdict = envelope.get("verdict") or {}
    if (envelope.get("self_check") or {}).get("status") == "contradicted":
        return FAIL, "the positive reply contradicts its own verdict"
    references = payload.get("references")
    if (not isinstance(references, list) or len(references) != 1
            or any(type(count) is not int or count != 1 for count in
                   (negative.get("result_count"), payload.get("total_upstream")))
            or negative.get("safe_to_conclude_absent") is not False
            or negative.get("kind") != "qualified_answer"
            or negative.get("interpretation") != "qualified_answer"
            or negative.get("trust") != "authoritative"
            or verdict.get("state") != "certified"
            or verdict.get("absence_claim") != "not_applicable"
            or verdict.get("safe_to_conclude_absent") is not False):
        return FAIL, "positive reference rows, counts and absence verdict do not agree"
    focal = payload.get("focal_entity") or {}
    caller = references[0]
    anchor = (payload.get("cross_repo") or {}).get("authority_anchor") or {}
    expected_use_line = next(index for index, line in enumerate(LINKGRAPH_SRC.splitlines(), 1)
                             if SYMBOL in line and line.lstrip().startswith("return "))
    if (not isinstance(caller, dict) or focal.get("name") != SYMBOL
            or focal.get("kind") != "constant" or focal.get("file_path") != expected_path
            or not focal.get("id") or anchor.get("entity_id") != focal["id"]
            or not anchor.get("repo_id")
            or caller.get("name") != ADMITTED_FUNCTION_NAME
            or caller.get("kind") != "Function" or caller.get("file_path") != expected_path
            or not caller.get("entity_id") or caller.get("resolution") != "type_resolved"
            or caller.get("relation_kinds") != ["references"]
            or caller.get("reference_lines") != [expected_use_line]
            or any(type(line) is not int for line in caller["reference_lines"])
            or type(caller.get("reference_line_count")) is not int
            or caller["reference_line_count"] != 1
            or caller.get("reference_lines_absent_reason") is not None
            or caller.get("reference_lines_partial_reason") is not None
            or payload.get("candidates") != []
            or type(payload.get("unconfirmed_candidates")) is not int
            or payload["unconfirmed_candidates"] != 0):
        return FAIL, "the answer does not prove the fixture's exact focal, caller and use site"
    if ((envelope.get("repository") or {}).get("root") != expected_repo
            or envelope.get("runtime") != "repo-daemon" or "behind" in envelope):
        return FAIL, "reference reply does not identify the admitted fixture repository"
    sources = ((focal_source, focal["id"], SYMBOL, "Constant", LINKGRAPH_SRC.splitlines()[0]),
               (caller_source, caller["entity_id"], ADMITTED_FUNCTION_NAME, "Function",
                ADMITTED_FUNCTION_BODY))
    contexts = []
    artifacts = []
    for source, entity_id, name, kind, body in sources:
        if not isinstance(source, dict):
            return UNREADABLE, "no targeted graph source proof for the positive reference"
        base = source.get("source_base") or {}
        context = base.get("context") or {}
        start = LINKGRAPH_SRC.encode("utf-8").index(body.encode("utf-8"))
        end = start + len(body.encode("utf-8"))
        if (source.get("id") != entity_id or base.get("entity_id") != entity_id
                or source.get("name") != name or source.get("kind") != kind
                or source.get("file_path") != expected_path or source.get("body") != body
                or source.get("span_coherence") != "digest_verified"
                or base.get("schema") != "kin.entity.source_base.v1"
                or not base.get("artifact_id")
                or source.get("start_byte") != start or source.get("end_byte") != end
                or base.get("start_byte") != start or base.get("end_byte") != end
                or any(type(value) is not int for value in
                       (source.get("start_byte"), source.get("end_byte"),
                        base.get("start_byte"), base.get("end_byte")))
                or base.get("source_blob_hash") != hashlib.sha256(LINKGRAPH_SRC.encode("utf-8")).hexdigest()
                or base.get("body_hash") != hashlib.sha256(body.encode("utf-8")).hexdigest()
                or context.get("repository_id") != anchor["repo_id"]
                or not context.get("workspace_tree_hash")):
            return FAIL, "targeted graph source does not bind the reference identities and fixture bytes"
        source_envelope = source.get("_kin") or {}
        freshness = source_envelope.get("freshness") or {}
        if (source_envelope.get("runtime") != "repo-daemon"
                or (source_envelope.get("self_check") or {}).get("status") == "contradicted"
                or freshness.get("state") != "recorded" or not freshness.get("at")
                or type(freshness.get("age_seconds")) is not int
                or freshness["age_seconds"] < 0):
            return FAIL, "targeted graph source has no recorded daemon observation"
        contexts.append(context["workspace_tree_hash"])
        artifacts.append(base["artifact_id"])
    if contexts[0] != contexts[1] or artifacts[0] != artifacts[1]:
        return FAIL, "the focal and caller proofs describe different admitted artifacts or trees"
    return PASS, "exact graph-owned focal and caller prove the real use on line %d; no absence claimed" % expected_use_line


def grade_absence_stays_authoritative_over_a_committed_tree(payload):
    """The control. A name nothing carries is still absent, and saying so is the
    product's job; qualifying it here would make the disclosure worthless.

    Both public verdicts must agree. A certified negative beside an inconclusive
    envelope is a product contradiction, not an authoritative absence.
    """
    block = negative_of(payload)
    if block is None:
        return UNREADABLE, "the response carries no negative block"
    if "safe_to_conclude_absent" not in block:
        return UNREADABLE, "the negative block does not answer the absence question"
    if block.get("safe_to_conclude_absent") is not True:
        return FAIL, (
            "a name nothing declares, over a fully committed tree, is no longer "
            "authoritatively absent: trust %r, reason %r"
            % (block.get("trust"), block.get("trust_reason"))
        )
    reason = block.get("trust_reason") or ""
    if "graph_behind_working_tree" in reason:
        return FAIL, "a committed tree is still being called behind: %r" % (reason,)
    envelope = payload.get("_kin")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("verdict"), dict):
        return FAIL, "the committed absence has no envelope verdict to corroborate it"
    verdict = envelope["verdict"]
    if (block.get("trust") != "authoritative"
            or verdict.get("state") != "certified"
            or verdict.get("absence_claim") != "authoritative"
            or verdict.get("safe_to_conclude_absent") is not True):
        return FAIL, "the negative block and envelope do not jointly certify the absence"
    self_check = envelope.get("self_check")
    if isinstance(self_check, dict) and self_check.get("status") == "contradicted":
        return FAIL, "the committed absence contradicts its own verdict"
    return PASS, "negative and envelope agree on authoritative absence, with no working-copy caveat"


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False, evidence_dir=None):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.evidence_dir = evidence_dir or os.path.join(workdir, "mcp-evidence")
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.mcp_sequence = 0
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home)
        # kin refuses to invent an author, which is correct product behavior and
        # not an obstacle. The run isolates HOME so it cannot read the machine's
        # identity, so it brings one of its own.
        with open(os.path.join(self.home, ".gitconfig"), "w") as handle:
            handle.write("[user]\n\tname = working-copy-freshness-repro\n"
                         "\temail = repro@example.invalid\n"
                         "[commit]\n\tgpgsign = false\n")
        self.env = dict(os.environ)
        self.env["HOME"] = self.home
        self.env["USERPROFILE"] = self.home
        self.env["KIN_HOME"] = self.home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env["KIN_REGISTRY_PATH"] = os.path.join(self.home, "registry.toml")
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DAEMON_URL", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self._repo = None
        self.unadmitted_path = "linkgraph/predicates.py"

    def git(self, args, repo):
        base = ["git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=working-copy-freshness-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=repo, env=self.env)

    def kin_run(self, args, timeout=600):
        rc, out, err = run([self.kin] + args, cwd=self.repo(), env=self.env, timeout=timeout)
        if self.verbose:
            print("  $ kin %s -> rc=%s" % (" ".join(args), rc))
        return rc, out, err

    def repo(self):
        if self._repo:
            return self._repo
        path = os.path.realpath(os.path.join(self.workdir, "notekeeper-repo"))
        os.makedirs(os.path.join(path, "notekeeper"))
        for rel, body in (
            ("notekeeper/__init__.py", ""),
            ("notekeeper/parsing.py", PARSING_SRC),
            ("notekeeper/storage.py", STORAGE_SRC),
        ):
            with open(os.path.join(path, rel), "w") as handle:
                handle.write(body)
        self.git(["init", "-q", "."], path)
        self._repo = path
        rc, out, err = self.kin_run(["init", "."])
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % (err or out)[-400:])
        rc, out, err = self.kin_run(["commit", "-m", "seed the modules the graph knows"])
        if rc != 0:
            raise RuntimeError("kin commit failed: %s" % (err or out)[-400:])
        self.strand_the_module()
        return path

    def strand_the_module(self):
        """Write a new directory offline, then observe disclosure or checked admission."""
        self.kin_run(["daemon", "stop"], timeout=180)
        target = os.path.join(self._repo, self.unadmitted_path)
        os.makedirs(os.path.dirname(target))
        with open(target, "w") as handle:
            handle.write(LINKGRAPH_SRC)
        # Bring the daemon back and let its startup catch-up run, because that
        # pass may either disclose this directory or admit it automatically.
        # A daemon that is merely absent would make every surface below report
        # "not measured", which is honest and is not what
        # this suite is grading.
        rc, out, err = self.kin_run(["graph", "status"], timeout=600)
        if rc != 0:
            raise RuntimeError("the daemon did not come back: %s" % (err or out)[-400:])

    def ground_truth(self):
        """What a one-line grep says, which is the whole point of the finding."""
        target = os.path.join(self.repo(), self.unadmitted_path)
        with open(target) as handle:
            return sum(1 for line in handle if SYMBOL in line)

    def mcp(self, calls):
        """Retain the complete exchange before parsing or rejecting a reply."""
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "working-copy-freshness-repro", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ]
        for index, (name, arguments) in enumerate(calls):
            frames.append({"jsonrpc": "2.0", "id": index + 2, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}})
        payload_in = "\n".join(json.dumps(frame) for frame in frames) + "\n"
        self.mcp_sequence += 1
        evidence = os.path.join(self.evidence_dir, "%03d" % self.mcp_sequence)
        os.makedirs(evidence)
        with open(os.path.join(evidence, "stdin.jsonl"), "w") as handle:
            handle.write(payload_in)
        rc, out, err, launch_error = None, "", "", None
        try:
            rc, out, err = run([self.kin, "mcp", "start"], cwd=self.repo(), env=self.env,
                               timeout=600, stdin=payload_in)
        except Exception as error:
            launch_error = repr(error)
        for name, text in (("stdout.jsonl", out), ("stderr.txt", err)):
            with open(os.path.join(evidence, name), "w") as handle:
                handle.write(text)
        if self.verbose:
            print("  $ kin mcp start (%d calls) -> rc=%s" % (len(calls), rc))
        payloads = {}
        parsed = []
        errors = []
        seen = set()
        if launch_error or rc != 0:
            errors.append("MCP process did not succeed: %r, %r" % (rc, launch_error))
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                errors.append("non-JSON stdout line")
                continue
            parsed.append(message)
            if not isinstance(message, dict):
                errors.append("non-object MCP message")
                continue
            if "error" in message:
                errors.append("JSON-RPC error reply")
            ident = message.get("id")
            if type(ident) is not int or ident < 2:
                continue
            if ident in seen or ident >= len(calls) + 2:
                errors.append("duplicate or unexpected MCP reply id %r" % ident)
                continue
            seen.add(ident)
            body = message.get("result") or message.get("error") or {}
            if "error" in message or not isinstance(body, dict):
                errors.append("MCP call %d returned an error" % ident)
                continue
            text = None
            if isinstance(body, dict) and isinstance(body.get("content"), list):
                try:
                    text = body["content"][0]["text"]
                except (KeyError, IndexError, TypeError):
                    text = None
            try:
                payload = json.loads(text) if text else None
                if not isinstance(payload, dict):
                    raise ValueError("tool result is not a JSON object")
                if body.get("isError"):
                    # A deliberately unresolved focal is a qualified negative,
                    # not a transport failure. Preserve the original absence
                    # controls, while an error can never prove positive rows.
                    negative = negative_of(payload) or {}
                    tool, arguments = calls[ident - 2]
                    name_miss = (
                        body["isError"] is True and tool == "find_references"
                        and arguments.get("query") in (SYMBOL, ABSENT_SYMBOL)
                        and payload.get("message") == "Entity not found"
                        and not payload.get("references") and not payload.get("candidates")
                        and not payload.get("focal_entity")
                        and negative.get("kind") == "focal_not_resolved"
                        and negative.get("interpretation") == "name_not_resolved"
                        and type(negative.get("result_count")) is int
                        and negative["result_count"] == 0)
                    if not name_miss:
                        errors.append("MCP call %d returned a tool error" % ident)
                        continue
                payloads[ident] = payload
            except (TypeError, ValueError):
                errors.append("MCP call %d returned malformed tool content" % ident)
        if set(payloads) != set(range(2, len(calls) + 2)):
            errors.append("MCP call replies are missing")
        with open(os.path.join(evidence, "parsed.json"), "w") as handle:
            json.dump({"exit_code": rc, "launch_error": launch_error, "messages": parsed,
                       "payloads": payloads, "errors": errors}, handle, indent=2)
        if errors:
            raise RuntimeError("MCP exchange failed; retained at %s: %s" % (evidence, "; ".join(errors)))
        return payloads

    def status_text(self):
        rc, out, err = self.kin_run(["status"])
        return out


class Result(object):
    def __init__(self, ident, status, detail):
        self.ident = ident
        self.status = status
        self.detail = detail


def check_durability(suite):
    lines = suite.ground_truth()
    if lines < 2:
        return Result("durability", UNREADABLE,
                      "%s the fixture module does not declare and use the symbol" % TICKET)
    payloads = suite.mcp([("kin_graph_status", {})])
    payload = payloads.get(2)
    status, detail = grade_durability_withholds_the_all_clear(payload)
    # Never replace an observed recorded/zero all-clear with a later good read.
    # This distinct arm applies only when the first status already reports a
    # positive uncommitted admission and no behind disclosure.
    block = durability_of(payload) or {}
    if (status != PASS and block.get("state") == "live_uncommitted"
            and "behind" not in ((payload or {}).get("_kin") or {})):
        listing = suite.mcp([("semantic_search", {"query": ADMITTED_FUNCTION_NAME,
                                                   "kind": "function"})]).get(2) or {}
        functions = [row for row in listing.get("results", [])
                     if row.get("kind") == "function" and row.get("name") == ADMITTED_FUNCTION_NAME]
        if len(functions) != 1 or not functions[0].get("id"):
            return Result("durability", UNREADABLE, "no unique admitted function to verify")
        proof = suite.mcp([("get_entity_source", {"entity_id": functions[0]["id"]}),
                           ("kin_graph_status", {})])
        status, detail = grade_durability_after_admission(payload, proof.get(2), suite.unadmitted_path)
        if status == PASS:
            status, detail = grade_durability_after_admission(proof.get(3), proof.get(2), suite.unadmitted_path)
    return Result("durability", status,
                  "%s grep finds %s on %d lines; %s" % (TICKET, SYMBOL, lines, detail))


def check_status(suite):
    text = suite.status_text()
    status, detail = grade_status_never_all_clears_an_unread_working_copy(
        text, suite.unadmitted_path
    )
    return Result("status", status, "%s %s" % (TICKET, detail))


def check_absence(suite):
    payloads = suite.mcp([("find_references", {"query": SYMBOL, "answer_only": False})])
    payload = payloads.get(2)
    if reports_positive_references(payload):
        # Freeze the original answer before asking for its targeted source proofs.
        # A later successful read must never replace an earlier false absence.
        focal = payload.get("focal_entity") or {}
        references = payload.get("references") or []
        caller = references[0] if isinstance(references, list) and references else {}
        proof = {}
        if isinstance(caller, dict) and focal.get("id") and caller.get("entity_id"):
            proof = suite.mcp([("get_entity_source", {"entity_id": focal["id"]}),
                               ("get_entity_source", {"entity_id": caller["entity_id"]})])
        status, detail = grade_admitted_reference(payload, proof.get(2), proof.get(3),
                                                  suite.unadmitted_path, suite.repo())
    else:
        status, detail = grade_absence_names_the_gap_it_is_withheld_for(payload)
    return Result("absence", status, "%s %s" % (TICKET, detail))


def check_committed(suite):
    rc, out, err = suite.kin_run(["commit", "-m", "land the stranded module"])
    if rc != 0:
        return Result("committed", UNREADABLE,
                      "%s the control's commit failed: %s" % (TICKET, (err or out)[-200:]))
    payloads = suite.mcp([
        ("kin_graph_status", {}),
        ("find_references", {"query": ABSENT_SYMBOL, "answer_only": False}),
    ])
    verdicts = [
        ("durability", grade_durability_reads_clean_over_a_committed_tree(payloads.get(2))),
        ("status", grade_status_reports_nothing_untracked(suite.status_text())),
        ("absence", grade_absence_stays_authoritative_over_a_committed_tree(payloads.get(3))),
    ]
    # Every arm is reported, never the first bad one, because the control is
    # three separate claims and knowing which of them broke is the whole value.
    detail = "; ".join("%s %s %s" % (name, status, note) for name, (status, note) in verdicts)
    if any(status == FAIL for _, (status, _) in verdicts):
        return Result("committed", FAIL, "%s %s" % (TICKET, detail))
    if any(status == UNREADABLE for _, (status, _) in verdicts):
        return Result("committed", UNREADABLE, "%s %s" % (TICKET, detail))
    return Result("committed", PASS, "%s %s" % (TICKET, detail))


# Ordered, and the order is load bearing: `committed` commits the module the
# first three checks are about.
CHECKS = [
    ("durability", check_durability),
    ("status", check_status),
    ("absence", check_absence),
    ("committed", check_committed),
]


# The block `_kin.behind` carries beside a withdrawn durability reading.
BEHIND_BLOCK = {"unadmitted_paths": 1, "measured": True, "sample": ["linkgraph/predicates.py"]}
# The same gap by the other route: startup catch-up admitted the module, so
# nothing is untracked, and the parse it owes is what the entity census cannot
# see. `kin admit` does not clear this one, which is why it is counted apart.
BEHIND_OWED_PARSE_BLOCK = {
    "unadmitted_paths": 0, "underived_paths": 1, "measured": True,
    "underived_sample": ["linkgraph/predicates.py"],
}

BEHIND = {"_kin": {"durability": {
    "state": "unknown", "live_entities": 6, "durable_entities": 6},
    "behind": BEHIND_BLOCK}}
SHIPPED_0_6_1 = {"_kin": {"durability": {
    "state": "recorded", "live_entities": 38, "durable_entities": 38,
    "live_only_entities": 0,
    "note": "38 entities, 0 uncommitted; durable repository authority records everything "
            "answering here."}}}
PROSE_ONLY = {"_kin": {"durability": {
    "state": "recorded", "live_entities": 6, "durable_entities": 6,
    "live_only_entities": 0,
    "note": "6 entities, 0 uncommitted, and 1 host path(s) on disk that no admission has taken, "
            "so how much of this working copy is recorded is unknown; this reading covers "
            "admitted content only. `kin admit` takes those paths now, and a commit takes them "
            "anyway."}}}

# ── one fixture per assertion, because two assertions that can both catch one
# input hide each other's absence ─────────────────────────────────────────────
#
# Every durability fixture above carries `recorded` AND `live_only_entities: 0`,
# so mutating away either field check left the other one catching the same input
# one step later and the self-test stayed green. Each dict below is caught by
# exactly one assertion, so deleting that assertion turns this suite red and
# nothing else does. Written as inputs, never by deleting a defence.
STATE_ONLY = {"_kin": {"durability": {
    "state": "recorded", "live_entities": 6, "durable_entities": 6},
    "behind": BEHIND_BLOCK}}
FIELD_ONLY = {"_kin": {"durability": {
    "state": "unknown", "live_entities": 6, "durable_entities": 6,
    "live_only_entities": 0},
    "behind": BEHIND_BLOCK}}
CARRIES_A_NOTE = {"_kin": {"durability": {
    "state": "unknown", "live_entities": 6, "durable_entities": 6,
    "note": "6 entities, 0 uncommitted, and 1 host path(s) on disk that no admission has taken, "
            "so how much of this working copy is recorded is unknown."},
    "behind": BEHIND_BLOCK}}
BEHIND_NAMES_NOTHING = {"_kin": {"durability": {
    "state": "unknown", "live_entities": 6, "durable_entities": 6}}}
BEHIND_OWED_PARSE = {"_kin": {"durability": {
    "state": "unknown", "live_entities": 6, "durable_entities": 6},
    "behind": BEHIND_OWED_PARSE_BLOCK}}
# A behind block that is present and counts nothing, which is the only input the
# "names no paths" arm can catch once a missing block is caught one step later.
BEHIND_COUNTS_NOTHING = {"_kin": {"durability": {
    "state": "unknown", "live_entities": 6, "durable_entities": 6},
    "behind": {"unadmitted_paths": 0, "underived_paths": 0, "measured": True}}}

STATUS_HEAD = "Kin repository-v6 status\nTree: abc (3 artifacts, matching its base change)\n"
STATUS_NAMING = STATUS_HEAD + (
    "Untracked host content: 1 host path(s) on disk that graph truth does not carry "
    "(linkgraph/predicates.py), measured 0s ago; nothing above describes them\n")
STATUS_UNMEASURED = STATUS_HEAD + (
    "Untracked host content: not measured; this repository's daemon reports no measurement "
    "of it\n")
STATUS_SILENT = STATUS_HEAD
STATUS_CLEAN = STATUS_HEAD + "Untracked host content: none, measured 0s ago\n"
# Names the file AND says nothing measured it, which is the only input the
# "not measured" arm can catch on its own: the unmeasured line above is caught
# one step later for not naming the file.
STATUS_UNMEASURED_NAMING = STATUS_HEAD + (
    "Untracked host content: not measured; this repository's daemon reports no measurement of "
    "1 host path(s) including linkgraph/predicates.py\n")
# Names the file and never says when, which is the only input the "does not say
# when it was measured" arm can catch on its own.
STATUS_NAMING_UNDATED = STATUS_HEAD + (
    "Untracked host content: 1 host path(s) on disk that graph truth does not carry "
    "(linkgraph/predicates.py); nothing above describes them\n")

# The read-after-admit shapes, from kin#1254 and kin#1258. The Tree verdict now
# states what it rests on, which is what lets an all-clear be earned rather than
# assumed.
# The 02:01Z shape: names the unadmitted path AND states its basis, because
# kin#1254 landed the clock at 01:57Z. This is the control the rewrite has to keep
# passing.
STATUS_NAMING_ADMITTED = (
    "Kin repository-v6 status\nTree: abc (3 artifacts, matching its base change as admitted "
    "0s ago)\n"
    "Untracked host content: 1 host path(s) on disk that graph truth does not carry "
    "(linkgraph/predicates.py), measured 0s ago; nothing above describes them\n")

STATUS_HEAD_ADMITTED = (
    "Kin repository-v6 status\nTree: abc (3 artifacts, matching its base change as admitted "
    "0s ago)\n")
STATUS_HEAD_UNREAD = (
    "Kin repository-v6 status\nTree: abc (3 artifacts, matching its base change as last "
    "admitted, not measured against the working copy: no daemon is running for this "
    "repository)\n")
# Earned: an admission ran and the count is measured.
STATUS_ADMITTED_CLEAN = STATUS_HEAD_ADMITTED + "Untracked host content: none, measured 0s ago\n"
# Honest: nothing read it and BOTH lines say so.
STATUS_UNREAD_UNMEASURED = STATUS_HEAD_UNREAD + (
    "Untracked host content: not measured; no daemon is running for this repository\n")
# The two disagreements, which are the shapes this rewrite exists to catch.
STATUS_UNREAD_BUT_CLEAN = STATUS_HEAD_UNREAD + (
    "Untracked host content: none, measured 0s ago\n")
STATUS_ADMITTED_BUT_UNMEASURED = STATUS_HEAD_ADMITTED + (
    "Untracked host content: not measured; this repository's daemon did not answer\n")

CERTIFIED = {"negative": {
    "safe_to_conclude_absent": True, "trust": "authoritative",
    "trust_reason": "structural_authoritative: daemon graph initialized and loaded, with no "
                    "degraded signals",
    "advice": "The name is authoritatively absent from this graph: no entity carries it."},
    "_kin": {"verdict": {"state": "certified", "absence_claim": "authoritative",
                          "safe_to_conclude_absent": True}}}
WITHHELD = {"negative": {
    "safe_to_conclude_absent": False, "trust": "inconclusive",
    "trust_reason": "graph_behind_working_tree: 1 host path(s) on disk have never been admitted",
    "advice": "graph_behind_working_tree: 1 host path(s) on disk have never been admitted"}}
# Quoted from what the product actually answered on this fixture after kin#1258,
# not written by hand: an invented reason cannot tell you what the producer says.
WITHHELD_ENRICHMENT = {"negative": {
    "safe_to_conclude_absent": False, "trust": "inconclusive",
    "trust_reason": "cross_file_edges_absent: the graph holds no cross-file references edges "
                    "for Python, so a use that reaches the target through references could "
                    "not have been found",
    "advice": "the enrichment sweep is what to look at, not the build's capability"}}
WITHHELD_UNEXPLAINED = {"negative": {
    "safe_to_conclude_absent": False, "trust": "inconclusive",
    "trust_reason": "some other reason entirely", "advice": "some other reason entirely"}}


def report_payload(results):
    """The report shape `scripts/acceptance/gate.py` reads.

    The key is `results` and not `checks`. That is not a style choice: the gate
    calls `payload.get("results")` at `gate.py:98` and refuses anything else
    with "carries no results list". This suite shipped keyed `checks`, so the
    post-merge run on kin#1205's squash printed four CHECK lines, wrote a report
    carrying all four rows, and the verdict step still could not read one of
    them. That is the second time this key has broken this gate; the first is
    recorded in `same_owner_call_repro.py`. Written once here and read back
    through the gate's own loader by the self-test, so it cannot drift again.
    """
    return {"suite": "working_copy_freshness", "ticket": TICKET,
            "results": [{"id": r.ident, "ticket": TICKET, "status": r.status,
                         "detail": r.detail} for r in results]}


def absolute_binary(path):
    """A binary path the fixtures can still find after they change directory.

    Every check runs the binary with `cwd=` a `tempfile.mkdtemp` workspace, so a
    relative `--kin target/release/kin` resolves against that temp directory
    rather than the caller's, and raises `[Errno 2] No such file or directory`.
    That is what happened to all four checks on kin#1205's squash, with the
    workflow passing exactly the path every sibling step passes. The siblings
    absolutize at parse time (`eject_journal_repro.py:918`); this does the same.
    """
    return path and os.path.abspath(os.path.expanduser(path))


def self_test():
    graded = []
    failures = []

    def expect(label, got, want):
        graded.append(label)
        status = got[0]
        if status != want:
            failures.append("%s: wanted %s got %s (%s)" % (label, want, status, got[1]))

    expect("durability passes the qualified reading",
           grade_durability_withholds_the_all_clear(BEHIND), PASS)
    expect("durability fails the shipped 0.6.1 envelope",
           grade_durability_withholds_the_all_clear(SHIPPED_0_6_1), FAIL)
    expect("durability fails a reading that withdrew only the prose",
           grade_durability_withholds_the_all_clear(PROSE_ONLY), FAIL)
    expect("durability cannot read a response with no envelope",
           grade_durability_withholds_the_all_clear({"entity_count": 6}), UNREADABLE)
    # One arm per assertion in that grader, each caught by exactly one of them.
    expect("durability fails a recorded state on its own",
           grade_durability_withholds_the_all_clear(STATE_ONLY), FAIL)
    expect("durability fails a zero live_only_entities on its own",
           grade_durability_withholds_the_all_clear(FIELD_ONLY), FAIL)
    expect("durability fails a note that still states an uncommitted count",
           grade_durability_withholds_the_all_clear(CARRIES_A_NOTE), FAIL)
    expect("durability fails a note that names no host paths",
           grade_durability_withholds_the_all_clear(BEHIND_NAMES_NOTHING), FAIL)
    expect("durability passes a reading whose only gap is an owed parse",
           grade_durability_withholds_the_all_clear(BEHIND_OWED_PARSE), PASS)
    expect("durability fails a behind block that counts nothing at all",
           grade_durability_withholds_the_all_clear(BEHIND_COUNTS_NOTHING), FAIL)

    expect("durability control passes a committed tree",
           grade_durability_reads_clean_over_a_committed_tree(SHIPPED_0_6_1), PASS)
    expect("durability control fails a tree still reporting unknown",
           grade_durability_reads_clean_over_a_committed_tree(BEHIND), FAIL)
    expect("durability control cannot read a response with no envelope",
           grade_durability_reads_clean_over_a_committed_tree({}), UNREADABLE)

    # The 02:01Z control set. These are the shapes the OLD form graded, kept
    # verbatim so the rewrite is shown to grade the same rule when the old
    # condition holds rather than merely to stop failing.
    expect("status passes a line naming the file, as it always did",
           grade_status_never_all_clears_an_unread_working_copy(
               STATUS_NAMING_ADMITTED, "linkgraph/predicates.py"), PASS)
    # And the sharper half: naming the file does NOT excuse a bare verdict. The
    # pre-kin#1254 head is kept for exactly this, because a rule about all-clears
    # has to bite on the verdict independently of the untracked line.
    expect("status fails a bare verdict even when the untracked line names the file",
           grade_status_never_all_clears_an_unread_working_copy(
               STATUS_NAMING, "linkgraph/predicates.py"), FAIL)
    expect("status fails a status with no untracked line at all",
           grade_status_never_all_clears_an_unread_working_copy(
               STATUS_SILENT, "linkgraph/predicates.py"), FAIL)
    expect("status cannot read something that is not a status",
           grade_status_never_all_clears_an_unread_working_copy(
               "nope", "linkgraph/predicates.py"), UNREADABLE)
    # The bare verdict, which is the original defect and the one shape that must
    # never pass in either world.
    expect("status fails a verdict that states no basis",
           grade_status_never_all_clears_an_unread_working_copy(
               STATUS_CLEAN, "linkgraph/predicates.py"), FAIL)
    # The read-after-admit world.
    expect("status passes an all-clear earned by a stated admission",
           grade_status_never_all_clears_an_unread_working_copy(
               STATUS_ADMITTED_CLEAN, "linkgraph/predicates.py"), PASS)
    expect("status passes a daemon-down answer where both lines say nothing read it",
           grade_status_never_all_clears_an_unread_working_copy(
               STATUS_UNREAD_UNMEASURED, "linkgraph/predicates.py"), PASS)
    expect("status fails an all-clear over a working copy the verdict says it never read",
           grade_status_never_all_clears_an_unread_working_copy(
               STATUS_UNREAD_BUT_CLEAN, "linkgraph/predicates.py"), FAIL)
    expect("status fails two lines about one working copy that disagree",
           grade_status_never_all_clears_an_unread_working_copy(
               STATUS_ADMITTED_BUT_UNMEASURED, "linkgraph/predicates.py"), FAIL)

    # The 02:01Z control: the gap this check was written for still passes.
    expect("absence passes a withheld answer naming graph_behind_working_tree",
           grade_absence_names_the_gap_it_is_withheld_for(WITHHELD), PASS)
    # And the gap read-after-admit leaves behind, which is what the fixture now
    # reaches. Same rule, different gap named.
    expect("absence passes a withheld answer naming the enrichment gap",
           grade_absence_names_the_gap_it_is_withheld_for(WITHHELD_ENRICHMENT), PASS)
    expect("absence fails the shipped certified answer",
           grade_absence_names_the_gap_it_is_withheld_for(CERTIFIED), FAIL)
    expect("absence fails an answer withheld for an unnamed reason",
           grade_absence_names_the_gap_it_is_withheld_for(WITHHELD_UNEXPLAINED), FAIL)
    expect("absence cannot read a response with no negative block",
           grade_absence_names_the_gap_it_is_withheld_for({"results": []}), UNREADABLE)

    expect("absence control passes a certified answer",
           grade_absence_stays_authoritative_over_a_committed_tree(CERTIFIED), PASS)
    expect("absence control fails an answer withheld over a committed tree",
           grade_absence_stays_authoritative_over_a_committed_tree(WITHHELD), FAIL)
    expect("absence control cannot read a response with no negative block",
           grade_absence_stays_authoritative_over_a_committed_tree({}), UNREADABLE)

    # The report shape, driven through the gate's own reader rather than through
    # a copy of its rules. This suite printed four CHECK lines on kin#1205's
    # squash and the verdict step still could not read one of them; a self-test
    # that only grades graders cannot see that, and this one could not.
    import importlib.util

    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    if not os.path.exists(gate_path):
        failures.append("gate.py is not beside this file, so the report shape went unchecked")
    else:
        spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        scratch = tempfile.mkdtemp(prefix="working-copy-freshness-selftest-")
        try:
            rows = [Result(ident, UNREADABLE, "%s check raised: fabricated" % TICKET)
                    for ident, _ in CHECKS]
            good = os.path.join(scratch, "good.json")
            with open(good, "w") as handle:
                json.dump(report_payload(rows), handle)
            try:
                loaded = gate.load_report(good)
                expect("the gate reads every row this suite writes",
                       (sorted(loaded), "loaded"), sorted(ident for ident, _ in CHECKS))
                expect("the gate reads a status off each row",
                       (loaded[CHECKS[0][0]].get("status"), "row status"), UNREADABLE)
            except Exception as exc:  # noqa: BLE001 - a refusal is the finding
                failures.append("the gate refused this suite's own report: %s" % exc)

            # CONTROL: the shape that shipped must still be refused, or the two
            # assertions above would pass over any payload at all.
            bad = os.path.join(scratch, "bad.json")
            with open(bad, "w") as handle:
                json.dump({"suite": "working_copy_freshness", "ticket": TICKET,
                           "checks": [{"id": ident, "status": UNREADABLE}
                                      for ident, _ in CHECKS]}, handle)
            try:
                gate.load_report(bad)
                refused = False
            except Exception:  # noqa: BLE001 - the refusal is what is wanted
                refused = True
            expect("CONTROL the gate still refuses the `checks`-keyed shape that broke CI",
                   (refused, "refused"), True)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    # The path the fixtures need, driven through this file's own resolver. An
    # assertion on `os.path.abspath` would say the standard library works, not
    # that this suite calls it, and this suite's defect was that it did not.
    expect("a relative kin path is absolutized by this suite",
           (os.path.isabs(absolute_binary("target/release/kin")), "isabs"), True)
    expect("and an absent binary stays absent rather than becoming the cwd",
           (absolute_binary(None), "absent"), None)

    # And that main() actually calls it, which the two assertions above cannot
    # see: deleting the call leaves every one of them green, measured. So this
    # drives this file as a subprocess from another directory with a relative
    # --kin, which is the shape the workflow passes, against a stub that exists
    # only from that directory. A stub rather than a real binary because the
    # question is whether the fixtures can FIND it, and that needs no build.
    stub_root = tempfile.mkdtemp(prefix="working-copy-freshness-stub-")
    try:
        os.makedirs(os.path.join(stub_root, "bin"))
        stub = os.path.join(stub_root, "bin", "kin")
        with open(stub, "w") as handle:
            handle.write("#!/bin/sh\nexit 42\n")
        os.chmod(stub, 0o755)

        def relative_run(binary):
            """This file, run from `stub_root`, told to use `binary` relatively."""
            proc = subprocess.Popen(
                [sys.executable, os.path.abspath(__file__), "--kin", binary,
                 "--json", os.path.join(stub_root, binary.replace("/", "-") + ".json")],
                cwd=stub_root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                return proc.communicate(timeout=180)[0].decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - a hang is a failure, not a verdict
                proc.kill()
                proc.communicate()
                return "SELFTEST the relative run did not finish inside 180s"

        found = relative_run("bin/kin")
        expect("main absolutizes, so the fixtures find a relative --kin from elsewhere",
               ("No such file or directory: 'bin/kin'" in found, "relative run"), False)
        # CONTROL: a binary that is absent from every directory must still be
        # reported absent, or the assertion above would pass over a suite that
        # never tried to run anything at all.
        absent = relative_run("bin/not-kin")
        expect("CONTROL a binary absent everywhere is still reported absent",
               ("No such file or directory" in absent, "absent run"), True)
    finally:
        shutil.rmtree(stub_root, ignore_errors=True)

    for line in failures:
        print("SELFTEST FAIL %s" % line)
    # Counted, never written out. A hardcoded total drifts from the assertions it
    # claims to describe, and it drifts silently downward.
    print("self-test: %d grader assertions, %d failed" % (len(graded), len(failures)))
    if len(graded) != len(set(graded)):
        print("SELFTEST FAIL duplicate assertion labels, so one shadowed another")
        return 1
    if not graded:
        print("SELFTEST FAIL no grader assertion ran")
        return 1
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN") or shutil.which("kin"))
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"))
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--evidence-dir", help="retain every MCP exchange here (defaults beside --json)")
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

    workdir = tempfile.mkdtemp(prefix="working-copy-freshness-")
    evidence_dir = os.path.abspath(opts.evidence_dir or
                                   (opts.json_path + ".mcp" if opts.json_path else workdir + "-mcp"))
    suite = Suite(opts.kin, workdir, daemon=opts.daemon, verbose=opts.verbose,
                  evidence_dir=evidence_dir)
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
        # Written before the asked/answered guard below, not after it. Four
        # UNREADABLE rows are a verdict the gate can name; a missing report is
        # one it can only refuse, and the refusal names the file rather than
        # the check that broke.
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
