#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail a pull request the day AGENTS.md's required-contexts sentence drifts from GitHub.

`AGENTS.md`'s "Landing" section enumerates the required status checks on `main` as prose, because
a lane deciding whether it is safe to land needs to read that list without an API call. Prose is a
second copy of a live GitHub ruleset, and on 2026-09-03 it had already drifted: the sentence said
six required contexts and named `DCO Sign-off`, `PR text hygiene`, `cargo-deny`,
`gitleaks (full history)`, `Fast gate lint and policy` and `Fast gate build and tests`, while
`GET /repos/firelock-ai/kin/rules/branches/main` answered with seven, the sixth-plus-one being
`MCP surface contract`. Nothing had compared the two since whoever added that context did.

This is the comparison. It reads the sentence out of `AGENTS.md` rather than keeping its own copy
of the expected list, because a second hardcoded copy in this file would be exactly the bug it
exists to catch: it would drift from the doc the same way the doc drifted from GitHub. It also
reads the API path (`/repos/firelock-ai/kin/rules/branches/main`) out of that same sentence rather
than hardcoding it, so a doc that names the wrong path fails this check by 404 rather than by
silently comparing against a path nobody wrote down.

## Why this lives in `ci.yml`, not `scripts/acceptance/`

kin's `Product Acceptance` job carries `if: ${{ github.event_name != 'pull_request' }}`, so a rule
under `scripts/acceptance/` grades main after a landing, never the pull request that caused the
drift. This runs as a step in `ci.yml`'s `fast-gate-lint` job, which carries the required
"Fast gate lint and policy" context and runs on every pull request unconditionally (no
`docs_only` skip), so an `AGENTS.md` edit is graded by the same pull request that makes it.

## Why no token is required

`GET /repos/{owner}/{repo}/rules/branches/{branch}` needs no authentication for a public
repository; verified twice on 2026-09-03, once through `gh api` and once through a bare
unauthenticated `curl -v` that carried no `Authorization` header and still answered 200 (at the
anonymous 60-request/hour limit). This check will pass a bearer token from `GH_TOKEN` or
`GITHUB_TOKEN` when either is set, which `ci.yml` does via `${{ github.token }}` for the 5000/hour
limit, but it runs with neither set, which is the shape `bin/kin-precheck kin` runs it in.

## The three outcomes, and why there are three rather than two

  MATCH (exit 0)       the doc's count word, the doc's own list length, and GitHub's live list
                        all agree. Printed with the full list so a diff is easy to eyeball.
  DRIFT (exit 1)       any of: the sentence could not be found or parsed in `AGENTS.md`; GitHub
                        answered a status this check does not treat as transient (a 404 on the
                        named path, a non-JSON body, a body with no `required_status_checks`
                        rule); or GitHub answered fine and the two lists disagree. None of these
                        is "could not check"; all of them are "checked, and it is wrong."
  SKIP (exit 0, loud)  GitHub could not be reached at all (DNS, timeout, connection refused) or
                        refused the read in a way indistinguishable from rate-limiting or a bad
                        token (401, 403, 429). This is the one outcome that does not fail the
                        pull request, and it prints `::warning::` plus a `SKIP:` line so it is
                        never mistaken for a pass in the log. A check that exits 0 having read
                        nothing is worse than no check, so this path is narrow on purpose: a 404
                        is DRIFT, not SKIP, because a 404 means the path the doc names is itself
                        wrong, which is squarely this check's job to catch.

Falsified with `--self-test`, offline and hermetic: every control below injects a fake network
call rather than reaching GitHub, including the exact six-doc/seven-live shape of the regression
this check exists for.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

API_HOST = "https://api.github.com"

WORD_TO_NUMBER = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20,
}

# Matches the one sentence in AGENTS.md this check exists to hold accountable. Whitespace in the
# input is normalized to single spaces before this runs, so the sentence's hand-wrapped line
# breaks do not matter. A change to the sentence's wording that stops this from matching is a
# DRIFT (see parse_sentence), never a silent pass.
SENTENCE_RE = re.compile(
    r"(?P<count_word>[A-Za-z]+) required contexts on main, read from "
    r"`(?P<api_path>/[^`]+)`:\s*"
    r"(?P<list>`[^`]+`(?:\s*(?:,|and)\s*`[^`]+`)*)\."
)
ITEM_RE = re.compile(r"`([^`]+)`")


class Unreachable(Exception):
    """GitHub could not be reached, or refused the read in a way that reads as transient
    (rate-limited or an invalid token). Not evidence the doc is wrong. Maps to SKIP."""


class Drift(Exception):
    """The doc's claim is unparseable, or GitHub answered with something this check does
    not recognize, or the two lists disagree. Always a hard failure, never a skip."""


def parse_sentence(text):
    """Return (count_word, api_path, doc_contexts) or raise Drift.

    Reads the API path out of the sentence rather than a module constant, so a doc that names the
    wrong path is caught by this check's own request 404ing, not by comparing against a path
    nobody wrote down.
    """
    normalized = re.sub(r"\s+", " ", text)
    match = SENTENCE_RE.search(normalized)
    if not match:
        raise Drift(
            "could not find the 'N required contexts on main, read from `<path>`: ...' sentence "
            "in AGENTS.md. Either it was reworded in a way SENTENCE_RE in "
            "scripts/check-required-contexts.py no longer recognizes, or the fact it guards is "
            "gone; either way this must not pass unread."
        )
    items = ITEM_RE.findall(match.group("list"))
    if not items:
        raise Drift("the sentence in AGENTS.md named no backtick-quoted context names")
    return match.group("count_word"), match.group("api_path"), items


def fetch_required_contexts(api_path, token=None, timeout=10, opener=None):
    """Return the live list of required_status_checks contexts, or raise Unreachable/Drift.

    `opener` is a callable(request) -> response, injected in --self-test so the real network is
    never touched there. The default opens the real URL with the given timeout.
    """
    if opener is None:
        opener = lambda req: urllib.request.urlopen(req, timeout=timeout)  # noqa: E731

    url = API_HOST + api_path
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "kin-check-required-contexts",
        },
    )
    if token:
        request.add_header("Authorization", "Bearer %s" % token)

    try:
        with opener(request) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 429):
            raise Unreachable(
                "%s answered %d %s; read as rate-limited or an invalid token, not as a doc "
                "problem" % (url, exc.code, exc.reason)
            ) from exc
        raise Drift(
            "%s answered %d %s; the path AGENTS.md names may no longer resolve"
            % (url, exc.code, exc.reason)
        ) from exc
    except urllib.error.URLError as exc:
        raise Unreachable("could not reach %s: %s" % (url, exc.reason)) from exc
    except TimeoutError as exc:
        raise Unreachable("timed out reaching %s" % url) from exc

    try:
        rules = json.loads(body)
    except json.JSONDecodeError as exc:
        raise Drift("%s did not return JSON: %s" % (url, exc)) from exc
    if not isinstance(rules, list):
        raise Drift("%s answered with a %s, not a list of rules" % (url, type(rules).__name__))

    contexts = []
    found_rule = False
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        found_rule = True
        checks = (rule.get("parameters") or {}).get("required_status_checks") or []
        for check in checks:
            if isinstance(check, dict) and check.get("context"):
                contexts.append(check["context"])
    if not found_rule:
        raise Drift(
            "%s carried no required_status_checks rule; either main requires nothing or the "
            "ruleset's shape changed under this check" % url
        )
    return contexts


def compare(count_word, doc_contexts, live_contexts):
    """Return a list of human-readable problems; empty means agreement."""
    problems = []
    declared = WORD_TO_NUMBER.get(count_word.lower())
    if declared is None:
        problems.append(
            "AGENTS.md says '%s required contexts', which is not a number word this check "
            "knows; extend WORD_TO_NUMBER in scripts/check-required-contexts.py" % count_word
        )
    elif declared != len(doc_contexts):
        problems.append(
            "AGENTS.md says '%s' (%d) but its own backtick list names %d"
            % (count_word, declared, len(doc_contexts))
        )

    doc_set, live_set = frozenset(doc_contexts), frozenset(live_contexts)
    missing = live_set - doc_set
    extra = doc_set - live_set
    if missing:
        problems.append("main requires contexts AGENTS.md does not name: " + ", ".join(sorted(missing)))
    if extra:
        problems.append("AGENTS.md names contexts main does not require: " + ", ".join(sorted(extra)))
    return problems


def default_agents_md():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "AGENTS.md")


def run(agents_md_path, token=None, opener=None):
    """Returns (exit_code, [lines to print]). Never raises: every failure mode is a return."""
    try:
        with open(agents_md_path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        return 1, ["::error::could not read %s: %s" % (agents_md_path, exc)]

    try:
        count_word, api_path, doc_contexts = parse_sentence(text)
    except Drift as exc:
        return 1, ["::error::%s" % exc]

    try:
        live_contexts = fetch_required_contexts(api_path, token=token, opener=opener)
    except Unreachable as exc:
        return 0, ["::warning::SKIP required-contexts check: %s" % exc, "SKIP: %s" % exc]
    except Drift as exc:
        return 1, ["::error::%s" % exc]

    problems = compare(count_word, doc_contexts, live_contexts)
    if problems:
        lines = ["::error::AGENTS.md's required-contexts sentence disagrees with GitHub:"]
        lines += ["  - %s" % p for p in problems]
        lines.append("doc  (%d): %s" % (len(doc_contexts), ", ".join(doc_contexts)))
        lines.append("live (%d): %s" % (len(live_contexts), ", ".join(live_contexts)))
        return 1, lines

    return 0, [
        "AGENTS.md's %d required contexts match %s exactly: %s"
        % (len(doc_contexts), api_path, ", ".join(doc_contexts))
    ]


# ─── Controls ───────────────────────────────────────────────────────────────
#
# Every control is offline: fetch_required_contexts is driven through an injected `opener`, never
# the real network, so this is deterministic in a network-denied sandbox. The second control below
# is the regression itself, frozen as fixture text, so a future edit that reintroduces this exact
# bug shape is caught here before it is caught by GitHub.

REAL_DOC_TEXT_SEVEN = (
    "kin is a classic direct-merge repo. Seven required contexts on main, read from "
    "`/repos/firelock-ai/kin/rules/branches/main`: `DCO Sign-off`, `PR text hygiene`, "
    "`cargo-deny`, `gitleaks (full history)`, `Fast gate lint and policy`, "
    "`Fast gate build and tests` and `MCP surface contract`. Commit with `git commit -s`."
)

# The exact shape of the bug this check exists for, frozen verbatim from AGENTS.md before this
# lane's fix: six named, GitHub's seventh (`MCP surface contract`) absent.
REGRESSION_DOC_TEXT_SIX = (
    "kin is a classic direct-merge repo. Six required contexts on main, read from "
    "`/repos/firelock-ai/kin/rules/branches/main`: `DCO Sign-off`, `PR text hygiene`, "
    "`cargo-deny`, `gitleaks (full history)`, `Fast gate lint and policy` and "
    "`Fast gate build and tests`. Commit with `git commit -s`."
)

# The live answer, verified twice on 2026-09-03 (gh api and a bare unauthenticated curl), frozen
# as a fixture payload shaped exactly like GitHub's real response: several unrelated rule types
# mixed in, because a naive reader that assumes rules[0] is the required_status_checks rule would
# pass this fixture by luck.
REAL_RULES_PAYLOAD = [
    {"type": "deletion", "ruleset_id": 18795156},
    {"type": "non_fast_forward", "ruleset_id": 18795156},
    {
        "type": "pull_request",
        "parameters": {"required_approving_review_count": 0},
        "ruleset_id": 18824348,
    },
    {
        "type": "required_status_checks",
        "parameters": {
            "required_status_checks": [
                {"context": "DCO Sign-off"},
                {"context": "PR text hygiene"},
                {"context": "cargo-deny"},
                {"context": "gitleaks (full history)"},
                {"context": "Fast gate lint and policy"},
                {"context": "Fast gate build and tests"},
                {"context": "MCP surface contract"},
            ]
        },
        "ruleset_id": 19746451,
    },
]
REAL_LIVE_SEVEN = [
    "DCO Sign-off", "PR text hygiene", "cargo-deny", "gitleaks (full history)",
    "Fast gate lint and policy", "Fast gate build and tests", "MCP surface contract",
]


class _FakeResponse:
    """A context-manager stand-in for what urlopen() returns, holding canned JSON bytes."""

    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


def _returns(payload):
    return lambda req: _FakeResponse(payload)


def _raises(exc):
    def opener(req):
        raise exc

    return opener


def self_test():
    """Grade every outcome by name. A grader that cannot fail is not evidence: the controls
    below include both directions of disagreement, the count-word-vs-list-length check
    independent of GitHub, every non-MATCH classification, and the real regression shape."""
    failures = []

    def check(name, cond):
        print("CONTROL %s %s" % ("PASS" if cond else "FAIL", name))
        if not cond:
            failures.append(name)

    # parse_sentence
    count_word, api_path, items = parse_sentence(REAL_DOC_TEXT_SEVEN)
    check("parses today's sentence: count word", count_word == "Seven")
    check("parses today's sentence: api path", api_path == "/repos/firelock-ai/kin/rules/branches/main")
    check("parses today's sentence: seven items in order", items == REAL_LIVE_SEVEN)

    try:
        parse_sentence("this file mentions no required contexts sentence at all")
        check("unparseable text raises Drift rather than passing silent", False)
    except Drift:
        check("unparseable text raises Drift rather than passing silent", True)

    # fetch_required_contexts, offline via injected openers
    fetched = fetch_required_contexts("/repos/firelock-ai/kin/rules/branches/main",
                                       opener=_returns(REAL_RULES_PAYLOAD))
    check("fetch extracts all seven contexts, ignoring unrelated rule types", fetched == REAL_LIVE_SEVEN)

    try:
        fetch_required_contexts("/x", opener=_raises(urllib.error.URLError("mock DNS failure")))
        check("a connection error raises Unreachable, not Drift", False)
    except Unreachable:
        check("a connection error raises Unreachable, not Drift", True)
    except Drift:
        check("a connection error raises Unreachable, not Drift", False)

    for code in (401, 403, 429):
        try:
            fetch_required_contexts(
                "/x", opener=_raises(urllib.error.HTTPError("https://api.github.com/x", code, "nope", None, None))
            )
            check("HTTP %d raises Unreachable (rate-limit/auth shape)" % code, False)
        except Unreachable:
            check("HTTP %d raises Unreachable (rate-limit/auth shape)" % code, True)
        except Drift:
            check("HTTP %d raises Unreachable (rate-limit/auth shape)" % code, False)

    try:
        fetch_required_contexts(
            "/x", opener=_raises(urllib.error.HTTPError("https://api.github.com/x", 404, "missing", None, None))
        )
        check("a 404 on the named path raises Drift, not Unreachable (the path itself is wrong)", False)
    except Drift:
        check("a 404 on the named path raises Drift, not Unreachable (the path itself is wrong)", True)
    except Unreachable:
        check("a 404 on the named path raises Drift, not Unreachable (the path itself is wrong)", False)

    try:
        fetch_required_contexts("/x", opener=_returns([{"type": "deletion"}, {"type": "pull_request"}]))
        check("a response with no required_status_checks rule raises Drift, not empty agreement", False)
    except Drift:
        check("a response with no required_status_checks rule raises Drift, not empty agreement", True)

    # compare()
    check("matching lists and count word: no problems",
          compare("Seven", REAL_LIVE_SEVEN, REAL_LIVE_SEVEN) == [])

    missing_case = compare("Six", REGRESSION_DOC_TEXT_SIX and
                            ["DCO Sign-off", "PR text hygiene", "cargo-deny", "gitleaks (full history)",
                             "Fast gate lint and policy", "Fast gate build and tests"],
                            REAL_LIVE_SEVEN)
    check("a context live has and the doc lacks is reported as missing",
          any("MCP surface contract" in p for p in missing_case))

    extra_case = compare("Seven", REAL_LIVE_SEVEN + ["Retired check"], REAL_LIVE_SEVEN)
    check("a context the doc has and live lacks is reported as extra",
          any("Retired check" in p for p in extra_case))

    count_mismatch = compare("Six", REAL_LIVE_SEVEN, REAL_LIVE_SEVEN)
    check("a count word that disagrees with its own list is reported even when live agrees",
          any("Six" in p and "7" in p for p in count_mismatch))

    unknown_word = compare("Umpteen", REAL_LIVE_SEVEN, REAL_LIVE_SEVEN)
    check("an unrecognized count word is reported rather than silently ignored",
          any("Umpteen" in p for p in unknown_word))

    # run(): end-to-end, still fully offline
    exit_code, lines = run.__wrapped__(REGRESSION_DOC_TEXT_SIX, None, _returns(REAL_RULES_PAYLOAD)) \
        if hasattr(run, "__wrapped__") else _run_on_text(REGRESSION_DOC_TEXT_SIX, _returns(REAL_RULES_PAYLOAD))
    check("THE REGRESSION: six-name doc vs real seven-name live goes red (exit 1)", exit_code == 1)
    check("THE REGRESSION: red output names the missing context",
          any("MCP surface contract" in line for line in lines))

    exit_code, lines = _run_on_text(REAL_DOC_TEXT_SEVEN, _returns(REAL_RULES_PAYLOAD))
    check("the corrected seven-name doc vs real live matches (exit 0)", exit_code == 0)

    exit_code, lines = _run_on_text(
        REAL_DOC_TEXT_SEVEN, _raises(urllib.error.URLError("mock DNS failure"))
    )
    check("run() maps Unreachable to exit 0", exit_code == 0)
    check("run() still prints a SKIP line, never a silent pass", any("SKIP" in line for line in lines))

    exit_code, lines = _run_on_text("no sentence here", _returns(REAL_RULES_PAYLOAD))
    check("run() maps an unparseable doc to exit 1", exit_code == 1)

    print("check-required-contexts: self-test %s" % ("PASSED" if not failures else "FAILED on %s" % ", ".join(failures)))
    return 1 if failures else 0


def _run_on_text(text, opener):
    """run(), but against in-memory text instead of a file on disk (self-test only)."""
    try:
        count_word, api_path, doc_contexts = parse_sentence(text)
    except Drift as exc:
        return 1, ["::error::%s" % exc]
    try:
        live_contexts = fetch_required_contexts(api_path, opener=opener)
    except Unreachable as exc:
        return 0, ["::warning::SKIP required-contexts check: %s" % exc, "SKIP: %s" % exc]
    except Drift as exc:
        return 1, ["::error::%s" % exc]
    problems = compare(count_word, doc_contexts, live_contexts)
    if problems:
        lines = ["::error::AGENTS.md's required-contexts sentence disagrees with GitHub:"]
        lines += ["  - %s" % p for p in problems]
        lines.append("doc  (%d): %s" % (len(doc_contexts), ", ".join(doc_contexts)))
        lines.append("live (%d): %s" % (len(live_contexts), ", ".join(live_contexts)))
        return 1, lines
    return 0, ["AGENTS.md's %d required contexts match %s exactly: %s"
               % (len(doc_contexts), api_path, ", ".join(doc_contexts))]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--agents-md", default=default_agents_md(),
        help="path to AGENTS.md (default: the repo root next to scripts/)",
    )
    parser.add_argument(
        "--token", default=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"),
        help="optional bearer token; the read works with none against a public repo",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv[1:])

    if args.self_test:
        return self_test()

    exit_code, lines = run(args.agents_md, args.token)
    for line in lines:
        print(line)
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
