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
  DRIFT (exit 1)       any of: the sentence could not be found or parsed in `AGENTS.md`; a 404 on
                        the named path (the doc's own claim about the path is wrong); a
                        well-formed, fully-read JSON response that carries no
                        `required_status_checks` rule; or GitHub answered fine and the two lists
                        disagree. Every one of these is a complete, readable answer that is
                        itself wrong, not a failure to get an answer.
  SKIP (exit 0, loud)  GitHub could not be reached, or the read that came back cannot be trusted
                        as a real answer: a connection failure, a timeout, an HTTP status that
                        reads as rate-limiting or a GitHub-side error (401, 403, 429, any 5xx), a
                        connection that reset or truncated mid-read, or a body that did not parse
                        as JSON at all (an HTML error page from a proxy, an empty response, a cut-
                        off stream). None of these says anything about whether the doc is right.
                        This is the one outcome that does not fail the pull request, and it prints
                        `::warning::` plus a `SKIP:` line so it is never mistaken for a pass in
                        the log. A check that exits 0 having read nothing is worse than no check,
                        so this path is narrow on purpose: a 404 is DRIFT, not SKIP, because that
                        specific failure is a complete answer about the doc's own claim.

This gates `Fast gate lint and policy`, a required context every pull request lands through, so a
transient GitHub-side blip must never read as DRIFT, and must never escape as an uncaught
traceback either, which reads exactly like a crash rather than a verdict. Before treating a read
as unreachable, it retries up to three times, two seconds apart, on every shape above that is
plausibly transient; 401 and 404 are never retried, because neither a bad token nor a wrong path
fixes itself between one request and the next. Two defects were found this way, not assumed: a
500 read as DRIFT until kin#1456 was paused for review over exactly that risk, and a follow-up
read confirmed that `urlopen`'s own `HTTPError`/`URLError` wrapping covers only the connect phase,
so a reset connection or a truncated read during `response.read()` (after headers already
arrived, so neither exception type applies) escaped as an uncaught crash, and a body that failed
to parse as JSON (an HTML error page, an empty response) raised DRIFT the same way the 500 did.
Both were confirmed by actually triggering them through `fetch_required_contexts`, not by reading
the code and assuming, before either was fixed.

Falsified with `--self-test`, offline and hermetic: every control below injects a fake network
call and a no-op sleep rather than reaching GitHub or waiting in real time, including the exact
six-doc/seven-live shape of the regression this check exists for.
"""

import argparse
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

API_HOST = "https://api.github.com"

# HTTP statuses worth one more try before giving up and calling the read Unreachable: GitHub's own
# rate limiting or abuse detection (403, 429) and a server-side error on GitHub's end (any 5xx).
# 401 (a bad token) and 404 (the wrong path) are deliberately absent: neither fixes itself between
# one request and the next, so retrying them spends the budget for no chance of a different answer.
RETRYABLE_HTTP_CODES = frozenset({403, 429, 500, 502, 503, 504})
MAX_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 2

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


def fetch_required_contexts(api_path, token=None, timeout=10, opener=None,
                             max_attempts=MAX_ATTEMPTS, sleep=None):
    """Return the live list of required_status_checks contexts, or raise Unreachable/Drift.

    `opener` is a callable(request) -> response, injected in --self-test so the real network is
    never touched there. The default opens the real URL with the given timeout. `sleep` is
    likewise injectable (a no-op in --self-test, so retries never make the offline suite slow);
    the default is the real `time.sleep`.

    Retries up to `max_attempts` times, two seconds apart, on anything plausibly transient: the
    codes in RETRYABLE_HTTP_CODES, the connection failing outright (urlopen wraps a socket
    timeout in URLError, not a bare TimeoutError, confirmed by actually raising one rather than
    assuming the Python docs' shape holds; there is no separate TimeoutError handler here for
    that reason), a failure during response.read() that urlopen's own HTTPError/URLError
    wrapping does not cover (a reset connection, a truncated read, a TLS failure -- confirmed by
    actually raising one, since these happen after the response headers already arrived and
    neither wrapped exception type applies), and a body that fails to parse as JSON (an HTML
    error page from a proxy, an empty response, a cut-off stream). A 404 or a 401 is raised on
    the first attempt with no retry, because neither is transient.
    """
    if opener is None:
        opener = lambda req: urllib.request.urlopen(req, timeout=timeout)  # noqa: E731
    if sleep is None:
        sleep = time.sleep

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

    rules = None
    for attempt in range(1, max_attempts + 1):
        try:
            with opener(request) as response:
                body = response.read()
            rules = json.loads(body)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise Drift(
                    "%s answered %d %s; the path AGENTS.md names may no longer resolve"
                    % (url, exc.code, exc.reason)
                ) from exc
            if exc.code not in RETRYABLE_HTTP_CODES:
                # 401, or any status this endpoint has never been seen to answer with: not a
                # doc problem, and retrying will not turn a permanent refusal into an answer.
                raise Unreachable(
                    "%s answered %d %s; read as an invalid token or an unrecognized refusal, "
                    "not as a doc problem" % (url, exc.code, exc.reason)
                ) from exc
            unreachable = Unreachable(
                "%s answered %d %s after %d attempt(s); read as rate-limited or a GitHub-side "
                "error, not as a doc problem" % (url, exc.code, exc.reason, attempt)
            )
            if attempt < max_attempts:
                sleep(RETRY_DELAY_SECONDS)
                continue
            raise unreachable from exc
        except urllib.error.URLError as exc:
            unreachable = Unreachable(
                "could not reach %s after %d attempt(s): %s" % (url, attempt, exc.reason)
            )
            if attempt < max_attempts:
                sleep(RETRY_DELAY_SECONDS)
                continue
            raise unreachable from exc
        except (OSError, http.client.HTTPException) as exc:
            # Everything urlopen's own HTTPError/URLError wrapping does not cover, because it
            # happens during response.read() rather than at connect: a reset connection, a
            # truncated read (http.client.IncompleteRead), a TLS failure, a timeout landing
            # mid-body. Placed after URLError deliberately: URLError (and HTTPError) are already
            # OSError subclasses, confirmed by inspecting the MRO rather than assumed, so an
            # OSError arm placed earlier would catch them first and lose their specific handling.
            # None of these says anything about whether the doc is right.
            unreachable = Unreachable(
                "reading %s failed after %d attempt(s): %s: %s"
                % (url, attempt, type(exc).__name__, exc)
            )
            if attempt < max_attempts:
                sleep(RETRY_DELAY_SECONDS)
                continue
            raise unreachable from exc
        except json.JSONDecodeError as exc:
            # A truncated body, an HTML error page from a proxy in front of GitHub, or an empty
            # response: GitHub did not hand back a complete answer, which is a transport failure
            # this check could not read past, not evidence the doc's claim is wrong.
            unreachable = Unreachable(
                "%s did not return parseable JSON after %d attempt(s): %s" % (url, attempt, exc)
            )
            if attempt < max_attempts:
                sleep(RETRY_DELAY_SECONDS)
                continue
            raise unreachable from exc

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


def _no_sleep(_seconds):
    """Stands in for time.sleep in every self-test call, so a retryable control proves the
    retry happened (via the call counter below) without making --self-test slow."""


def _counting_opener(fail_times, exc_factory, payload=None):
    """An opener that raises exc_factory() for the first `fail_times` calls, then succeeds with
    `payload` (REAL_RULES_PAYLOAD if omitted). Returns (opener, calls), where calls['count'] is
    how many times the opener was actually invoked, so a control can assert retry happened the
    right number of times rather than merely that no exception escaped."""
    calls = {"count": 0}

    def opener(req):
        calls["count"] += 1
        if calls["count"] <= fail_times:
            raise exc_factory()
        return _FakeResponse(REAL_RULES_PAYLOAD if payload is None else payload)

    return opener, calls


class _FlakyReadResponse:
    """A context-manager response that connects cleanly (so HTTPError/URLError never enter it)
    but whose read() raises for the first `fail_times` calls, sharing one counter with the
    opener that returns it, then returns `payload_bytes`. Models the class of failure
    urlopen's own HTTPError/URLError wrapping does not cover, because it happens after the
    response headers already arrived: a reset connection, a truncated read, a TLS failure."""

    def __init__(self, calls, fail_times, exc_factory, payload_bytes):
        self._calls = calls
        self._fail_times = fail_times
        self._exc_factory = exc_factory
        self._payload_bytes = payload_bytes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        self._calls["count"] += 1
        if self._calls["count"] <= self._fail_times:
            raise self._exc_factory()
        return self._payload_bytes


def _counting_read_opener(fail_times, exc_factory, payload=None):
    """An opener whose response fails `fail_times` times at read() (not at connect), then
    succeeds with `payload` (REAL_RULES_PAYLOAD if omitted). Returns (opener, calls)."""
    calls = {"count": 0}
    payload_bytes = json.dumps(REAL_RULES_PAYLOAD if payload is None else payload).encode("utf-8")

    def opener(req):
        return _FlakyReadResponse(calls, fail_times, exc_factory, payload_bytes)

    return opener, calls


def _returns_raw(raw_bytes):
    """An opener that connects cleanly and returns `raw_bytes` verbatim, not JSON-encoded, for
    testing a body that is not JSON at all (an HTML error page, a truncated response)."""

    class _RawResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return raw_bytes

    return lambda req: _RawResponse()


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

    # fetch_required_contexts, offline via injected openers. sleep is always the no-op stub here:
    # a retryable control must prove the retry happened (via the opener's own call counter, not
    # via elapsed time), and it must not make --self-test slow.
    fetched = fetch_required_contexts("/repos/firelock-ai/kin/rules/branches/main",
                                       opener=_returns(REAL_RULES_PAYLOAD), sleep=_no_sleep)
    check("fetch extracts all seven contexts, ignoring unrelated rule types", fetched == REAL_LIVE_SEVEN)

    # A connection error retries up to MAX_ATTEMPTS times before giving up, same as an HTTP one.
    opener_url, calls_url = _counting_opener(99, lambda: urllib.error.URLError("mock DNS failure"))
    try:
        fetch_required_contexts("/x", opener=opener_url, sleep=_no_sleep)
        check("a connection error raises Unreachable after retrying, not Drift", False)
    except Unreachable:
        check("a connection error raises Unreachable after retrying, not Drift",
              calls_url["count"] == MAX_ATTEMPTS)
    except Drift:
        check("a connection error raises Unreachable after retrying, not Drift", False)

    # 401 is a permanent refusal (a bad token will not fix itself): raised on the first attempt,
    # never retried.
    opener_401, calls_401 = _counting_opener(
        99, lambda: urllib.error.HTTPError("https://api.github.com/x", 401, "bad credentials", None, None)
    )
    try:
        fetch_required_contexts("/x", opener=opener_401, sleep=_no_sleep)
        check("HTTP 401 raises Unreachable without retrying", False)
    except Unreachable:
        check("HTTP 401 raises Unreachable without retrying", calls_401["count"] == 1)
    except Drift:
        check("HTTP 401 raises Unreachable without retrying", False)

    # 403, 429 and every 5xx read as transient and are retried up to MAX_ATTEMPTS times before
    # giving up. 500 is named explicitly, not just folded into the loop, because it is the exact
    # case kin#1456's review paused on: measured as Drift before this fix, which would have
    # stopped a required context on a GitHub-side blip rather than skipped past it.
    for code in (403, 429, 500, 502, 503, 504):
        opener_x, calls_x = _counting_opener(
            99, lambda code=code: urllib.error.HTTPError("https://api.github.com/x", code, "nope", None, None)
        )
        try:
            fetch_required_contexts("/x", opener=opener_x, sleep=_no_sleep)
            check("HTTP %d raises Unreachable after retrying, not Drift" % code, False)
        except Unreachable:
            check("HTTP %d raises Unreachable after retrying, not Drift" % code,
                  calls_x["count"] == MAX_ATTEMPTS)
        except Drift:
            check("HTTP %d raises Unreachable after retrying, not Drift" % code, False)

    # A transient failure that clears within the retry budget returns the real answer instead of
    # raising at all: retry exists to recover a genuine transient blip, not just to spend time
    # before giving up.
    opener_recovers, calls_recovers = _counting_opener(
        2, lambda: urllib.error.HTTPError("https://api.github.com/x", 503, "unavailable", None, None)
    )
    fetched_after_retry = fetch_required_contexts("/x", opener=opener_recovers, sleep=_no_sleep)
    check("a 503 that clears within the retry budget still returns the real answer",
          fetched_after_retry == REAL_LIVE_SEVEN and calls_recovers["count"] == 3)

    # 404 is also never retried: retrying a wrong path cannot make it right, so it is raised (as
    # Drift, not Unreachable, since the path itself is the doc's own claim) on the first attempt.
    opener_404, calls_404 = _counting_opener(
        99, lambda: urllib.error.HTTPError("https://api.github.com/x", 404, "missing", None, None)
    )
    try:
        fetch_required_contexts("/x", opener=opener_404, sleep=_no_sleep)
        check("a 404 on the named path raises Drift without retrying (the path itself is wrong)", False)
    except Drift:
        check("a 404 on the named path raises Drift without retrying (the path itself is wrong)",
              calls_404["count"] == 1)
    except Unreachable:
        check("a 404 on the named path raises Drift without retrying (the path itself is wrong)", False)

    try:
        fetch_required_contexts("/x", opener=_returns([{"type": "deletion"}, {"type": "pull_request"}]),
                                 sleep=_no_sleep)
        check("a response with no required_status_checks rule raises Drift, not empty agreement", False)
    except Drift:
        check("a response with no required_status_checks rule raises Drift, not empty agreement", True)

    # Read-phase failures: urlopen's own HTTPError/URLError wrapping covers only the connect
    # phase. A reset connection or a truncated read during response.read() escaped as an
    # uncaught traceback before this fix, confirmed by actually raising one through
    # fetch_required_contexts, not by reading the code and assuming; kin#1456's review named
    # exactly this class after 589727bb8 closed the 5xx hole.
    for name, exc_factory in (
        ("ConnectionResetError", lambda: ConnectionResetError("Connection reset by peer")),
        ("IncompleteRead", lambda: http.client.IncompleteRead(b"partial")),
    ):
        opener_read, calls_read = _counting_read_opener(99, exc_factory)
        label = "a read-phase %s raises Unreachable after retrying, not an uncaught crash" % name
        try:
            fetch_required_contexts("/x", opener=opener_read, sleep=_no_sleep)
            check(label, False)
        except Unreachable:
            check(label, calls_read["count"] == MAX_ATTEMPTS)
        except Drift:
            check(label, False)
        # No bare `except Exception` guard here, deliberately: if this regresses, the escape
        # itself is the failure signal, an uncaught traceback, the same shape a real crash is.

    # A read-phase failure that clears within the retry budget returns the real answer, not just
    # "did not raise" -- retry exists to recover a genuine transient blip.
    opener_read_recovers, calls_read_recovers = _counting_read_opener(
        2, lambda: ConnectionResetError("Connection reset by peer")
    )
    fetched_after_read_retry = fetch_required_contexts("/x", opener=opener_read_recovers, sleep=_no_sleep)
    check("a read-phase failure that clears within the retry budget still returns the real answer",
          fetched_after_read_retry == REAL_LIVE_SEVEN and calls_read_recovers["count"] == 3)

    # A truncated body, an HTML error page from a proxy, or any non-JSON response is a transport
    # failure this check could not read past, not evidence the doc's claim is wrong.
    try:
        fetch_required_contexts(
            "/x", opener=_returns_raw(b"<html><body>502 Bad Gateway</body></html>"), sleep=_no_sleep
        )
        check("an HTML (non-JSON) body raises Unreachable, not Drift", False)
    except Unreachable:
        check("an HTML (non-JSON) body raises Unreachable, not Drift", True)
    except Drift:
        check("an HTML (non-JSON) body raises Unreachable, not Drift", False)

    try:
        fetch_required_contexts("/x", opener=_returns_raw(b""), sleep=_no_sleep)
        check("an empty body raises Unreachable, not Drift", False)
    except Unreachable:
        check("an empty body raises Unreachable, not Drift", True)
    except Drift:
        check("an empty body raises Unreachable, not Drift", False)

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
    exit_code, lines = _run_on_text(REGRESSION_DOC_TEXT_SIX, _returns(REAL_RULES_PAYLOAD))
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
    """run(), but against in-memory text instead of a file on disk (self-test only). Always
    passes the no-op sleep: every caller here is offline, and a retryable opener must not make
    --self-test slow."""
    try:
        count_word, api_path, doc_contexts = parse_sentence(text)
    except Drift as exc:
        return 1, ["::error::%s" % exc]
    try:
        live_contexts = fetch_required_contexts(api_path, opener=opener, sleep=_no_sleep)
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
