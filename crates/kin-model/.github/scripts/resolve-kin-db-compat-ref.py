#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Resolve which kin-db ref the downstream compatibility gate should grade.

The gate builds kin-db against the kin-model on this PR. Grading against
kin-db `main` is right for almost every PR and wrong for exactly one kind: a
change that ADDS a field to a type kin-db constructs by exhaustive struct
literal. kin-db main cannot compile against such a change until it is taught
the field, and it cannot be taught the field until the kin-model version
carrying it is published, because kin-db pins kin-model exactly. Neither side
can go first, and the gate as written had no way to say so.

A PR body may therefore carry one line naming the kin-db branch that carries
the matching change:

    kin-db-compat-ref: chore/lane-example-kin-db

Absent, the answer is `main` and the gate behaves exactly as it always did.

The value may name only a branch of the same repository the workflow already
hardcodes. It is deliberately NOT a repository, a URL, an owner-qualified ref
or a raw sha from elsewhere: the point is to grade against a different branch
of the real consumer, not against a different consumer. Anything else refuses
loudly, because a gate that silently fell back to `main` on a typo would report
the PR as compatible with a kin-db that was never asked about it, which is the
one outcome worse than refusing.

Reads the PR body on stdin. Prints the resolved ref on stdout. Exits non-zero
with the reason on stderr when the body names something this may not resolve.
"""

import re
import sys

# At column 0, deliberately. An indented line is a markdown indented code block
# or a list continuation, which a reader sees as prose or as an example, not as
# an instruction to CI.
DIRECTIVE = re.compile(r"^kin-db-compat-ref:[ \t]*(.*?)[ \t]*$")

# Anything a reader would take FOR the directive, at column 0: any casing, and a
# space before the colon. A line matching this but not `DIRECTIVE` is a near
# miss, and a near miss must refuse rather than fall back to main. Silently
# grading against main because someone typed `Kin-DB-Compat-Ref:` reports the PR
# as compatible with a kin-db nobody asked about, which is the one outcome this
# resolver exists to prevent.
NEAR_MISS = re.compile(r"^kin-db-compat-ref[ \t]*:", re.IGNORECASE)

# A fenced code block delimiter: three or more backticks or tildes, indented up
# to three spaces, which is what markdown accepts.
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")

# A git branch name, and nothing that could name anything else. `:` is excluded
# because `owner:branch` is how a fork is addressed.
BRANCH = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/-]*$")

# A bare object name. actions/checkout reclassifies a 40 or 64 character hex ref
# as a commit rather than a branch, so admitting one would let a directive name
# a commit this repository never reviewed.
BARE_OBJECT_NAME = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")

MAX_LENGTH = 200


def refuse(message: str) -> "None":
    print(f"kin-db-compat-ref: {message}", file=sys.stderr)
    raise SystemExit(1)


def lines(body: str) -> "list[str]":
    """Split on the line endings GitHub splits on, and no others.

    `str.splitlines` also breaks on U+2028, U+000C and U+0085, which GitHub
    does not, so a directive could sit mid-paragraph in a rendered body and
    still be read as its own line here. A reader would see prose; CI would see
    an instruction.
    """
    return [line.rstrip("\r") for line in body.replace("\r\n", "\n").split("\n")]


def directives(body: str) -> "list[str]":
    """Every directive line, ignoring anything a reader would not read as one.

    Skipped: fenced code blocks, HTML comments, and any indented line. The
    fence rule is not a nicety. A PR explaining this mechanism, including the
    one that introduced it, puts an example in a code fence, and a scanner that
    matched its own documentation would send the gate off to check out a branch
    named in an example. That is the class where a guard whose own text sits
    inside what it scans quietly matches itself.

    A fence closes only on the same character and at least as many of them, so
    ``` inside ~~~ and ``` inside ```` stay inside the block they are written
    in rather than closing it.
    """
    found = []
    fence: "str | None" = None
    in_comment = False
    for line in lines(body):
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        if fence is not None:
            closing = FENCE.match(line)
            if closing:
                marker = closing.group(1)
                if marker[0] == fence[0] and len(marker) >= len(fence):
                    fence = None
            continue
        opening = FENCE.match(line)
        if opening:
            fence = opening.group(1)
            continue
        stripped = line.lstrip()
        if stripped.startswith("<!--"):
            # A line that IS a comment. Whole-line comments stay ignored; a
            # comment TRAILING a directive is caught below instead, because
            # ignoring that one would drop a directive its author meant.
            if "-->" not in stripped:
                in_comment = True
            continue
        if not NEAR_MISS.match(line):
            continue
        match = DIRECTIVE.match(line)
        if not match:
            refuse(
                f"`{line.strip()}` looks like the directive but is not one. It reads exactly "
                "`kin-db-compat-ref:` in lower case with no space before the colon, at the start "
                "of the line. Refusing rather than falling back to main, because a fallback here "
                "would grade this PR against a kin-db nobody asked for"
            )
        value = match.group(1)
        if "<!--" in value or "-->" in value:
            refuse(
                f"`{value}` carries an HTML comment; the branch name is the whole of the value, "
                "so put any note on its own line"
            )
        found.append(value)
    return found


def resolve(body: str) -> str:
    matches = directives(body or "")
    if not matches:
        return "main"
    if len(matches) > 1:
        refuse(
            f"the PR body carries {len(matches)} `kin-db-compat-ref:` lines; "
            "exactly one branch can be graded, so name one or none"
        )

    value = matches[0]
    if not value:
        refuse("the `kin-db-compat-ref:` line names no branch")
    if len(value) > MAX_LENGTH:
        refuse(f"branch name is {len(value)} characters, over the {MAX_LENGTH} allowed")
    if "://" in value or value.startswith("git@"):
        refuse(
            f"`{value}` looks like a URL; this names a BRANCH of the kin-db "
            "repository the workflow already pins, never another repository"
        )
    if ":" in value:
        refuse(
            f"`{value}` is owner-qualified; this names a branch of firelock-ai/kin-db, "
            "never a fork"
        )
    if value.lower().startswith("refs/"):
        refuse(
            f"`{value}` is a full ref path; a branch is named without it. `refs/pull/<n>/head` "
            "in particular would grade against whatever some pull request proposes, which is "
            "not a branch anybody reviewed"
        )
    if BARE_OBJECT_NAME.match(value):
        refuse(
            f"`{value}` is a bare object name; actions/checkout reads a 40 or 64 character hex "
            "ref as a commit rather than a branch, so this would grade against a commit no "
            "branch points at"
        )
    if not BRANCH.match(value):
        refuse(f"`{value}` is not a plain branch name")
    # Git's own refname rules, for the subset reachable through the pattern above.
    if ".." in value or "//" in value or value.endswith("/") or value.endswith(".lock"):
        refuse(f"`{value}` is not a valid git ref name")
    return value


def main() -> "None":
    print(resolve(sys.stdin.read()))


if __name__ == "__main__":
    main()
