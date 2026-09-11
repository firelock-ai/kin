// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Contract for the downstream compatibility gate's ref resolver.
//!
//! `.github/workflows/kin-db-compat.yml` decides which kin-db grades a PR by
//! running `.github/scripts/resolve-kin-db-compat-ref.py` over the PR body.
//! Nothing else in CI can tell you that resolver is wrong: the gate is green
//! either way, and the only visible difference is WHICH kin-db it built, which
//! is exactly the thing a reader takes on trust.
//!
//! Two failures matter and they fail in opposite directions. A resolver that
//! silently fell back to `main` on a typo would report the PR as compatible
//! with a kin-db that was never asked about it. A resolver that accepted an
//! owner-qualified ref or a URL would let a PR body choose which repository
//! grades it. So the tests below pin an exact refusal for anything that is not
//! a plain branch name, and pin `main` for the absent case, which is what every
//! existing PR relies on.
//!
//! These drive the REAL script the workflow runs, resolved from
//! `CARGO_MANIFEST_DIR`, rather than a copy of its rules. A second copy of a
//! parser is only ever wrong in a way that looks like a passing run.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn script() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".github/scripts/resolve-kin-db-compat-ref.py");
    assert!(
        path.is_file(),
        "the compat gate's resolver is missing at {}; the workflow runs this exact path, so a \
         rename must move this test with it",
        path.display()
    );
    path
}

/// Run the resolver over `body`, returning `Ok(resolved_ref)` or `Err(stderr)`.
fn resolve(body: &str) -> Result<String, String> {
    let mut child = Command::new("python3")
        .arg(script())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect(
            "python3 must be on PATH: the compat gate runs this resolver with it on both CI \
             runners",
        );
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(body.as_bytes())
        .expect("the resolver must accept a body on stdin");
    let output = child.wait_with_output().expect("the resolver must finish");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");
    if output.status.success() {
        Ok(stdout.trim().to_string())
    } else {
        assert!(
            !stderr.trim().is_empty(),
            "a refusal must say why on stderr, or the gate fails with no reason a reader can act on"
        );
        Err(stderr.trim().to_string())
    }
}

/// A body with no directive resolves to `main`, which is what every PR that
/// predates this mechanism depends on.
#[test]
fn a_body_without_the_directive_resolves_to_main() {
    for body in [
        "",
        "Ordinary PR body.\n\nWith paragraphs and a list:\n- one\n- two\n",
        // The words appear, but not as the directive.
        "This PR discusses the kin-db compat ref and kin-db-compat-refs generally.\n",
    ] {
        assert_eq!(
            resolve(body).expect("an absent directive must not be an error"),
            "main",
            "body {body:?} must resolve to main"
        );
    }
}

/// One well-formed directive resolves to exactly the branch it names, wherever
/// it sits in the body and whatever surrounds it.
#[test]
fn one_well_formed_directive_resolves_to_the_branch_it_names() {
    let cases = [
        (
            "kin-db-compat-ref: chore/lane-transferpack-kin-db",
            "chore/lane-transferpack-kin-db",
        ),
        ("Header\n\nkin-db-compat-ref: main\n\nTrailer\n", "main"),
        (
            "kin-db-compat-ref:   feat/collab-apply   \n",
            "feat/collab-apply",
        ),
        ("kin-db-compat-ref: release/v0.6.4\n", "release/v0.6.4"),
    ];
    for (body, expected) in cases {
        assert_eq!(
            resolve(body).unwrap_or_else(|error| panic!("{body:?} must resolve: {error}")),
            expected
        );
    }
}

/// A directive inside a fenced code block is documentation, not an instruction.
///
/// The PR that introduced this mechanism has to explain it, and explaining it
/// means writing the directive down. Without this rule that PR would send the
/// gate off to check out whatever branch its own example named. It is the class
/// where a guard whose own text sits inside what it scans matches itself, and
/// the falsification that matters is deleting the fence rule and watching this
/// go red rather than watching the ordinary cases stay green.
#[test]
fn a_directive_inside_a_code_fence_is_documentation_rather_than_an_instruction() {
    let documented = "Explaining the mechanism:\n\n```\nkin-db-compat-ref: chore/lane-example-kin-db\n```\n\nEnd.\n";
    assert_eq!(
        resolve(documented).expect("a fenced example must not be an error"),
        "main",
        "an example inside a fence must not choose the grader"
    );

    let tilde = "~~~\nkin-db-compat-ref: chore/lane-example-kin-db\n~~~\n";
    assert_eq!(
        resolve(tilde).expect("a tilde fence must behave like a backtick fence"),
        "main"
    );

    // The control, and the half that keeps the rule from being a way to
    // disable the mechanism: a real directive outside the fence still wins,
    // even when a fenced example sits above it.
    let both = "```\nkin-db-compat-ref: chore/lane-example-kin-db\n```\nkin-db-compat-ref: chore/lane-real-kin-db\n";
    assert_eq!(
        resolve(both).expect("a real directive beside an example must resolve"),
        "chore/lane-real-kin-db"
    );
}

/// Anything that names a repository rather than a branch is refused, and each
/// refusal says which rule refused it.
///
/// Asserting the MESSAGE rather than only the refusal is the point, and it was
/// a review finding rather than foresight. The `BRANCH` pattern already rejects
/// every value below, so a test that only asserted "this is refused" stayed
/// green when the specific checks were deleted: they are message refinements
/// over the pattern, not independent guards, and a falsification arm against
/// one of them reddened nothing. Keyed on the message, each check is
/// independently falsifiable and each refusal tells a reader which rule it
/// tripped instead of a generic one.
#[test]
fn a_directive_naming_anything_but_a_branch_is_refused_by_the_rule_that_refuses_it() {
    let cases = [
        ("https://example.invalid/other/repo", "looks like a URL"),
        ("git@example.invalid:other/repo.git", "looks like a URL"),
        ("attacker:main", "is owner-qualified"),
        ("-upload-pack=touch", "is not a plain branch name"),
        ("branch with spaces", "is not a plain branch name"),
        // Every character here is one BRANCH accepts, so this reaches the
        // refname rules rather than being caught by the pattern first.
        ("feature/../etc", "is not a valid git ref name"),
    ];
    for (value, expected) in cases {
        let body = format!("kin-db-compat-ref: {value}");
        match resolve(&body) {
            Ok(resolved) => panic!("{value:?} must be refused, it resolved to {resolved:?}"),
            Err(error) => {
                assert!(
                    error.starts_with("kin-db-compat-ref:"),
                    "a refusal must name itself so a red job points at this mechanism, got: {error}"
                );
                assert!(
                    error.contains(expected),
                    "{value:?} must be refused for {expected:?}, but the reason given was: {error}"
                );
            }
        }
    }
}

/// A full ref path or a bare object name is refused, because
/// `actions/checkout` would honour either.
///
/// This is not a hypothetical. checkout reclassifies a 40 or 64 character hex
/// ref as a commit rather than a branch, and it fetches `refs/pull/<n>/head`,
/// so a directive naming a kin-db pull ref would have graded this PR against
/// whatever that pull request proposed. The workflow also passes
/// `refs/heads/<value>` explicitly, so the two sides agree that the value is a
/// branch; these cases keep the resolver from being the weaker half.
#[test]
fn a_full_ref_path_or_a_bare_object_name_is_refused() {
    let hex40 = "0123456789abcdef0123456789abcdef01234567";
    let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    for value in [
        "refs/heads/main",
        "refs/pull/1/head",
        "refs/tags/v0.6.4",
        hex40,
        hex64,
        &hex40.to_uppercase(),
    ] {
        let body = format!("kin-db-compat-ref: {value}");
        match resolve(&body) {
            Ok(resolved) => panic!("{value:?} must be refused, it resolved to {resolved:?}"),
            Err(error) => assert!(
                error.starts_with("kin-db-compat-ref:"),
                "a refusal must name itself, got: {error}"
            ),
        }
    }
}

/// A line that LOOKS like the directive but is not well formed refuses, rather
/// than silently falling back to `main`.
///
/// This is the failure direction that matters. A mis-cased directive, a space
/// before the colon, or a note trailing the value were all read as "no
/// directive at all", so the gate would have graded the PR against main and
/// reported it compatible with a kin-db the author never asked about, with
/// nothing anywhere saying the line had been ignored. Falling back is worse
/// than refusing, because a refusal is visible and a fallback is not.
///
/// The distinction from the test below is column 0. An INDENTED line is a code
/// block or a list continuation, which a reader reads as prose, so it stays
/// ignored. A line at column 0 that all but spells the directive is someone
/// trying to use the mechanism, so it gets an error rather than silence.
#[test]
fn a_near_miss_directive_refuses_rather_than_falling_back_to_main() {
    // Keyed on the MESSAGE, not merely on the refusal. The trailing-comment case
    // is why: the branch pattern already rejects a value containing `<!--`, so
    // an arm deleting the trailing-comment check on its own reddened NOTHING
    // while this asserted only that the value was refused. That check is a
    // message refinement over the pattern rather than an independent guard, and
    // the same was true of the URL and owner-qualified checks below. Naming the
    // expected reason makes each one falsifiable on its own and tells a reader
    // of a red job which rule tripped.
    let cases = [
        (
            "mis-cased",
            "Kin-DB-Compat-Ref: chore/lane-example-kin-db",
            "looks like the directive",
        ),
        (
            "upper-cased",
            "KIN-DB-COMPAT-REF: chore/lane-example-kin-db",
            "looks like the directive",
        ),
        (
            "space before the colon",
            "kin-db-compat-ref : chore/lane-example-kin-db",
            "looks like the directive",
        ),
        (
            "tab before the colon",
            "kin-db-compat-ref\t: chore/lane-example-kin-db",
            "looks like the directive",
        ),
        (
            "a note trailing the value",
            "kin-db-compat-ref: chore/lane-example-kin-db <!-- for now -->",
            "carries an HTML comment",
        ),
    ];
    for (label, body, expected) in cases {
        match resolve(body) {
            Ok(resolved) => panic!(
                "{label} must be refused, but it resolved to {resolved:?}; a fallback here grades \
                 the PR against a kin-db nobody asked for"
            ),
            Err(error) => {
                assert!(
                    error.starts_with("kin-db-compat-ref:"),
                    "{label} must be refused by name, got: {error}"
                );
                assert!(
                    error.contains(expected),
                    "{label} must be refused for {expected:?}, but the reason given was: {error}"
                );
            }
        }
    }
}

/// The `refs/` refusal is case-insensitive, because `actions/checkout`'s own
/// ref classification is.
///
/// A case-sensitive refusal would pass `REFS/pull/1/head` straight through to a
/// checkout that understands it perfectly well, which is the whole refusal
/// defeated by the shift key.
#[test]
fn the_ref_path_refusal_does_not_depend_on_case() {
    for value in [
        "REFS/heads/main",
        "Refs/pull/1/head",
        "rEfS/tags/v0.6.4",
        "0123456789ABCDEF0123456789ABCDEF01234567",
    ] {
        let body = format!("kin-db-compat-ref: {value}");
        match resolve(&body) {
            Ok(resolved) => panic!("{value:?} must be refused, it resolved to {resolved:?}"),
            Err(error) => assert!(
                error.starts_with("kin-db-compat-ref:"),
                "a refusal must name itself, got: {error}"
            ),
        }
    }
}

/// A directive a reader would not read as an instruction is not one.
///
/// Four shapes, each of which a reader sees as prose or as an example while a
/// naive scanner sees as a line of its own: an indented code block, a fence
/// that does not close where a naive pairing would think it does, an HTML
/// comment, and a separator character Python's `splitlines` treats as a line
/// break while GitHub does not.
#[test]
fn a_directive_a_reader_would_not_read_as_one_is_ignored() {
    let example = "chore/lane-example-kin-db";
    let cases = [
        (
            "four-space indented block",
            format!("Text:\n\n    kin-db-compat-ref: {example}\n\nEnd.\n"),
        ),
        (
            "tab indented block",
            format!("Text:\n\n\tkin-db-compat-ref: {example}\n\nEnd.\n"),
        ),
        (
            "backticks inside tildes",
            format!("~~~\n```\nkin-db-compat-ref: {example}\n```\n~~~\n"),
        ),
        (
            "three inside four",
            format!("````\n```\nkin-db-compat-ref: {example}\n```\n````\n"),
        ),
        (
            "html comment",
            format!("<!--\nkin-db-compat-ref: {example}\n-->\n"),
        ),
        (
            "U+2028 line separator",
            format!("prose\u{2028}kin-db-compat-ref: {example}\nmore\n"),
        ),
        (
            "U+000C form feed",
            format!("prose\u{000C}kin-db-compat-ref: {example}\nmore\n"),
        ),
        (
            "U+0085 next line",
            format!("prose\u{0085}kin-db-compat-ref: {example}\nmore\n"),
        ),
    ];
    for (label, body) in cases {
        assert_eq!(
            resolve(&body).unwrap_or_else(|error| panic!("{label} must not error: {error}")),
            "main",
            "{label}: a reader sees prose or an example here, so CI must not see an instruction"
        );
    }

    // The control, and the half that keeps all of the above from being a way to
    // disable the mechanism: a real directive at column 0 outside every block
    // still wins, even with examples above it.
    let both = format!(
        "```\nkin-db-compat-ref: {example}\n```\n<!-- kin-db-compat-ref: {example} -->\nkin-db-compat-ref: chore/lane-real-kin-db\n"
    );
    assert_eq!(
        resolve(&both).expect("a real directive beside examples must resolve"),
        "chore/lane-real-kin-db"
    );
}

/// A malformed directive is refused rather than quietly falling back to `main`.
///
/// Falling back is the dangerous behaviour, not the inconvenient one: it would
/// grade the PR against a kin-db the author did not ask for and report success.
#[test]
fn a_malformed_directive_is_refused_rather_than_falling_back_to_main() {
    let cases = [
        // Names nothing.
        "kin-db-compat-ref:",
        "kin-db-compat-ref:    \n",
        // Names two things; one branch can be graded, so this is ambiguous.
        "kin-db-compat-ref: one\nkin-db-compat-ref: two\n",
    ];
    for body in cases {
        let error = resolve(body).unwrap_or_else(|error| error);
        assert!(
            error.starts_with("kin-db-compat-ref:"),
            "{body:?} must be refused with a reason, but the resolver answered {error:?}"
        );
    }
}
