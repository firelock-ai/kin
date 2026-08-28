# Code scanning triage

CodeQL runs on this repository through GitHub's **default setup**, configured in repository
settings rather than in a workflow file. `sast.yml` is `cargo-deny` and runs no CodeQL. There is one
configuration per language, and nothing in the tree changes it.

That has one consequence worth knowing before you try to fix anything here. Default setup reads a
CodeQL configuration file only when the repository property `github-codeql-config-file` names one.
Neither that property nor an organisation property schema exists for this repo, so a
`.github/codeql/codeql-config.yml` committed today would be read by nothing. It would look like
remediation while every alert kept firing. The levers that work are fixing the code, dismissing
through the code-scanning API with a reason, or moving to advanced setup, which replaces default
setup for every configured language and is a deliberate choice rather than a config tweak.

## When the CodeQL check is red on your pull request

**Run this first.** It answers pass or fail before you open a single annotation:

```
gh api 'repos/firelock-ai/kin/code-scanning/analyses?ref=refs/pull/<n>/head&per_page=100' --paginate \
  --jq '[.[] | select(.category=="/language:rust")] | max_by(.created_at).results_count'
```

**CodeQL fails exactly when that number is not zero.** Measured across 19 pull requests on
2026-08-28: 15 with `results_count` 0 all passed, 3 with a non-zero count all failed, and one with
no Rust analysis at all was neutral. Eighteen for eighteen wherever an analysis existed.

### What the number means

The pull-request analysis is **narrower than the one on `main`**, and it grows with the size of the
Rust diff:

| ref | Rust lines changed | `results_count` | CodeQL |
|---|---|---|---|
| `refs/heads/main` | n/a | 71 | n/a |
| a 451-line Rust diff | 451 | 0 | success |
| a 3759-line Rust diff | 3759 | 12 | failure |
| a 9111-line Rust diff | 9111 | 42 | failure |
| an 18349-line Rust diff | 18349 | 42 | failure |

Nothing widens or falls back to a full scan. There is no baseline subtraction anywhere: a passing
pull request passes because its analysis produced nothing, and **every result that does exist is
reported as new**, including alerts that have been sitting on `main` for weeks. The relation
saturates, so past a certain diff size the count stops climbing.

So a red CodeQL check on a large pull request usually means the analysis was wide enough to
re-report existing alerts, not that your change introduced anything.

### Confirming that, rather than assuming it

Read the check-run annotations, which is the surface the check summary points at:

```
gh api repos/firelock-ai/kin/check-runs/<check_run_id>/annotations --paginate \
  --jq '.[] | [.path, (.start_line|tostring), .title] | @tsv'
```

Then compare each annotation against the alerts already open on `main`. Two cautions, both of which
have produced confident wrong answers here:

- **Match on source text, not on line numbers.** An alert's `start_line` from the API is a property
  of the last analysis, not of the current tip, so it goes stale silently whenever the file moves.
  A twin-match keyed on line numbers alone returns a false "not a twin" for any file `main` has
  touched since. Fetch both files and compare the lines, with a deliberately mismatched pair as a
  control.
- **A filter that returns nothing reads exactly like a clean pull request.** Control in both
  directions: run the same call against a pull request whose CodeQL passed and confirm it returns
  zero, and confirm a fabricated check-run id errors rather than returning an empty list.

## Standing dispositions

A triage of all 70 open alerts was completed on 2026-08-28 under **FIR-2837**. Two were real. The
other 67 were dismissed as false positives with per-alert evidence, authorized by the founder.

| rule | disposition | why |
|---|---|---|
| `rust/path-injection` | false positive, except one | CodeQL models the axum `State<Arc<DaemonState>>` extractor as remote input. Almost every flagged path is a `KinLayout` root joined with a compile-time constant, and `KinLayout` is built only by `discover()` walking the local filesystem. |
| `rust/cleartext-logging` | false positive | No credential reaches a sink. Every flagged site is `println!`, `eprintln!`, `assert!` or `panic!`; subscribers write to stderr and `tracing_appender` is not a dependency, so no sink is a log file. |
| `rust/cleartext-transmission` | false positive | A `format!` building a REST path against loopback. The session id is the resource identifier in that path. |
| `rust/uncontrolled-allocation-size` | false positive | Both allocations are bounded on or beside the flagged line. |
| `rust/non-https-url` | false positive | The GCE metadata server is link-local and does not serve HTTPS. |
| `rust/access-invalid-pointer` | false positive, except one | Two are guarded before the dereference. |

**A Kin session id is not a bearer credential**, and that single fact decides most of the cleartext
alerts. `crates/kin-daemon/src/api.rs` states it directly: nothing on a request proves the caller
owns the session, and the session record carries no owner token to check against. The daemon's
actual gate is a separate bearer token.

The two real findings were **FIR-2868**, a scan root taken from a request body and handed to a
directory walk without containment, and **FIR-2867**, a Windows ACL dereference formed before its
type is verified.

## Before you dismiss anything

Dismissal is a repository-level change to the security surface and it is a founder decision, not a
lane's. When it is authorized:

- Read the open count before and after, and report the **after** count as a measurement rather than
  as the number you expected.
- Control the endpoint as a pair. A fabricated alert number must be refused **and** a real one must
  be found, through the same call. A refusal on its own can come from something unrelated, and one
  that reads as a passing control while proving nothing is worse than no control.
- `dismissed_comment` is capped at **280 characters**. Over that, the API returns HTTP 422 and
  dismisses nothing, which at least fails loudly.
- Cite the rule's evidence in each reason, not just the policy. A dismissal without evidence is
  indistinguishable later from one made to clear a check.

## Adding a rule to this page

The open alert set is small enough to enumerate, so keep this page enumerable. If a new rule starts
firing, classify it here with the line that makes it safe quoted, or fix the code. Do not add a
disposition you have not read the source for.
