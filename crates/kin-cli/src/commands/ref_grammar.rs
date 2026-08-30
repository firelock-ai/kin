// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The one endpoint grammar every read surface speaks.
//!
//! `kin diff`, `kin blame --ref` and `kin history --ref` all name a point in
//! repository history, and until FIR-3015 each of the first two parsed that name
//! with its own code. `diff.rs` had a `resolve_endpoint` that knew `@`, `ref:`
//! and `ref-hex:`; `ref_lookup.rs` had a `resolve_ref_core` that knew `HEAD~N`,
//! `kin:` and `branch:`. Neither knew the other's forms, and neither knew a
//! short id at all, which is the form `kin history` prints.
//!
//! The npm-mode stranger run met all three halves of that in one sitting and
//! called it the dominant friction of its version control arm. Each refusal was
//! correct about its own resolver and useless to the operator, because the
//! grammar you learn on one surface is not the grammar the next one speaks:
//!
//! ```text
//! kin diff 1971f659d7aa 479aa9b94288
//!   diff endpoint '1971f659d7aa' is not an authority ref, semantic change,
//!   Git object, HEAD, or WORKSPACE
//! ```
//!
//! That twelve-hex string came out of `kin history` one command earlier.
//!
//! So resolution lives here once and both surfaces call it. The unification
//! needs no trait: `ActiveRepositoryAuthority::manager().read_authority()`
//! yields exactly the `AuthorityReadLease` diff already holds, so one function
//! taking a lease and a graph serves both callers.
//!
//! `WORKSPACE` stays in `diff.rs` on purpose. It names the uncommitted working
//! tree rather than a point in history, there is no change id behind it, and
//! blame and history have nothing to do with it.

use anyhow::{anyhow, bail, Context, Result};
use kin_model::{
    GitObjectId, GraphStore, Hash256, RefName, RefTarget, SemanticChangeId,
    WorkspaceId,
};

use super::repository_authority::{parse_git_object_id, parse_ref_name};

/// The shortest prefix that may stand in for a change id.
///
/// Four, matching Git's floor. Shorter than that is far more likely to be a
/// branch name than an id, and the bare-name arm reaches it first anyway.
pub(crate) const MIN_PREFIX: usize = 4;

/// The full width of a semantic change id in hexadecimal.
pub(crate) const CHANGE_ID_HEX: usize = 64;

/// How many candidates an ambiguous-prefix refusal names before it stops.
const AMBIGUITY_PREVIEW: usize = 4;

/// The sentence a selector that matched no arm of the grammar is refused with.
///
/// A constant rather than two literals, and both surfaces' tests assert on this
/// symbol rather than on its text. A surface that forked back to a private
/// parser would write its own wording and those tests would go red, which is the
/// only cheap way to prove the two are still joined.
pub(crate) const UNRESOLVABLE: &str =
    "is not a ref, a semantic change or its unique prefix, an imported Git object, or HEAD";

/// Which arm of the grammar answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectorKind {
    Head,
    Ref,
    Change,
    GitObject,
}

/// One resolved endpoint, with enough provenance for a caller to describe it.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedRef {
    pub change_id: SemanticChangeId,
    /// The ref this came from, when it came from one. `None` after a parent hop,
    /// because the ref names the tip and the hop walked away from it.
    pub ref_name: Option<RefName>,
    pub target: Option<RefTarget>,
    pub kind: SelectorKind,
}

/// A `~N` or `^N` step off the core selector.
#[derive(Debug, Clone, Copy)]
struct ParentHop(usize);

fn ref_error(reference: &str, reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("cannot resolve '{reference}': {reason}")
}

/// Whether `value` could be a change id or a prefix of one.
///
/// Lowercase only. A change id is rendered lowercase everywhere Kin prints one,
/// so accepting uppercase here would mean accepting a string Kin never emits and
/// then having to decide what a mixed-case ref name means.
pub(crate) fn is_change_prefix(value: &str) -> bool {
    (MIN_PREFIX..=CHANGE_ID_HEX).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

/// Split trailing `~N` and `^N` steps off a selector, innermost last.
///
/// Lifted from `ref_lookup.rs` unchanged, which is the point: it used to be
/// reachable from `kin blame` and not from `kin diff`.
fn split_relative_hops(reference: &str) -> Result<(&str, Vec<ParentHop>)> {
    let mut hops = Vec::new();
    let mut rest = reference;
    while let Some(&last) = rest.as_bytes().last() {
        if last == b'^' || last == b'~' {
            hops.push(ParentHop(1));
            rest = &rest[..rest.len() - 1];
            continue;
        }
        if last.is_ascii_digit() {
            let digits_start = rest
                .rfind(|character: char| !character.is_ascii_digit())
                .map(|index| index + 1)
                .unwrap_or(0);
            if digits_start == 0 {
                break;
            }
            let marker = rest.as_bytes()[digits_start - 1];
            if marker != b'^' && marker != b'~' {
                break;
            }
            let count: usize = rest[digits_start..]
                .parse()
                .map_err(|_| ref_error(reference, "parent index is out of range"))?;
            if marker == b'^' {
                if count == 0 {
                    break;
                }
                hops.push(ParentHop(count));
            } else {
                hops.extend(std::iter::repeat_n(ParentHop(1), count));
            }
            rest = &rest[..digits_start - 1];
            continue;
        }
        break;
    }
    Ok((rest, hops))
}

fn apply_parent_hops<G>(
    graph: &G,
    original: &str,
    mut head: SemanticChangeId,
    hops: &[ParentHop],
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    for hop in hops {
        let change = graph
            .get_change(&head)
            .map_err(|error| anyhow!(error.to_string()))?
            .ok_or_else(|| ref_error(original, format!("change {head} not found in history")))?;
        head = *change.parents.get(hop.0 - 1).ok_or_else(|| {
            ref_error(
                original,
                format!(
                    "{head} has {} parent(s), no parent #{}",
                    change.parents.len(),
                    hop.0
                ),
            )
        })?;
    }
    Ok(head)
}

pub(crate) fn parse_change_id(input: &str) -> Result<SemanticChangeId> {
    Ok(SemanticChangeId::from_hash(
        Hash256::from_hex(input).map_err(|error| anyhow!("invalid change hash: {error}"))?,
    ))
}

/// The one change whose id starts with `prefix`, or a refusal that says why not.
///
/// The candidate set is the authority snapshot's own change map, which both
/// callers already hold a lease on. That map IS the repository's history, so a
/// prefix is matched against every change kin holds rather than against the
/// slice reachable from one branch: an id an operator read out of
/// `kin history --ref <branch>` resolves here whatever branch they are standing
/// on. Nothing on disk is consulted; the ids come from graph-owned authority.
///
/// Ambiguity is refused rather than resolved to whichever candidate came first.
/// Picking one would be the worst outcome available: it answers, it looks right,
/// and it silently describes a different point in history than the operator
/// meant.
fn resolve_change_prefix(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    original: &str,
    prefix: &str,
) -> Result<SemanticChangeId> {
    let mut matches = Vec::new();
    for change_id in lease.snapshot().changes.keys() {
        if change_id.to_string().starts_with(prefix) {
            matches.push(*change_id);
            if matches.len() > AMBIGUITY_PREVIEW {
                break;
            }
        }
    }
    // Sorted so an ambiguity refusal names the same candidates in the same order
    // every run. A HashMap's iteration order is not stable and an error message
    // that reshuffles between two runs of one command reads like two different
    // failures.
    matches.sort();
    match matches.len() {
        0 => Err(ref_error(
            original,
            format!(
                "no semantic change in this repository's history begins with '{prefix}'; run \
                 `kin log` to see the changes kin holds"
            ),
        )),
        1 => Ok(matches[0]),
        count => {
            let preview = matches
                .iter()
                .map(|candidate| candidate.to_string()[..12].to_string())
                .collect::<Vec<_>>()
                .join(", ");
            Err(ref_error(
                original,
                format!(
                    "'{prefix}' is ambiguous: at least {count} semantic changes begin with it \
                     ({preview}); use more characters"
                ),
            ))
        }
    }
}

/// The change the workspace's committed base names, if it has one.
fn workspace_head(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    workspace_id: &WorkspaceId,
) -> Result<Option<SemanticChangeId>> {
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| &workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            anyhow!("this repository has no workspace {workspace_id} in its authority")
        })?;
    workspace
        .base_target
        .as_ref()
        .map(|target| lease.resolve_target_change_id(target))
        .transpose()
        .context("resolve the workspace's committed base")
}

/// Resolve a ref name the authority is expected to hold.
fn resolve_named(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    original: &str,
    name: RefName,
) -> Result<ResolvedRef> {
    let target = lease
        .resolve_ref_target(&name)
        .with_context(|| format!("resolve repository ref '{name}'"))?
        .ok_or_else(|| ref_error(original, format!("repository ref '{name}' was not found")))?;
    let change_id = lease
        .resolve_target_change_id(&target)
        .with_context(|| format!("resolve repository ref '{name}' semantic target"))?;
    Ok(ResolvedRef {
        change_id,
        ref_name: Some(name),
        target: Some(target),
        kind: SelectorKind::Ref,
    })
}

/// Resolve an imported Git object.
///
/// Reads `external_objects` as well as `aliases`. `diff.rs` already read both
/// and `ref_lookup.rs` read only the aliases, so unifying on the superset means
/// `kin blame --ref` gains the external-object arm it never had.
fn resolve_git_object(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    original: &str,
    oid: GitObjectId,
) -> Result<ResolvedRef> {
    let target = lease
        .metadata()
        .external_objects
        .iter()
        .find(|record| record.object.oid == oid)
        .map(|record| RefTarget::external_object(record.object))
        .or_else(|| {
            lease
                .metadata()
                .aliases
                .iter()
                .find(|alias| alias.oid == oid)
                .map(|alias| RefTarget::change(alias.change_id))
        })
        .ok_or_else(|| {
            ref_error(
                original,
                format!(
                    "Git object '{oid}' was never imported into this repository, so kin holds no \
                     semantic change for it; import it with `kin init` in the source checkout, or \
                     name a ref kin already holds"
                ),
            )
        })?;
    let change_id = lease
        .resolve_target_change_id(&target)
        .with_context(|| format!("resolve Git object '{oid}' semantic target"))?;
    Ok(ResolvedRef {
        change_id,
        ref_name: None,
        target: Some(target),
        kind: SelectorKind::GitObject,
    })
}

/// A change that must already be in the graph the caller will read it from.
fn resolve_present_change<G>(
    graph: &G,
    original: &str,
    change_id: SemanticChangeId,
) -> Result<ResolvedRef>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if graph
        .get_change(&change_id)
        .map_err(|error| anyhow!(error.to_string()))?
        .is_none()
    {
        return Err(ref_error(
            original,
            format!(
                "semantic change {change_id} is not in this repository's authority; run `kin log` \
                 to see the changes kin holds"
            ),
        ));
    }
    Ok(ResolvedRef {
        change_id,
        ref_name: None,
        target: Some(RefTarget::change(change_id)),
        kind: SelectorKind::Change,
    })
}

/// Resolve one endpoint selector against repository authority.
///
/// This is the whole grammar, in one place, for every surface that names a point
/// in history. The arms are ordered, and the order is load-bearing:
///
///   1. `HEAD` and `@`, the workspace's committed base
///   2. explicitly tagged forms, `ref-hex:`, `ref:`, `branch:`, `kin:`,
///      `change:` and `git:`, which say what they are and are never guessed at
///   3. a bare value, which prefers an exact ref, then a semantic change, then
///      an imported Git object, then a unique change-id prefix
///
/// A bare value prefers a ref because that matches Git's ordinary branch UX and
/// because a branch is a thing a person named on purpose. The prefix arm is last
/// for the same reason in reverse: it is the only arm that can be ambiguous, so
/// nothing that can be resolved exactly should ever reach it.
pub(crate) fn resolve<G>(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    graph: &G,
    workspace_id: &WorkspaceId,
    input: &str,
) -> Result<ResolvedRef>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if input.contains("@{") {
        return Err(ref_error(
            input,
            "reflog and upstream '@{...}' syntax is not supported",
        ));
    }

    let (core, hops) = split_relative_hops(input)?;
    let resolved = resolve_core(lease, graph, workspace_id, input, core)?;
    if hops.is_empty() {
        return Ok(resolved);
    }

    // Past a parent hop the ref no longer describes the answer: the ref names a
    // tip and the hop walked away from it. Reporting `main` for `main~2` would
    // put a true name on a false claim.
    let change_id = apply_parent_hops(graph, input, resolved.change_id, &hops)?;
    Ok(ResolvedRef {
        change_id,
        ref_name: None,
        target: Some(RefTarget::change(change_id)),
        kind: SelectorKind::Change,
    })
}

fn resolve_core<G>(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    graph: &G,
    workspace_id: &WorkspaceId,
    original: &str,
    core: &str,
) -> Result<ResolvedRef>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if matches!(core, "HEAD" | "@") {
        let change_id = workspace_head(lease, workspace_id)?.ok_or_else(|| {
            ref_error(
                original,
                "this workspace has no commits yet, so HEAD names nothing; make one with \
                 `kin commit`",
            )
        })?;
        return Ok(ResolvedRef {
            change_id,
            ref_name: None,
            target: Some(RefTarget::change(change_id)),
            kind: SelectorKind::Head,
        });
    }

    if let Some(hex_name) = core.strip_prefix("ref-hex:") {
        if hex_name.is_empty()
            || hex_name != hex_name.to_ascii_lowercase()
            || !hex_name.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("ref-hex selector must use non-empty canonical lowercase hexadecimal bytes");
        }
        let bytes = hex::decode(hex_name).context("decode ref-hex selector")?;
        let name =
            RefName::from_bytes(bytes).map_err(|error| anyhow!("invalid ref-hex selector: {error}"))?;
        return resolve_named(lease, original, name);
    }

    if let Some(value) = core
        .strip_prefix("ref:")
        .or_else(|| core.strip_prefix("branch:"))
    {
        return resolve_named(lease, original, parse_ref_name(value)?);
    }

    if let Some(value) = core
        .strip_prefix("kin:")
        .or_else(|| core.strip_prefix("change:"))
    {
        let change_id = if value.len() == CHANGE_ID_HEX {
            parse_change_id(value).map_err(|error| ref_error(original, error.to_string()))?
        } else if is_change_prefix(value) {
            resolve_change_prefix(lease, original, value)?
        } else {
            return Err(ref_error(
                original,
                format!(
                    "'{value}' is not a semantic change id or a prefix of one; ids are {CHANGE_ID_HEX} \
                     lowercase hexadecimal characters and a prefix must be at least {MIN_PREFIX}"
                ),
            ));
        };
        return resolve_present_change(graph, original, change_id);
    }

    if let Some(value) = core.strip_prefix("git:") {
        return resolve_git_object(lease, original, parse_git_object_id(value)?);
    }

    // A bare value prefers an exact ref, so a branch someone named stays a
    // branch even when its name happens to look like hexadecimal.
    if let Ok(name) = parse_ref_name(core) {
        if lease.resolve_ref_target(&name)?.is_some() {
            return resolve_named(lease, original, name);
        }
    }

    if core.len() == CHANGE_ID_HEX && core.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        if let Ok(change_id) = parse_change_id(core) {
            if graph
                .get_change(&change_id)
                .map_err(|error| anyhow!(error.to_string()))?
                .is_some()
            {
                return resolve_present_change(graph, original, change_id);
            }
        }
    }

    // Exactly 40 or 64 hexadecimal characters is a whole Git object id and
    // nothing else: a change id of that width was already tried above, and a
    // prefix arm cannot help a value that is already full width.
    if matches!(core.len(), 40 | CHANGE_ID_HEX) && core.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return resolve_git_object(lease, original, parse_git_object_id(core)?);
    }

    if is_change_prefix(core) {
        let change_id = resolve_change_prefix(lease, original, core)?;
        return resolve_present_change(graph, original, change_id);
    }

    Err(ref_error(original, UNRESOLVABLE))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two files that must not grow a parser of their own again.
    ///
    /// Resolved from `CARGO_MANIFEST_DIR`, so the test grades the tree it was
    /// compiled from rather than whichever checkout the runner happens to be
    /// standing in.
    const DIFF_SOURCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/commands/diff.rs");
    const REF_LOOKUP_SOURCE: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/commands/ref_lookup.rs");

    /// Tagged forms this module owns. A surface that recognised any of these on
    /// its own would be a second grammar, which is the defect FIR-3015 fixed.
    const OWNED_PREFIXES: &[&str] = &[
        "\"kin:\"",
        "\"change:\"",
        "\"branch:\"",
        "\"ref:\"",
        "\"ref-hex:\"",
        "\"git:\"",
    ];

    #[test]
    fn parent_hops_split_off_every_shape_git_accepts() {
        for (input, core, hops) in [
            ("HEAD", "HEAD", 0),
            ("HEAD~", "HEAD", 1),
            ("HEAD^", "HEAD", 1),
            ("HEAD~1", "HEAD", 1),
            ("HEAD~3", "HEAD", 3),
            ("HEAD^2", "HEAD", 1),
            ("HEAD~2^", "HEAD", 3),
            ("main~1", "main", 1),
        ] {
            let (parsed_core, parsed_hops) = split_relative_hops(input).unwrap();
            assert_eq!(parsed_core, core, "core of {input}");
            assert_eq!(parsed_hops.len(), hops, "hop count of {input}");
        }
    }

    /// A name that merely ends in digits is not a hop, or `v2` would resolve to
    /// the parent of `v`.
    #[test]
    fn a_trailing_digit_without_a_marker_is_part_of_the_name() {
        let (core, hops) = split_relative_hops("release2").unwrap();
        assert_eq!(core, "release2");
        assert!(hops.is_empty(), "release2 is a branch name, not a hop");
    }

    #[test]
    fn a_change_prefix_is_lowercase_hex_of_a_workable_width() {
        assert!(is_change_prefix("dead"), "four characters is the floor");
        assert!(is_change_prefix("1971f659d7aa"), "the width kin history prints");
        assert!(is_change_prefix(&"a".repeat(CHANGE_ID_HEX)), "a full id is its own prefix");
        assert!(!is_change_prefix("dea"), "three characters is below the floor");
        assert!(
            !is_change_prefix(&"a".repeat(CHANGE_ID_HEX + 1)),
            "longer than an id is not a prefix of one"
        );
        assert!(!is_change_prefix("DEADBEEF"), "kin never prints uppercase ids");
        assert!(!is_change_prefix("deadbeeg"), "g is not hexadecimal");
        assert!(!is_change_prefix("main"), "a branch name is not a prefix");
    }

    /// The join: `kin diff` and `kin blame --ref` resolve through this module
    /// and hold no grammar of their own.
    ///
    /// FIR-3015 happened because they each had a parser and nothing compared
    /// them. This reads the two files and requires one call into `resolve` and
    /// zero of the tagged prefixes this module owns. Mutating either surface
    /// back to a private copy turns it red, which is the only cheap way to prove
    /// the two are still joined.
    ///
    /// The needles cannot match this test itself, because the files read are the
    /// other two. The positive control is the assertion that this module DOES
    /// carry every needle: without it, a typo in a needle would report both
    /// surfaces clean and the check would pass over any code at all.
    #[test]
    fn diff_and_blame_resolve_through_this_module_and_hold_no_grammar_of_their_own() {
        let grammar = include_str!("ref_grammar.rs");
        for needle in OWNED_PREFIXES {
            assert!(
                grammar.contains(needle),
                "CONTROL: {needle} is not in ref_grammar.rs, so the absence checks below \
                 are searching for something that exists nowhere and cannot fail"
            );
        }

        for path in [DIFF_SOURCE, REF_LOOKUP_SOURCE] {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("read {path}: {error}"));
            assert_eq!(
                source.matches("ref_grammar::resolve(").count(),
                1,
                "{path} must reach repository history through exactly one call to the \
                 shared resolver"
            );
            for needle in OWNED_PREFIXES {
                assert!(
                    !source.contains(needle),
                    "{path} recognises {needle} on its own, which is a second grammar; \
                     FIR-3015 is exactly what two of those cost"
                );
            }
        }
    }
}
