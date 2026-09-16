// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which interface methods a Go concrete method may be dispatched through.
//!
//! A Go call written `w.Write(p)` where `w` holds an `io.Writer` resolves to
//! the INTERFACE method `Writer.Write`, not to any concrete `Buffer.Write`.
//! That is correct, and it is also what the Go compiler's own reference set
//! does, so a caller query asked for `Buffer.Write` returns nothing for those
//! sites. On the gh CLI at the pre-registered callers protocol's pinned commit
//! that class is 184 call sites over 15 declarations, and Kin returned 0 of
//! them on both tiers.
//!
//! The two halves of the chain the graph already holds:
//!
//! * an interface's method specs are first-class `Method` entities named
//!   `Interface.Method`, contained by the interface
//!   (`kin-parser/src/languages/go.rs`, the `EntityKind::Interface` arm), and
//! * a concrete method is a `Method` entity named `Receiver.Method`, contained
//!   by its receiver type.
//!
//! The half it does not hold is the binding between them. The Go adapter does
//! compute implicit satisfaction from method sets, but only within one file,
//! because both method sets are built inside a single `extract` call over one
//! tree, and it emits the result as a TYPE to TYPE `Implements` edge. A struct
//! in one package and the interface it satisfies in another never produce one,
//! which is the ordinary Go arrangement and the gh arrangement.
//!
//! This module computes the binding at query time from what the graph already
//! persists, so no store migrates and no relation schema changes, the same
//! discipline [`crate::resolution`] uses for its own marker. What it produces
//! is a CANDIDATE and never a fact: Go interface satisfaction is structural, so
//! a concrete method whose type satisfies an interface may be what a call
//! through that interface reaches, and the graph holds nothing that says it
//! was. A caller that presents one of these as a proven caller is lying;
//! [`DISPATCH_FIELD`] exists so a reader can tell the two apart.

use std::collections::{BTreeSet, HashMap, HashSet};

use kin_model::{Entity, EntityFilter, EntityId, EntityKind, GraphStore, LanguageId, RelationKind};

use crate::error::{IndexError, Result};

/// Field name a dispatch candidate is published under on an agent-facing
/// response. Named beside [`crate::resolution::RESOLUTION_FIELD`] rather than
/// folded into it, because the two say different things: a dispatch candidate's
/// call edge may itself be perfectly `type_resolved` onto the interface method,
/// and what is unproven is that the interface value held this concrete type.
pub const DISPATCH_FIELD: &str = "dispatch";

/// The one value [`DISPATCH_FIELD`] currently takes. A row carrying it reached
/// the focal through an interface method the focal's type satisfies, and
/// nothing at the call site proves the dynamic type.
pub const DISPATCH_INTERFACE_CANDIDATE: &str = "interface_candidate";

/// How deep embedded-type expansion follows `Extends` before it stops.
///
/// Go embedding is a DAG in valid code, and the walk is cycle-safe by visited
/// set regardless, so this bounds work on a pathological graph rather than
/// correctness on a healthy one.
const EMBED_EXPANSION_DEPTH: u32 = 8;

/// An interface method a concrete method may be dispatched through, and the
/// interface that binds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchTarget {
    /// The interface whose method set the focal's receiver type satisfies.
    pub interface_id: EntityId,
    /// The interface's declared name, for a reader to recognize.
    pub interface_name: String,
    /// The interface's method spec entity, which is what call sites through
    /// the interface actually resolve to.
    pub interface_method_id: EntityId,
    /// That method spec's qualified name, `Interface.Method`.
    pub interface_method_name: String,
}

/// The method name out of a qualified `Owner.method` entity name.
///
/// Splits at the LAST dot, because a Go receiver type never contains one while
/// a package-qualified embedded name can.
pub fn split_qualified_method(name: &str) -> Option<(&str, &str)> {
    let (owner, method) = name.rsplit_once('.')?;
    if owner.is_empty() || method.is_empty() {
        return None;
    }
    Some((owner, method))
}

/// Whether a type carrying `concrete` satisfies a contract requiring
/// `required`, by method NAME alone.
///
/// An empty contract is not satisfied by anything here. In Go `interface{}` is
/// satisfied by every type, which is true and useless: it would make every call
/// through an empty interface a candidate caller of every method in the
/// repository. A contract with no methods carries no dispatch story, so it is
/// excluded rather than trivially matched.
pub fn method_set_satisfies(required: &BTreeSet<String>, concrete: &BTreeSet<String>) -> bool {
    !required.is_empty() && required.is_subset(concrete)
}

/// The parameter and result counts of a Go method signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoArity {
    /// Declared parameters, counting each name in a grouped parameter
    /// separately, so `Read(p, q []byte)` is two.
    pub params: usize,
    /// Declared results. A bare single result is one, a parenthesised list is
    /// its length, and no result clause is zero.
    pub results: usize,
}

/// Read the arity of `method_name` out of a Go signature.
///
/// Handles both shapes the Go adapter produces: an interface method spec
/// (`Read(p []byte) (n int, err error)`) and a concrete method declaration
/// (`func (b *Buffer) Read(p []byte) (int, error)`), by anchoring on the
/// method name and taking the parentheses that follow it, which skips a
/// receiver clause without needing to recognise one.
///
/// Returns `None` when the signature cannot be read that way. Callers treat
/// that as "no opinion" and keep the candidate, because this filter exists to
/// remove obvious non-matches and a candidate is already published as unproven.
pub fn go_method_arity(signature: &str, method_name: &str) -> Option<GoArity> {
    let bytes = signature.as_bytes();
    let mut search_from = 0usize;
    let open = loop {
        let at = signature.get(search_from..)?.find(method_name)? + search_from;
        let before_is_boundary = at
            .checked_sub(1)
            .and_then(|i| bytes.get(i))
            .is_none_or(|c| !is_go_ident_byte(*c));
        let after = at + method_name.len();
        let after_is_open = signature[after..].trim_start().starts_with('(')
            && bytes
                .get(after)
                .is_some_and(|c| *c == b'(' || c.is_ascii_whitespace());
        if before_is_boundary && after_is_open {
            break after + signature[after..].find('(')?;
        }
        search_from = at + method_name.len().max(1);
        if search_from >= signature.len() {
            return None;
        }
    };

    let (params_inner, params_end) = balanced_paren_span(signature, open)?;
    let params = count_go_parameters(params_inner);

    let tail = signature.get(params_end..)?.trim();
    let results = if tail.is_empty() {
        0
    } else if tail.starts_with('(') {
        let (results_inner, _) = balanced_paren_span(tail, 0)?;
        count_go_parameters(results_inner)
    } else {
        1
    };

    Some(GoArity { params, results })
}

fn is_go_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The text inside the parentheses opening at `open`, and the byte index just
/// past the matching close. `None` when the parentheses never close.
fn balanced_paren_span(text: &str, open: usize) -> Option<(&str, usize)> {
    let mut depth = 0usize;
    for (offset, ch) in text.get(open..)?.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    let close = open + offset;
                    return Some((text.get(open + 1..close)?, close + ch.len_utf8()));
                }
            }
            _ => {}
        }
    }
    None
}

/// How many parameters a Go parameter list declares.
///
/// Counts top-level commas, so a grouped `p, q []byte` is two and a nested
/// `f func(a, b int)` is one. An empty list is zero.
fn count_go_parameters(inner: &str) -> usize {
    if inner.trim().is_empty() {
        return 0;
    }
    let mut depth = 0usize;
    let mut count = 1usize;
    for ch in inner.chars() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

/// The interface methods `focal` may be reached through by dynamic dispatch.
///
/// Empty for anything that is not a Go method on a concrete receiver, and
/// empty when the receiver type satisfies no interface in the graph. Costs one
/// entity query for the repository's Go interfaces plus a `Contains` read per
/// interface; it is not on any default path.
pub fn interface_dispatch_targets<G: GraphStore>(
    store: &G,
    focal: &Entity,
) -> Result<Vec<DispatchTarget>> {
    if focal.kind != EntityKind::Method || focal.language != LanguageId::Go {
        return Ok(Vec::new());
    }
    let Some((_, method_name)) = split_qualified_method(&focal.name) else {
        return Ok(Vec::new());
    };

    let Some(owner) = owner_of_method(store, focal)? else {
        return Ok(Vec::new());
    };
    // An interface method's own callers are already direct callers. Widening
    // one interface method to its siblings would invent dispatch between two
    // contracts that nothing implements.
    if owner.kind == EntityKind::Interface {
        return Ok(Vec::new());
    }

    let concrete_methods = expanded_method_names(store, &owner)?;
    if !concrete_methods.contains(method_name) {
        return Ok(Vec::new());
    }
    let focal_arity = go_method_arity(&focal.signature, method_name);

    let interfaces = store
        .query_entities(&EntityFilter {
            kinds: Some(vec![EntityKind::Interface]),
            languages: Some(vec![LanguageId::Go]),
            ..EntityFilter::default()
        })
        .map_err(|error| IndexError::Graph(error.to_string()))?;

    let mut targets = Vec::new();
    for interface in interfaces {
        if interface.id == owner.id {
            continue;
        }
        let required = expanded_method_names(store, &interface)?;
        if !required.contains(method_name) {
            continue;
        }
        if !method_set_satisfies(&required, &concrete_methods) {
            continue;
        }
        let Some(spec) = interface_method_spec(store, &interface, method_name)? else {
            continue;
        };
        // Structural satisfaction in Go needs identical signatures, and the
        // graph holds signature TEXT rather than resolved types. Arity is the
        // part of that text two packages cannot spell differently, so it is
        // the part worth filtering on. A signature neither side can be read
        // from keeps the candidate, which is what "unproven" already means.
        if let (Some(focal_arity), Some(spec_arity)) =
            (focal_arity, go_method_arity(&spec.signature, method_name))
        {
            if focal_arity != spec_arity {
                continue;
            }
        }
        targets.push(DispatchTarget {
            interface_id: interface.id,
            interface_name: interface.name.clone(),
            interface_method_id: spec.id,
            interface_method_name: spec.name.clone(),
        });
    }
    targets.sort_by(|a, b| {
        a.interface_method_name
            .cmp(&b.interface_method_name)
            .then_with(|| a.interface_method_id.cmp(&b.interface_method_id))
    });
    targets.dedup_by(|a, b| a.interface_method_id == b.interface_method_id);
    Ok(targets)
}

/// The type that `Contains` this method entity.
///
/// Reads the whole edge set rather than [`kin_model::EntityStore::get_relations`],
/// which answers with a node's OUTGOING edges only. The owner is on the incoming
/// side of `Contains`, so the narrower read returns an empty list for every
/// method in the graph and this function would answer `None` always.
fn owner_of_method<G: GraphStore>(store: &G, focal: &Entity) -> Result<Option<Entity>> {
    let relations = store
        .get_all_relations_for_entity(&focal.id)
        .map_err(|error| IndexError::Graph(error.to_string()))?;
    for relation in relations {
        if relation.kind != RelationKind::Contains {
            continue;
        }
        if relation.dst.as_entity() != Some(focal.id) {
            continue;
        }
        let Some(src) = relation.src.as_entity() else {
            continue;
        };
        let owner = store
            .get_entity(&src)
            .map_err(|error| IndexError::Graph(error.to_string()))?;
        if let Some(owner) = owner {
            if matches!(
                owner.kind,
                EntityKind::Class | EntityKind::Interface | EntityKind::TypeAlias
            ) {
                return Ok(Some(owner));
            }
        }
    }
    Ok(None)
}

/// Every method name `owner` offers, including those it gains by embedding.
///
/// Go embedding forwards the embedded type's methods, and the Go adapter
/// records an embed as an `Extends` edge for both structs and interfaces, so
/// one walk serves both the concrete side and the contract side.
fn expanded_method_names<G: GraphStore>(store: &G, owner: &Entity) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut visited: HashSet<EntityId> = HashSet::new();
    let mut frontier = vec![(owner.id, 0u32)];
    visited.insert(owner.id);

    while let Some((current, depth)) = frontier.pop() {
        // Outgoing is the whole question here, so the narrow read is the right
        // one: a type Contains its methods and Extends what it embeds.
        let relations = store
            .get_relations(&current, &[RelationKind::Contains, RelationKind::Extends])
            .map_err(|error| IndexError::Graph(error.to_string()))?;
        for relation in relations {
            if relation.src.as_entity() != Some(current) {
                continue;
            }
            let Some(dst) = relation.dst.as_entity() else {
                continue;
            };
            match relation.kind {
                RelationKind::Contains => {
                    let Some(member) = store
                        .get_entity(&dst)
                        .map_err(|error| IndexError::Graph(error.to_string()))?
                    else {
                        continue;
                    };
                    if member.kind == EntityKind::Method {
                        if let Some((_, method)) = split_qualified_method(&member.name) {
                            names.insert(method.to_string());
                        }
                    }
                }
                RelationKind::Extends if depth < EMBED_EXPANSION_DEPTH => {
                    if visited.insert(dst) {
                        frontier.push((dst, depth + 1));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(names)
}

/// The `Interface.method` spec entity this interface contains.
fn interface_method_spec<G: GraphStore>(
    store: &G,
    interface: &Entity,
    method_name: &str,
) -> Result<Option<Entity>> {
    let relations = store
        .get_relations(&interface.id, &[RelationKind::Contains])
        .map_err(|error| IndexError::Graph(error.to_string()))?;
    for relation in relations {
        if relation.src.as_entity() != Some(interface.id) {
            continue;
        }
        let Some(dst) = relation.dst.as_entity() else {
            continue;
        };
        let Some(member) = store
            .get_entity(&dst)
            .map_err(|error| IndexError::Graph(error.to_string()))?
        else {
            continue;
        };
        if member.kind != EntityKind::Method {
            continue;
        }
        if split_qualified_method(&member.name).is_some_and(|(_, name)| name == method_name) {
            return Ok(Some(member));
        }
    }
    Ok(None)
}

/// Whether interface dispatch is a question worth answering about `focal`.
///
/// True for a Go method on a CONCRETE receiver, which is the only shape
/// [`interface_dispatch_targets`] can ever return a target for. The two empty
/// answers that function gives are different facts, and a surface that reports
/// one at zero needs to tell them apart: a concrete method whose receiver type
/// satisfies no interface has a dispatch story and the answer to it is none,
/// while an interface method spec, a free function or a method in another
/// language has no dispatch story at all. Reporting "satisfies no interface" for
/// `Writer.Write` would be describing the contract as if it were an
/// implementation of itself.
///
/// Costs the one incoming `Contains` read [`interface_dispatch_targets`] already
/// makes, and never the interface scan behind it, so a caller can gate on this
/// before deciding whether to pay for the walk.
pub fn dispatch_applies<G: GraphStore>(store: &G, focal: &Entity) -> Result<bool> {
    if focal.kind != EntityKind::Method || focal.language != LanguageId::Go {
        return Ok(false);
    }
    if split_qualified_method(&focal.name).is_none() {
        return Ok(false);
    }
    let Some(owner) = owner_of_method(store, focal)? else {
        return Ok(false);
    };
    Ok(owner.kind != EntityKind::Interface)
}

/// The entities that call `targets`, keyed by caller, with the interface
/// method each one reached.
///
/// A caller that is the focal itself is dropped: a concrete method calling its
/// own interface contract is not another caller of it.
pub fn dispatch_candidate_callers<G: GraphStore>(
    store: &G,
    focal: &Entity,
    targets: &[DispatchTarget],
) -> Result<Vec<(EntityId, Vec<String>)>> {
    let mut by_caller: HashMap<EntityId, BTreeSet<String>> = HashMap::new();
    for target in targets {
        // The callers are on the INCOMING side, which `get_relations` does not
        // answer: it reads a node's outgoing edges only.
        let relations = store
            .get_all_relations_for_entity(&target.interface_method_id)
            .map_err(|error| IndexError::Graph(error.to_string()))?;
        for relation in relations {
            if relation.kind != RelationKind::Calls {
                continue;
            }
            if relation.dst.as_entity() != Some(target.interface_method_id) {
                continue;
            }
            let Some(caller) = relation.src.as_entity() else {
                continue;
            };
            if caller == focal.id || caller == target.interface_method_id {
                continue;
            }
            by_caller
                .entry(caller)
                .or_default()
                .insert(target.interface_method_name.clone());
        }
    }
    let mut rows: Vec<(EntityId, Vec<String>)> = by_caller
        .into_iter()
        .map(|(caller, via)| (caller, via.into_iter().collect()))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_qualified_method_splits_at_its_last_dot() {
        assert_eq!(
            split_qualified_method("Buffer.Write"),
            Some(("Buffer", "Write"))
        );
        assert_eq!(
            split_qualified_method("ghrepo.Interface.RepoOwner"),
            Some(("ghrepo.Interface", "RepoOwner"))
        );
        assert_eq!(split_qualified_method("Write"), None);
        assert_eq!(split_qualified_method(".Write"), None);
        assert_eq!(split_qualified_method("Buffer."), None);
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    #[test]
    fn a_superset_of_the_contract_satisfies_it() {
        assert!(method_set_satisfies(
            &set(&["Read"]),
            &set(&["Read", "Close", "Seek"])
        ));
        assert!(method_set_satisfies(
            &set(&["Read", "Close"]),
            &set(&["Read", "Close"])
        ));
    }

    #[test]
    fn a_missing_contract_method_does_not_satisfy() {
        assert!(!method_set_satisfies(
            &set(&["Read", "Close"]),
            &set(&["Read"])
        ));
    }

    /// `interface{}` is satisfied by every type in Go, which would make every
    /// call through an empty interface a candidate caller of every method in
    /// the repository.
    #[test]
    fn an_empty_contract_is_satisfied_by_nothing() {
        assert!(!method_set_satisfies(&set(&[]), &set(&["Read"])));
        assert!(!method_set_satisfies(&set(&[]), &set(&[])));
    }

    #[test]
    fn an_interface_method_spec_reports_its_arity() {
        let arity = go_method_arity("Read(p []byte) (n int, err error)", "Read").unwrap();
        assert_eq!(
            arity,
            GoArity {
                params: 1,
                results: 2
            }
        );
    }

    #[test]
    fn a_concrete_declaration_skips_its_receiver_clause() {
        let arity =
            go_method_arity("func (b *Buffer) Read(p []byte) (int, error)", "Read").unwrap();
        assert_eq!(
            arity,
            GoArity {
                params: 1,
                results: 2
            }
        );
    }

    /// The receiver variable can be named after the method. Anchoring on the
    /// first textual hit would read `(r *Reader)` as the parameter list.
    #[test]
    fn a_receiver_named_like_the_method_does_not_capture_the_parameter_list() {
        let arity = go_method_arity("func (read *reader) read(p []byte) error", "read").unwrap();
        assert_eq!(
            arity,
            GoArity {
                params: 1,
                results: 1
            }
        );
    }

    #[test]
    fn a_grouped_parameter_counts_each_name() {
        let arity = go_method_arity("Write(p, q []byte) error", "Write").unwrap();
        assert_eq!(
            arity,
            GoArity {
                params: 2,
                results: 1
            }
        );
    }

    #[test]
    fn a_nested_function_parameter_is_one_parameter() {
        let arity = go_method_arity("Walk(fn func(a, b int) error) error", "Walk").unwrap();
        assert_eq!(
            arity,
            GoArity {
                params: 1,
                results: 1
            }
        );
    }

    #[test]
    fn no_result_clause_is_zero_results() {
        let arity = go_method_arity("Close()", "Close").unwrap();
        assert_eq!(
            arity,
            GoArity {
                params: 0,
                results: 0
            }
        );
    }

    #[test]
    fn a_variadic_parameter_counts_once() {
        let arity =
            go_method_arity("Printf(format string, args ...any) (int, error)", "Printf").unwrap();
        assert_eq!(
            arity,
            GoArity {
                params: 2,
                results: 2
            }
        );
    }

    #[test]
    fn a_signature_the_method_name_is_absent_from_has_no_arity() {
        assert_eq!(
            go_method_arity("func (b *Buffer) Read(p []byte)", "Close"),
            None
        );
    }

    /// The filter only ever removes a candidate, so an unreadable signature has
    /// to be `None` rather than a wrong number that silently drops a real one.
    #[test]
    fn an_unclosed_parameter_list_has_no_arity() {
        assert_eq!(go_method_arity("Read(p []byte", "Read"), None);
    }

    #[test]
    fn a_differing_arity_is_what_the_filter_is_for() {
        let concrete = go_method_arity(
            "func (r *readmeGetter) Get(name string) (*api.RepoReadme, error)",
            "Get",
        )
        .unwrap();
        let contract = go_method_arity("Get(key string, fallback string) string", "Get").unwrap();
        assert_ne!(concrete, contract);
    }
}
