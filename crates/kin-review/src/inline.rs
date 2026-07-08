// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::BTreeMap;

use kin_model::entity::{Entity, EntityKind, EntityRole, Visibility};
use kin_model::ids::EntityId;
use kin_model::Hash256;
use serde::{Deserialize, Serialize};

use crate::diff::{EntityChangeKind, SemanticDiff};
use crate::impact::{ConsumerCallShapeSummary, ImpactReport};

const COMMAND_EFFECT_CONTRACT_KEY: &str = "command_effect_contract";

/// A review comment anchored to a specific source location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineComment {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub kind: InlineCommentKind,
    pub message: String,
}

/// Classification of an inline review comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InlineCommentKind {
    Breaking,
    /// A contract-surface change whose every graph-known consumer was itself
    /// modified in the reviewed range — a coherent in-diff migration. Visible
    /// evidence, but not a blocking break: nothing external was stranded.
    BreakingMigrated,
    CoverageGap,
    ContractViolation,
    CommandEffectContract,
    SignatureChange,
    VisibilityChange,
    ConsumerFanout,
    /// A body-only change with wide consumer fanout whose new body is provably
    /// behavior-equivalent to the old (docstring / comment / formatting only,
    /// per the graph-owned equivalence class). Reported as informational
    /// evidence — the fanout is real but carries no behavior risk — so it never
    /// feeds the gate. Downgraded sibling of [`ConsumerFanout`].
    ConsumerFanoutEquivalent,
    Added,
    Removed,
    Renamed,
    AgentUnreviewed,
    ToolchainSurfaceChange,
    RevertHistory,
    RevertHistoryIncidental,
}

impl InlineCommentKind {
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Breaking => "!!",
            Self::BreakingMigrated => "~",
            Self::ContractViolation => "!!",
            Self::CommandEffectContract => "~",
            Self::CoverageGap => "?",
            Self::SignatureChange => "~",
            Self::VisibilityChange => "~",
            Self::ConsumerFanout => "~",
            Self::ConsumerFanoutEquivalent => "~",
            Self::Added => "+",
            Self::Removed => "-",
            Self::Renamed => "~",
            Self::AgentUnreviewed => "@",
            Self::RevertHistory => "~",
            Self::RevertHistoryIncidental => "~",
            Self::ToolchainSurfaceChange => "~",
        }
    }
}

/// Distinct non-test consumer ENTITIES at or above which a public body-only
/// modification (signature and visibility unchanged) emits a consumer-fanout
/// attention comment. The decision is graph-native — it counts consuming
/// entities (typed inbound edges), not the files they happen to live in; a body
/// change reaching a single consumer is ordinary local iteration. Private
/// helper body changes are reported through coverage/evidence context, but do
/// not gate unless their contract surface changes. The signature channels own
/// contract-surface changes.
pub const CONSUMER_FANOUT_THRESHOLD: usize = 2;

/// Qualifiers whose ADDITION strengthens a declaration without invalidating
/// any existing caller. Removal of one is a real surface change.
const STRENGTHENING_QUALIFIERS: &[&str] = &["constexpr", "inline", "[[nodiscard]]"];

/// True for roles that are not a contract surface: a test's, a generated
/// artifact's, or a vendored copy's declaration is consumed by nothing the
/// review protects, so a signature/visibility change to one is not a
/// downstream risk and must not produce a gate-feeding surface finding.
/// Mirrors the consumer-exclusion set the impact harvest already applies.
pub(crate) fn is_non_contract_surface_role(role: EntityRole) -> bool {
    matches!(
        role,
        EntityRole::Test | EntityRole::Generated | EntityRole::Vendored
    )
}

/// True when `old` → `new` differs ONLY by adding strengthening qualifiers:
/// the qualifier-stripped declarations are identical and `new` carries more
/// strengthening qualifiers than `old`.
pub fn signature_strengthened_only(old: &str, new: &str) -> bool {
    if old == new {
        return false;
    }
    fn strip(sig: &str) -> (String, usize) {
        let mut removed = 0usize;
        let kept: Vec<&str> = sig
            .split_whitespace()
            .filter(|tok| {
                if STRENGTHENING_QUALIFIERS.contains(tok) {
                    removed += 1;
                    false
                } else {
                    true
                }
            })
            .collect();
        (kept.join(" "), removed)
    }
    let (old_core, old_quals) = strip(old);
    let (new_core, new_quals) = strip(new);
    old_core == new_core && new_quals > old_quals
}

/// True when a textual signature delta changes no runtime call contract.
///
/// Python type annotations are useful surface information, but adding or
/// tightening them does not change the callable argument contract at runtime.
/// The graph still records the changed body/signature text; the review gate just
/// must not turn annotation-only edits into breaking downstream-risk findings.
pub fn signature_runtime_neutral(old: &str, new: &str) -> bool {
    if old == new {
        return false;
    }
    signature_strengthened_only(old, new)
        || python_signatures_runtime_neutral(old, new)
        || go_struct_field_addition_only(old, new)
}

/// The callable name and normalized parameter list of a Python `def`, or
/// `None` when the text is not one. Annotations, comments, and whitespace are
/// normalized away so two annotation-only variants compare equal.
fn python_signature_parts(signature: &str) -> Option<(String, Vec<String>)> {
    let without_comment = signature.split('#').next().unwrap_or(signature).trim();
    let def_pos = without_comment.find("def ")?;
    let after_def = &without_comment[def_pos + 4..];
    let name_end = after_def.find('(')?;
    let name = after_def[..name_end].trim();
    if name.is_empty() {
        return None;
    }

    let params_start = def_pos + 4 + name_end;
    let params_end = matching_paren(without_comment, params_start)?;
    let params = &without_comment[params_start + 1..params_end];
    let params = split_python_params(params)
        .into_iter()
        .map(|param| normalize_python_param(&param))
        .collect::<Vec<_>>();
    Some((name.to_string(), params))
}

/// True when `old` → `new` preserves the Python runtime call contract: same
/// callable, and either identical normalized parameters (annotation- or
/// default-format-only edit) or `new` only APPENDS trailing parameters that
/// each add no required argument — a default value or a `*`/`*args`/`**kwargs`
/// marker. Existing positional and keyword call sites stay valid. Reordering,
/// renaming, retyping, or removing a parameter — or appending a required one —
/// is never neutral.
fn python_signatures_runtime_neutral(old: &str, new: &str) -> bool {
    let (Some((old_name, old_params)), Some((new_name, new_params))) =
        (python_signature_parts(old), python_signature_parts(new))
    else {
        return false;
    };
    if old_name != new_name {
        return false;
    }
    if old_params == new_params {
        return true;
    }
    if new_params.len() <= old_params.len() || new_params[..old_params.len()] != old_params[..] {
        return false;
    }
    new_params[old_params.len()..]
        .iter()
        .all(|param| python_param_adds_no_required_arg(param))
}

/// A normalized Python parameter that a caller can omit: it carries a default
/// (`name=…`) or is a `*`, `/`, `*args`, or `**kwargs` marker rather than a
/// bare required parameter.
fn python_param_adds_no_required_arg(param: &str) -> bool {
    let param = param.trim();
    param.contains('=') || param == "/" || param.starts_with('*')
}

/// The call-contract role of a normalized Python parameter. A rename is only
/// caller-relevant when the position keeps its role; reclassifying a position
/// (e.g. a normal parameter becoming `*args`) is a structural change, not a
/// rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PyParamRole {
    /// A by-name/by-position parameter (`name`, `name=default`).
    Normal,
    /// Variadic positional collector (`*args`).
    VarPositional,
    /// Variadic keyword collector (`**kwargs`).
    VarKeyword,
    /// A bare `*` or `/` boundary marker.
    Marker,
}

/// Classify a normalized Python parameter by call-contract role.
fn python_param_role(param: &str) -> PyParamRole {
    if param == "*" || param == "/" {
        PyParamRole::Marker
    } else if param.starts_with("**") {
        PyParamRole::VarKeyword
    } else if param.starts_with('*') {
        PyParamRole::VarPositional
    } else {
        PyParamRole::Normal
    }
}

/// The bare identifier of a normalized Python parameter, with any splat prefix
/// and default value stripped. Boundary markers (`*`, `/`) have no identifier
/// and yield an empty string.
fn python_param_identifier(param: &str) -> &str {
    if param == "*" || param == "/" {
        return "";
    }
    let stripped = param
        .strip_prefix("**")
        .or_else(|| param.strip_prefix('*'))
        .unwrap_or(param);
    match stripped.find('=') {
        Some(idx) => &stripped[..idx],
        None => stripped,
    }
}

/// When `old` → `new` is an arity-preserving pure parameter RENAME of the same
/// Python `def` — same callable name, same parameter count, every position
/// keeps its role, and at least one normal parameter's identifier changes —
/// returns the OLD identifiers of the renamed normal positions. Returns `None`
/// otherwise.
///
/// The result is the set of names whose by-keyword call sites a rename could
/// strand, so a caller-shape check can decide whether the rename is actually
/// runtime-neutral. Excluded, because they are not caller-safe renames or not
/// renames at all:
/// - reorders — a new identifier that reuses any old parameter's identifier;
///   swapping positions changes positional call semantics, not just names;
/// - role changes at any position (normal ↔ `*args`/`**kwargs`/marker);
/// - retype- or default-only edits (identifier unchanged);
/// - arity changes or non-`def` text.
///
/// Renames of `*args`/`**kwargs` collectors are not reported: no caller can
/// target them by name, so renaming one strands nothing. Positions are visited
/// left to right, so the returned order is deterministic.
pub fn arity_preserving_rename(old: &str, new: &str) -> Option<Vec<String>> {
    if old == new {
        return None;
    }
    let (old_name, old_params) = python_signature_parts(old)?;
    let (new_name, new_params) = python_signature_parts(new)?;
    if old_name != new_name || old_params.len() != new_params.len() {
        return None;
    }
    let old_identifiers: std::collections::BTreeSet<&str> = old_params
        .iter()
        .map(|p| python_param_identifier(p))
        .filter(|id| !id.is_empty())
        .collect();

    let mut renamed = Vec::new();
    for (old_param, new_param) in old_params.iter().zip(new_params.iter()) {
        let old_role = python_param_role(old_param);
        if old_role != python_param_role(new_param) {
            return None;
        }
        let old_id = python_param_identifier(old_param);
        let new_id = python_param_identifier(new_param);
        if old_id == new_id {
            continue;
        }
        if old_role != PyParamRole::Normal {
            // Renaming a `*args`/`**kwargs` collector strands no caller.
            continue;
        }
        if old_identifiers.contains(new_id) {
            // The new name reuses an existing parameter name: a reorder, which
            // changes positional semantics and is never a safe rename.
            return None;
        }
        renamed.push(old_id.to_string());
    }

    if renamed.is_empty() {
        None
    } else {
        Some(renamed)
    }
}

/// True when an arity-preserving rename of `renamed_old_names` strands no
/// graph-known consumer: every consumer is a shaped call site, none forwards
/// `**kwargs`, and none passes a renamed parameter by keyword. Any gap in the
/// evidence is conservative — the rename stays potentially breaking.
pub fn rename_is_runtime_neutral_for_consumers(
    renamed_old_names: &[String],
    summary: &ConsumerCallShapeSummary,
) -> bool {
    summary.all_consumers_shaped_calls
        && !summary.any_var_keyword_caller
        && renamed_old_names
            .iter()
            .all(|name| !summary.caller_keyword_names.contains(name.as_str()))
}

/// True when `old` and `new` are Go struct type signatures that differ ONLY by
/// added fields: identical `Name struct` header, and every whitespace token of
/// the old field body still appears, in order, inside a strictly larger new
/// body. A consumer reading existing fields by name cannot be broken by the
/// additions. Removing, renaming, reordering, or retyping a field breaks the
/// ordered-subsequence match and is never neutral.
fn go_struct_field_addition_only(old: &str, new: &str) -> bool {
    let (Some((old_header, old_body)), Some((new_header, new_body))) =
        (go_struct_parts(old), go_struct_parts(new))
    else {
        return false;
    };
    if old_header != new_header {
        return false;
    }
    let old_tokens: Vec<&str> = old_body.split_whitespace().collect();
    let new_tokens: Vec<&str> = new_body.split_whitespace().collect();
    new_tokens.len() > old_tokens.len() && is_ordered_subsequence(&old_tokens, &new_tokens)
}

/// Split a Go `Name struct { … }` signature into its header (`Name struct`)
/// and brace-delimited field body. `None` unless the `struct` keyword directly
/// precedes the field brace, which excludes Rust's `struct Name { … }` form
/// (a name sits between keyword and brace) and partial-word matches.
fn go_struct_parts(signature: &str) -> Option<(&str, &str)> {
    let struct_kw = signature.find("struct")?;
    let after_kw = struct_kw + "struct".len();
    let brace_open = signature[after_kw..].find('{')? + after_kw;
    if !signature[after_kw..brace_open].trim().is_empty() {
        return None;
    }
    let brace_close = matching_brace(signature, brace_open)?;
    let header = signature[..brace_open].trim_end();
    let body = signature[brace_open + 1..brace_close].trim();
    Some((header, body))
}

fn matching_brace(input: &str, open_byte: usize) -> Option<usize> {
    if input.as_bytes().get(open_byte).copied() != Some(b'{') {
        return None;
    }
    let mut depth = 0i32;
    for (idx, ch) in input.char_indices().skip_while(|(idx, _)| *idx < open_byte) {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

/// True when `needle`'s items appear in `haystack` in order (not necessarily
/// contiguously): `haystack` is `needle` with insertions only.
fn is_ordered_subsequence(needle: &[&str], haystack: &[&str]) -> bool {
    let mut haystack = haystack.iter();
    needle.iter().all(|tok| haystack.any(|hay| hay == tok))
}

fn matching_paren(input: &str, open_byte: usize) -> Option<usize> {
    if input.as_bytes().get(open_byte).copied() != Some(b'(') {
        return None;
    }
    let mut depth = 0i32;
    for (idx, ch) in input.char_indices().skip_while(|(idx, _)| *idx < open_byte) {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_python_params(params: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in params.chars() {
        if let Some(q) = quote {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                current.push(ch);
            }
            '[' | '(' | '{' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' | ')' | '}' => {
                bracket_depth -= 1;
                current.push(ch);
            }
            ',' if bracket_depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

fn normalize_python_param(param: &str) -> String {
    let trimmed = param.trim();
    let (before_default, default) = match top_level_char(trimmed, '=') {
        Some(idx) => (&trimmed[..idx], Some(&trimmed[idx + 1..])),
        None => (trimmed, None),
    };
    let name = match top_level_char(before_default, ':') {
        Some(idx) => before_default[..idx].trim(),
        None => before_default.trim(),
    };
    let name = name.split_whitespace().collect::<String>();
    match default {
        Some(default) => format!("{name}={}", default.split_whitespace().collect::<String>()),
        None => name,
    }
}

fn top_level_char(input: &str, needle: char) -> Option<usize> {
    let mut bracket_depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' | '(' | '{' => bracket_depth += 1,
            ']' | ')' | '}' => bracket_depth -= 1,
            _ if ch == needle && bracket_depth == 0 => return Some(idx),
            _ => {}
        }
    }
    None
}

/// Collect line-level inline comments from a review's diff and impact data.
///
/// Each comment is anchored to a file + line range derived from the entity's
/// `SourceSpan`. Entities without a span are skipped (they have no file location
/// to anchor to).
pub fn collect_inline_comments(diff: &SemanticDiff, impact: &ImpactReport) -> Vec<InlineComment> {
    let mut comments = Vec::new();

    for change in &diff.entity_changes {
        match &change.kind {
            EntityChangeKind::Added(entity) => {
                collect_added_comments(entity, impact, &mut comments);
            }
            EntityChangeKind::Modified { old, new } => {
                collect_modified_comments(old, new, impact, &mut comments);
            }
            EntityChangeKind::Removed(_) => {
                // Removed entities have no span data — nothing to anchor.
            }
        }
    }

    // Sort by file, then by start_line for stable output.
    comments.sort_by(|a, b| a.file.cmp(&b.file).then(a.start_line.cmp(&b.start_line)));

    comments
}

/// Graph-known tests covering one changed entity.
fn covering_tests(impact: &ImpactReport, entity_id: &EntityId) -> usize {
    impact
        .entity_impact(entity_id)
        .map_or(0, |entry| entry.covering_tests)
}

fn collect_added_comments(
    entity: &Entity,
    impact: &ImpactReport,
    comments: &mut Vec<InlineComment>,
) {
    let span = match &entity.span {
        Some(s) => s,
        None => return,
    };

    comments.push(InlineComment {
        file: span.file.to_string(),
        start_line: span.start_line,
        end_line: span.end_line,
        kind: InlineCommentKind::Added,
        message: format!(
            "New {:?} `{}` — {}",
            entity.kind, entity.name, entity.signature,
        ),
    });

    // Public entity without test coverage. Keyed on THIS entity's covering
    // tests, not the diff-global test bucket, and suppressed when the diff
    // has no impact signal at all — an empty channel cannot distinguish
    // "uncovered" from "relations never ingested", and the report already
    // carries that deficit as an `impact_signal_absent` evidence gap.
    if entity.visibility == Visibility::Public
        && entity.role != EntityRole::Test
        && !impact.is_empty()
        && covering_tests(impact, &entity.id) == 0
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::CoverageGap,
            message: format!("New public entity `{}` has no test coverage", entity.name,),
        });
    }

    // Unreviewed agent change
    if impact.unreviewed_agent_changes.contains(&entity.id) {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::AgentUnreviewed,
            message: format!(
                "Entity `{}` was added by an agent and has not been reviewed",
                entity.name,
            ),
        });
    }
}

/// The zero-hash sentinel on `SemanticFingerprint.equivalence_hash`, meaning the
/// behavior-equivalence class was not computed for that entity (unsupported
/// language, or an entity the ingest could not classify).
fn equivalence_not_computed(hash: Hash256) -> bool {
    hash == Hash256::from_bytes([0; 32])
}

/// Whether the body change from `old` to `new` is provably behavior-preserving
/// under the graph-owned `equivalence_hash` attached at ingest. True only when
/// both revisions carry a COMPUTED class and the two are equal; the zero-hash
/// sentinel on either side means "unknown" and never proves equivalence — the
/// conservative default that keeps every genuine behavior change, and every
/// entity the ingest could not classify, in the attention channel.
fn body_change_is_behavior_equivalent(old: &Entity, new: &Entity) -> bool {
    let old_class = old.fingerprint.equivalence_hash;
    !equivalence_not_computed(old_class) && old_class == new.fingerprint.equivalence_hash
}

fn collect_modified_comments(
    old: &Entity,
    new: &Entity,
    impact: &ImpactReport,
    comments: &mut Vec<InlineComment>,
) {
    // Anchor to the new entity's span (where the change landed).
    let span = match &new.span {
        Some(s) => s,
        None => return,
    };

    // All gate-relevant rules key on THIS entity's inbound edges. Another
    // entity's consumers are that entity's risk, not this one's.
    let per_entity = impact.entity_impact(&new.id);
    let consumer_count = per_entity.map_or(0, |e| e.consumer_count);
    let strong_consumer_count = per_entity.map_or(0, |e| e.strong_consumer_count);
    let contract_consumer_count = per_entity.map_or(0, |e| e.contract_consumer_count);
    let consumer_file_count = per_entity.map_or(0, |e| e.consumer_files.len());
    let entity_covering_tests = per_entity.map_or(0, |e| e.covering_tests);
    // Consumers that were themselves modified in the reviewed range. When a
    // surface change has NO external consumer left but did have consumers that
    // all moved with it, the break is a coherent in-diff migration: visible
    // evidence, not a blocking break.
    let consumers_migrated = per_entity.map_or(0, |e| e.consumers_migrated_in_diff);
    let fanout_gate_consumer_count = if entity_covering_tests > 0 {
        strong_consumer_count
    } else {
        consumer_count
    };

    // Signature change. A difference that only ADDS strengthening qualifiers
    // (constexpr/inline/[[nodiscard]]) cannot invalidate existing callers and
    // is not a contract-surface change; anything else — including removing
    // such qualifiers — remains one.
    if !is_non_contract_surface_role(new.role)
        && old.signature != new.signature
        && !signature_runtime_neutral(&old.signature, &new.signature)
    {
        // An arity-preserving parameter rename cannot break a caller that
        // passes the renamed parameter positionally. When the graph-known call
        // sites prove every external consumer is a shaped positional call — no
        // keyword use of a renamed name, no `**kwargs`, no unshaped consumer —
        // the rename is runtime-neutral for those consumers: the signature
        // change is still recorded as evidence, but it is not a blocking break.
        let rename_is_neutral = consumer_count > 0
            && match arity_preserving_rename(&old.signature, &new.signature) {
                Some(renamed) => {
                    let summary = per_entity
                        .map(|e| e.call_shapes.clone())
                        .unwrap_or_default();
                    rename_is_runtime_neutral_for_consumers(&renamed, &summary)
                }
                None => false,
            };

        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::SignatureChange,
            message: if rename_is_neutral {
                format!(
                    "Signature changed: `{}` → `{}` (parameter rename; all {} graph-known call site(s) pass positionally — no runtime break)",
                    old.signature, new.signature, consumer_count,
                )
            } else {
                format!("Signature changed: `{}` → `{}`", old.signature, new.signature)
            },
        });

        // Breaking only when THIS entity has EXTERNAL non-test consumers to
        // break. A rename proven runtime-neutral by its call sites strands none
        // of them, so it emits no blocking finding. Test-only consumers are
        // covering evidence, not a broken contract. Consumers that were
        // themselves modified in this diff are excluded from `consumer_count`;
        // when they are the ONLY consumers the change is a coherent in-diff
        // migration — reported as visible evidence but not a blocking break.
        if rename_is_neutral {
            // Proven safe by call-site shapes; the signature evidence above stands.
        } else if consumer_count > 0 {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::Breaking,
                message: format!(
                    "Breaking change: signature modification affects {} downstream entity(ies)",
                    consumer_count,
                ),
            });
        } else if consumers_migrated > 0 {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::BreakingMigrated,
                message: format!(
                    "Signature changed; all {} graph-known consumer(s) were co-updated in this diff (migration verified in-range)",
                    consumers_migrated,
                ),
            });
        }
    }

    // Visibility reduction
    if !is_non_contract_surface_role(new.role)
        && old.visibility == Visibility::Public
        && new.visibility != Visibility::Public
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::VisibilityChange,
            message: format!(
                "Visibility reduced: {:?} → {:?} on `{}`",
                old.visibility, new.visibility, new.name,
            ),
        });

        if consumer_count > 0 {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::Breaking,
                message: format!(
                    "Breaking change: visibility reduced with {} consumer(s)",
                    consumer_count,
                ),
            });
        } else if consumers_migrated > 0 {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::BreakingMigrated,
                message: format!(
                    "Visibility reduced; all {} graph-known consumer(s) were co-updated in this diff (migration verified in-range)",
                    consumers_migrated,
                ),
            });
        }
    }

    // Renamed
    if old.name != new.name {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::Renamed,
            message: format!("Renamed: `{}` → `{}`", old.name, new.name),
        });
    }

    // Contract entity whose own consumers are exposed to this modification.
    if matches!(
        new.kind,
        EntityKind::ApiEndpoint | EntityKind::EventContract | EntityKind::Schema
    ) && contract_consumer_count > 0
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::ContractViolation,
            message: format!(
                "Contract {:?} `{}` modified with {} consumer(s)",
                new.kind, new.name, contract_consumer_count,
            ),
        });
    }

    // Fire only when BOTH sides carry a contract: persist paths differ in
    // whether they attach the key, so one-sided presence is path-coverage
    // skew, not a behavior change.
    if let (Some(old_contract), Some(new_contract)) = (
        old.metadata.extra.get(COMMAND_EFFECT_CONTRACT_KEY),
        new.metadata.extra.get(COMMAND_EFFECT_CONTRACT_KEY),
    ) {
        if old_contract != new_contract {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::CommandEffectContract,
                message: format!(
                    "Command-effect contract for `{}` changed; external command behavior needs review",
                    new.name,
                ),
            });
        }
    }

    // Body-only modification with wide consumer fanout. The contract surface
    // is unchanged, so the breaking channels stay silent, but a public behavior
    // change reaching many distinct non-test consumer entities deserves
    // attention. Graph-known covering tests can absorb weak/ambiguous fanout,
    // so covered body-only changes gate on strong consumers only. Uncovered
    // public body-only changes gate on all graph-native consumer entities:
    // weak fanout plus no tests is still a review risk. Private helper body
    // changes remain visible through coverage/evidence findings, but they do
    // not feed the gate without a signature or visibility surface change.
    let body_only_fanout_has_enough_shape = new.visibility == Visibility::Public
        && fanout_gate_consumer_count >= CONSUMER_FANOUT_THRESHOLD;
    if old.signature == new.signature
        && old.visibility == new.visibility
        && body_only_fanout_has_enough_shape
    {
        // A body change that is provably behavior-preserving (docstring /
        // comment / formatting, per the graph-owned equivalence class) carries
        // no downstream behavior risk, so its wide fanout is informational
        // evidence rather than an attention signal. The downgrade fires only
        // when THIS entity's own new body is proven equivalent to its old body;
        // any entity whose change is not proven equivalent keeps the attention
        // ConsumerFanout, so a diff with even one real behavior change still
        // gates.
        let (kind, message) = if body_change_is_behavior_equivalent(old, new) {
            (
                InlineCommentKind::ConsumerFanoutEquivalent,
                format!(
                    "Behavior-preserving change to `{}` reaches {} distinct non-test consumer(s) across {} file(s); \
                     the new body is provably equivalent to the old (docstring/comment/formatting), so this is informational",
                    new.name, fanout_gate_consumer_count, consumer_file_count,
                ),
            )
        } else {
            (
                InlineCommentKind::ConsumerFanout,
                format!(
                    "Behavior of `{}` changed with {} distinct non-test consumer(s) across {} file(s)",
                    new.name, fanout_gate_consumer_count, consumer_file_count,
                ),
            )
        };
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind,
            message,
        });
    }

    // No test coverage. Keyed on THIS entity's covering tests and suppressed
    // when the diff-wide impact signal is absent — that deficit is already
    // reported as an `impact_signal_absent` evidence gap.
    if new.role != EntityRole::Test && !impact.is_empty() && entity_covering_tests == 0 {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::CoverageGap,
            message: format!("Modified entity `{}` has no test coverage", new.name,),
        });
    }

    // Unreviewed agent change
    if impact.unreviewed_agent_changes.contains(&new.id) {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::AgentUnreviewed,
            message: format!(
                "Entity `{}` was modified by an agent and has not been reviewed",
                new.name,
            ),
        });
    }
}

/// Group inline comments by file path, with comments sorted by line within
/// each file. Returns entries in file-path-sorted order.
pub fn group_by_file(comments: &[InlineComment]) -> BTreeMap<&str, Vec<&InlineComment>> {
    let mut grouped: BTreeMap<&str, Vec<&InlineComment>> = BTreeMap::new();
    for comment in comments {
        grouped.entry(&comment.file).or_default().push(comment);
    }
    // Each group is already sorted because collect_inline_comments sorts globally.
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
    use crate::impact::{EntityImpact, ImpactReport};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        SourceSpan, Visibility,
    };
    use kin_model::ids::*;

    fn test_entity_with_span(name: &str, file: &str, start_line: u32, end_line: u32) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 100,
                start_line,
                start_col: 0,
                end_line,
                end_col: 0,
            }),
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_entity_no_span(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn added_entity_with_span_produces_comment() {
        let entity = test_entity_with_span("handle_request", "src/api.rs", 10, 25);
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(!comments.is_empty());
        assert_eq!(comments[0].file, "src/api.rs");
        assert_eq!(comments[0].start_line, 10);
        assert_eq!(comments[0].end_line, 25);
        assert_eq!(comments[0].kind, InlineCommentKind::Added);
    }

    #[test]
    fn entity_without_span_produces_no_comment() {
        let entity = test_entity_no_span("orphan");
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments.is_empty());
    }

    #[test]
    fn modified_entity_signature_change_produces_comments() {
        let old = test_entity_with_span("process", "src/core.rs", 5, 20);
        let mut new = old.clone();
        new.signature = "fn process(x: i32)".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::SignatureChange));
    }

    #[test]
    fn breaking_change_when_callers_exist() {
        let old = test_entity_with_span("api_handler", "src/api.rs", 1, 10);
        let mut new = old.clone();
        new.signature = "fn api_handler(req: Request, extra: bool)".to_string();

        let caller = test_entity_with_span("caller_fn", "src/client.rs", 1, 5);

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![caller],
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 1,
                strong_consumer_count: 1,
                contract_consumer_count: 0,
                consumer_files: vec!["src/client.rs".to_string()],
                covering_tests: 0,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::Breaking));
    }

    #[test]
    fn breaking_requires_this_entitys_consumers_not_the_diffs() {
        // Entity A changes signature but nothing consumes A; the diff-global
        // caller belongs to entity B. A must NOT be reported as breaking.
        let old_a = test_entity_with_span("isolated_fn", "src/a.rs", 1, 10);
        let mut new_a = old_a.clone();
        new_a.signature = "fn isolated_fn(x: i32)".to_string();
        let b = test_entity_with_span("popular_fn", "src/b.rs", 1, 10);
        let caller_of_b = test_entity_with_span("caller_fn", "src/client.rs", 1, 5);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: new_a.id,
                    kind: EntityChangeKind::Modified {
                        old: old_a.clone(),
                        new: new_a.clone(),
                    },
                },
                EntityChange {
                    entity_id: b.id,
                    kind: EntityChangeKind::Modified {
                        old: b.clone(),
                        new: b.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![caller_of_b],
            changed_ids: vec![new_a.id, b.id],
            entity_impacts: vec![
                EntityImpact {
                    entity_id: new_a.id,
                    consumer_count: 0,
                    strong_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![],
                    covering_tests: 0,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
                },
                EntityImpact {
                    entity_id: b.id,
                    consumer_count: 1,
                    strong_consumer_count: 1,
                    contract_consumer_count: 0,
                    consumer_files: vec!["src/client.rs".to_string()],
                    covering_tests: 0,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
                },
            ],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::Breaking),
            "another entity's consumers must not make this signature change breaking"
        );
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::SignatureChange));
    }

    #[test]
    fn breaking_suppressed_when_only_tests_consume() {
        // Signature change whose only inbound edges are tests: the tests are
        // the covering evidence, not a broken contract. Not breaking.
        let old = test_entity_with_span("tested_fn", "src/core.rs", 1, 10);
        let mut new = old.clone();
        new.signature = "fn tested_fn(flag: bool)".to_string();
        let test_entity = test_entity_with_span("test_tested_fn", "tests/core.rs", 1, 5);

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_tests: vec![test_entity],
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 0,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec![],
                covering_tests: 1,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::Breaking),
            "test-only consumers must not produce a breaking finding"
        );
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::CoverageGap),
            "a tested entity has no coverage gap"
        );
    }

    #[test]
    fn all_consumers_migrated_downgrades_breaking_to_visible_evidence() {
        // Signature changed, no external consumer left, but two consumers were
        // co-updated in the same diff: a coherent migration. The blocking
        // Breaking finding is replaced by a non-blocking BreakingMigrated one,
        // and the signature change itself is still surfaced.
        let old = test_entity_with_span("api_handler", "src/api.rs", 1, 10);
        let mut new = old.clone();
        new.signature = "fn api_handler(req: Request, extra: bool)".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 0,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec![],
                covering_tests: 0,
                consumers_migrated_in_diff: 2,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::Breaking),
            "a fully co-updated migration is not a blocking break"
        );
        let migrated: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::BreakingMigrated)
            .collect();
        assert_eq!(migrated.len(), 1);
        assert!(migrated[0].message.contains("2 graph-known consumer"));
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::SignatureChange));
    }

    #[test]
    fn partial_migration_still_breaks_and_emits_no_migrated_finding() {
        // One external consumer remains alongside migrated ones: still a real,
        // blocking break — not a coherent migration.
        let old = test_entity_with_span("api_handler", "src/api.rs", 1, 10);
        let mut new = old.clone();
        new.signature = "fn api_handler(req: Request, extra: bool)".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 1,
                strong_consumer_count: 1,
                contract_consumer_count: 0,
                consumer_files: vec!["src/client.rs".to_string()],
                covering_tests: 0,
                consumers_migrated_in_diff: 2,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::Breaking),
            "a stranded external consumer still blocks"
        );
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::BreakingMigrated),
            "partial migration is a real break, not migrated evidence"
        );
    }

    #[test]
    fn coverage_gap_keys_on_the_entity_not_the_diff() {
        // Covered entity + uncovered entity in one diff: exactly the
        // uncovered one carries the gap. Under the old diff-global rule the
        // covered entity's test silenced both.
        let covered = test_entity_with_span("covered_fn", "src/covered.rs", 1, 10);
        let uncovered = test_entity_with_span("uncovered_fn", "src/uncovered.rs", 1, 10);
        let test_entity = test_entity_with_span("test_covered_fn", "tests/covered.rs", 1, 5);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: covered.id,
                    kind: EntityChangeKind::Modified {
                        old: covered.clone(),
                        new: covered.clone(),
                    },
                },
                EntityChange {
                    entity_id: uncovered.id,
                    kind: EntityChangeKind::Modified {
                        old: uncovered.clone(),
                        new: uncovered.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_tests: vec![test_entity],
            changed_ids: vec![covered.id, uncovered.id],
            entity_impacts: vec![
                EntityImpact {
                    entity_id: covered.id,
                    consumer_count: 0,
                    strong_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![],
                    covering_tests: 1,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
                },
                EntityImpact {
                    entity_id: uncovered.id,
                    consumer_count: 0,
                    strong_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![],
                    covering_tests: 0,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
                },
            ],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        let gaps: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::CoverageGap)
            .collect();
        assert_eq!(gaps.len(), 1, "exactly the uncovered entity carries a gap");
        assert_eq!(gaps[0].file, "src/uncovered.rs");
    }

    #[test]
    fn coverage_gap_suppressed_when_impact_signal_absent() {
        // The graph connects nothing to this diff: an empty channel cannot
        // prove a coverage gap, and the shadow report already carries the
        // deficit as an impact_signal_absent evidence gap.
        let old = test_entity_with_span("quiet_fn", "src/quiet.rs", 1, 10);
        let new = old.clone();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::CoverageGap),
            "no coverage gap may be claimed from an absent impact signal"
        );
    }

    #[test]
    fn command_contract_delta_emits_inline_finding() {
        let mut old = test_entity_with_span("prCheckout", "command/pr_checkout.go", 14, 102);
        old.metadata.extra.insert(
            COMMAND_EFFECT_CONTRACT_KEY.into(),
            serde_json::json!({
                "schema_version": 1,
                "effects": [{
                    "kind": "queued_git_argv",
                    "expr": "append(cmdQueue, []string{\"git\", \"checkout\", newBranchName})",
                    "bindings": { "newBranchName": "pr.HeadRefName" }
                }]
            }),
        );
        let mut new = old.clone();
        new.metadata.extra.insert(
            COMMAND_EFFECT_CONTRACT_KEY.into(),
            serde_json::json!({
                "schema_version": 1,
                "effects": [{
                    "kind": "queued_git_argv",
                    "expr": "append(cmdQueue, []string{\"git\", \"checkout\", newBranchName})",
                    "bindings": { "newBranchName": "fmt.Sprintf(\"pr/%d/%s\", pr.Number, pr.HeadRefName)" }
                }]
            }),
        );

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 0,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec![],
                covering_tests: 1,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            comments
                .iter()
                .any(|comment| comment.kind == InlineCommentKind::CommandEffectContract),
            "command contract metadata delta should emit an attention finding: {comments:?}"
        );
    }

    #[test]
    fn consumer_fanout_fires_on_body_change_at_threshold() {
        // Body-only modification (signature and visibility unchanged) reaching
        // two distinct non-test consumer entities -> attention comment.
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let new = old.clone();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let consumer_a = test_entity_with_span("use_a", "src/a.rs", 1, 5);
        let consumer_b = test_entity_with_span("use_b", "src/b.rs", 1, 5);
        let impact = ImpactReport {
            affected_callers: vec![consumer_a, consumer_b],
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 2,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 1,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        let fanout: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(fanout.len(), 1);
        assert!(fanout[0].message.contains("2 distinct non-test consumer"));
    }

    /// Stamp a computed behavior-equivalence class on an entity, as ingest does.
    /// `seed` must be non-zero — the zero hash is the "not computed" sentinel.
    fn with_equivalence_class(mut e: Entity, seed: u8) -> Entity {
        e.fingerprint.equivalence_hash = Hash256::from_bytes([seed; 32]);
        e
    }

    /// A body-only wide-fanout change whose old and new bodies carry the SAME
    /// equivalence class downgrades from the attention `ConsumerFanout` to the
    /// informational `ConsumerFanoutEquivalent`, with the fanout evidence
    /// preserved in the message.
    #[test]
    fn consumer_fanout_downgrades_when_body_is_equivalent() {
        let base = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let old = with_equivalence_class(base.clone(), 1);
        let new = with_equivalence_class(base.clone(), 1);
        let diff = fanout_diff(&old, &new);
        let impact = fanout_impact(new.id);

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::ConsumerFanout),
            "an equivalent body change must not raise the attention fanout: {comments:?}"
        );
        let downgraded: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanoutEquivalent)
            .collect();
        assert_eq!(
            downgraded.len(),
            1,
            "equivalent fanout must be reported once"
        );
        assert!(
            downgraded[0]
                .message
                .contains("2 distinct non-test consumer"),
            "the fanout evidence must be preserved in the downgraded finding"
        );
    }

    /// When the equivalence classes DIFFER (a real behavior change), the
    /// attention `ConsumerFanout` still fires — the protected-true-positive path.
    #[test]
    fn consumer_fanout_stays_attention_when_classes_differ() {
        let base = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let old = with_equivalence_class(base.clone(), 1);
        let new = with_equivalence_class(base.clone(), 2);
        let diff = fanout_diff(&old, &new);
        let impact = fanout_impact(new.id);

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::ConsumerFanout),
            "a real behavior change must keep the attention fanout"
        );
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::ConsumerFanoutEquivalent),
            "a differing equivalence class must never downgrade"
        );
    }

    /// With no equivalence class attached (unknown), the change is conservatively
    /// treated as attention — absence never proves equivalence.
    #[test]
    fn consumer_fanout_stays_attention_when_class_absent() {
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let new = old.clone();
        let diff = fanout_diff(&old, &new);
        let impact = fanout_impact(new.id);

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::ConsumerFanout),
            "an unclassified change must stay in the attention channel"
        );
    }

    /// A diff with two wide-fanout entities — one behavior-equivalent, one a real
    /// change — downgrades ONLY the equivalent one and keeps attention on the
    /// other. A diff with even one real behavior change still gates.
    #[test]
    fn mixed_diff_keeps_attention_for_the_non_equivalent_entity() {
        let a_base = test_entity_with_span("equiv_fn", "src/a.rs", 1, 20);
        let a_old = with_equivalence_class(a_base.clone(), 1);
        let a_new = with_equivalence_class(a_base.clone(), 1);
        let b_base = test_entity_with_span("changed_fn", "src/b.rs", 1, 20);
        let b_old = with_equivalence_class(b_base.clone(), 2);
        let b_new = with_equivalence_class(b_base.clone(), 3);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: a_new.id,
                    kind: EntityChangeKind::Modified {
                        old: a_old.clone(),
                        new: a_new.clone(),
                    },
                },
                EntityChange {
                    entity_id: b_new.id,
                    kind: EntityChangeKind::Modified {
                        old: b_old.clone(),
                        new: b_new.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![a_new.id, b_new.id],
            entity_impacts: vec![
                EntityImpact {
                    entity_id: a_new.id,
                    consumer_count: 2,
                    strong_consumer_count: 2,
                    contract_consumer_count: 0,
                    consumer_files: vec!["src/x.rs".to_string(), "src/y.rs".to_string()],
                    covering_tests: 1,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
                },
                EntityImpact {
                    entity_id: b_new.id,
                    consumer_count: 2,
                    strong_consumer_count: 2,
                    contract_consumer_count: 0,
                    consumer_files: vec!["src/x.rs".to_string(), "src/y.rs".to_string()],
                    covering_tests: 1,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
                },
            ],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        let attention: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(
            attention.len(),
            1,
            "exactly the non-equivalent entity keeps attention"
        );
        assert!(
            attention[0].message.contains("changed_fn"),
            "attention must be on the real behavior change, got: {:?}",
            attention[0].message
        );
        assert!(
            comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::ConsumerFanoutEquivalent
                    && c.message.contains("equiv_fn")),
            "the equivalent entity is downgraded to informational"
        );
    }

    /// The downgrade is deterministic across repeated collection.
    #[test]
    fn consumer_fanout_downgrade_is_deterministic() {
        let base = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let old = with_equivalence_class(base.clone(), 1);
        let new = with_equivalence_class(base.clone(), 1);
        let diff = fanout_diff(&old, &new);
        let impact = fanout_impact(new.id);
        let first = collect_inline_comments(&diff, &impact);
        let second = collect_inline_comments(&diff, &impact);
        let kinds = |cs: &[InlineComment]| cs.iter().map(|c| c.kind).collect::<Vec<_>>();
        assert_eq!(kinds(&first), kinds(&second));
    }

    /// Build a body-only modified-entity diff for `old` -> `new`.
    fn fanout_diff(old: &Entity, new: &Entity) -> SemanticDiff {
        SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        }
    }

    /// Build an impact report giving `id` two strong non-test consumers.
    fn fanout_impact(id: EntityId) -> ImpactReport {
        ImpactReport {
            changed_ids: vec![id],
            entity_impacts: vec![EntityImpact {
                entity_id: id,
                consumer_count: 2,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 1,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn consumer_fanout_uses_weak_consumers_only_when_uncovered() {
        // Ambiguous-dispatch fan-out links every possible implementor at low
        // confidence. Covered body-only changes need strong consumers to gate;
        // uncovered body-only changes still gate on weak fanout, because the
        // graph has no test evidence to absorb that possible blast radius.
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let new = old.clone();
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let covered_weak_only = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 4,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 1,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &covered_weak_only);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::ConsumerFanout),
            "covered weak-only consumers must not fire the fanout gate"
        );

        let uncovered_weak_only = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 4,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 0,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &uncovered_weak_only);
        let fanout: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(
            fanout.len(),
            1,
            "uncovered weak fanout must still fire the review gate"
        );
        assert!(
            fanout[0].message.contains("4 distinct non-test consumer"),
            "uncovered fanout reports the full graph-native consumer count"
        );

        let mixed = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 4,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 1,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &mixed);
        let fanout: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(fanout.len(), 1, "strong consumers at threshold must fire");
        assert!(fanout[0].message.contains("2 distinct non-test consumer"));
    }

    #[test]
    fn strengthened_only_signature_is_not_a_signature_change() {
        assert!(signature_strengthened_only(
            "TestRunInfo(StringRef _name)",
            "constexpr TestRunInfo(StringRef _name)"
        ));
        assert!(!signature_strengthened_only(
            "constexpr TestRunInfo(StringRef _name)",
            "TestRunInfo(StringRef _name)"
        ));
        assert!(!signature_strengthened_only(
            "TestRunInfo(StringRef _name)",
            "TestRunInfo(StringRef _name, int mode)"
        ));
        assert!(!signature_strengthened_only(
            "inline int f()",
            "constexpr int f()"
        ));
        assert!(!signature_strengthened_only("int f()", "int f()"));
    }

    #[test]
    fn python_annotation_only_signature_is_runtime_neutral() {
        assert!(signature_runtime_neutral(
            "def __init__(self, reprlocation_lines): # List of(reprlocation, lines) tuples",
            "def __init__(self, reprlocation_lines: Sequence[Tuple[ReprFileLocation, Sequence[str]]])"
        ));
        assert!(signature_runtime_neutral(
            "def toterminal(self, tw)",
            "def toterminal(self, tw) -> None"
        ));
        assert!(signature_runtime_neutral(
            "def make(self, value = (1, 2), *, flag: bool = True)",
            "def make(self, value=(1,2), *, flag=True) -> object"
        ));
        assert!(!signature_runtime_neutral(
            "def _makefile(self, ext, args, kwargs, encoding=\"utf-8\")",
            "def _makefile(self, ext, lines, files, encoding=\"utf-8\")"
        ));
        assert!(!signature_runtime_neutral(
            "class Item(Node, Request)",
            "class Item(Node)"
        ));
    }

    #[test]
    fn arity_preserving_rename_detects_normal_param_renames() {
        // The _makefile defect shape: two arity-preserving positional renames,
        // annotations/defaults on other positions unchanged.
        assert_eq!(
            arity_preserving_rename(
                "def _makefile(self, ext, args, kwargs, encoding=\"utf-8\")",
                "def _makefile(self, ext, lines, files, encoding=\"utf-8\")"
            ),
            Some(vec!["args".to_string(), "kwargs".to_string()])
        );
        // Single rename with a leading `self`.
        assert_eq!(
            arity_preserving_rename("def f(self, config)", "def f(self, options)"),
            Some(vec!["config".to_string()])
        );
        // Rename survives an annotation/default reformat on the same position.
        assert_eq!(
            arity_preserving_rename("def f(a: int = 1)", "def f(b: int = 1)"),
            Some(vec!["a".to_string()])
        );
    }

    #[test]
    fn arity_preserving_rename_rejects_reorders() {
        // Swapping two names is not a safe rename: positional callers shift.
        assert_eq!(arity_preserving_rename("def f(a, b)", "def f(b, a)"), None);
        // A new name that reuses an existing parameter name (a shift) is rejected.
        assert_eq!(arity_preserving_rename("def f(a, b)", "def f(b, c)"), None);
        // Renaming both positions to fresh names is a clean rename, not a reorder.
        assert_eq!(
            arity_preserving_rename("def f(a, b)", "def f(x, y)"),
            Some(vec!["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn arity_preserving_rename_rejects_non_renames() {
        // Retype-only and default-only edits keep the identifier.
        assert_eq!(
            arity_preserving_rename("def f(a: int)", "def f(a: str)"),
            None
        );
        assert_eq!(arity_preserving_rename("def f(a=1)", "def f(a=2)"), None);
        // Arity changes are not renames.
        assert_eq!(arity_preserving_rename("def f(a)", "def f(a, b)"), None);
        assert_eq!(arity_preserving_rename("def f(a, b)", "def f(a)"), None);
        // Appended optional parameter.
        assert_eq!(arity_preserving_rename("def f(a)", "def f(a, b=1)"), None);
        // Different callable, identical text, and non-`def` text.
        assert_eq!(arity_preserving_rename("def f(a)", "def g(b)"), None);
        assert_eq!(arity_preserving_rename("def f(a)", "def f(a)"), None);
        assert_eq!(arity_preserving_rename("class A(B)", "class A(C)"), None);
    }

    #[test]
    fn arity_preserving_rename_ignores_collectors_and_role_changes() {
        // Renaming `*args`/`**kwargs` collectors strands no caller.
        assert_eq!(
            arity_preserving_rename("def f(a, *args, **kwargs)", "def f(a, *rest, **opts)"),
            None
        );
        // A normal rename alongside a collector rename reports only the normal one.
        assert_eq!(
            arity_preserving_rename("def f(a, *args)", "def f(b, *rest)"),
            Some(vec!["a".to_string()])
        );
        // Reclassifying a position (normal → `*args`) is structural, not a rename.
        assert_eq!(arity_preserving_rename("def f(a, b)", "def f(a, *b)"), None);
    }

    #[test]
    fn rename_neutral_only_when_every_caller_is_positional_and_shaped() {
        let renamed = vec!["args".to_string(), "kwargs".to_string()];

        // (a) every caller positional, every consumer a shaped call → neutral.
        let all_positional = ConsumerCallShapeSummary {
            all_consumers_shaped_calls: true,
            ..Default::default()
        };
        assert!(rename_is_runtime_neutral_for_consumers(
            &renamed,
            &all_positional
        ));

        // (b) a caller passes a renamed parameter by keyword → breaking.
        let mut keyword_caller = all_positional.clone();
        keyword_caller
            .caller_keyword_names
            .insert("args".to_string());
        assert!(!rename_is_runtime_neutral_for_consumers(
            &renamed,
            &keyword_caller
        ));

        // (c) a keyword unrelated to the rename is fine; a renamed one is not.
        let mut mixed = ConsumerCallShapeSummary {
            all_consumers_shaped_calls: true,
            ..Default::default()
        };
        mixed.caller_keyword_names.insert("encoding".to_string());
        assert!(rename_is_runtime_neutral_for_consumers(&renamed, &mixed));
        mixed.caller_keyword_names.insert("kwargs".to_string());
        assert!(!rename_is_runtime_neutral_for_consumers(&renamed, &mixed));

        // (d) a `**kwargs` caller has an unknown keyword set → breaking.
        let var_keyword = ConsumerCallShapeSummary {
            all_consumers_shaped_calls: true,
            any_var_keyword_caller: true,
            ..Default::default()
        };
        assert!(!rename_is_runtime_neutral_for_consumers(
            &renamed,
            &var_keyword
        ));

        // (f) any consumer without captured shape evidence → breaking.
        let missing_shape = ConsumerCallShapeSummary {
            all_consumers_shaped_calls: false,
            ..Default::default()
        };
        assert!(!rename_is_runtime_neutral_for_consumers(
            &renamed,
            &missing_shape
        ));

        // A rename with no consumers at all is vacuously neutral: an empty
        // real-consumer set is already handled upstream as no downstream risk.
        let no_consumers = ConsumerCallShapeSummary {
            all_consumers_shaped_calls: true,
            ..Default::default()
        };
        assert!(rename_is_runtime_neutral_for_consumers(&[], &no_consumers));
    }

    #[test]
    fn python_appended_defaulted_params_are_runtime_neutral() {
        // Trailing parameter with a default: existing calls stay valid.
        assert!(signature_runtime_neutral(
            "def render(self, node)",
            "def render(self, node, inline=False)"
        ));
        // Trailing *args / **kwargs markers add no required argument.
        assert!(signature_runtime_neutral(
            "def emit(self, event)",
            "def emit(self, event, *args, **kwargs)"
        ));
        // Keyword-only defaulted tail is neutral.
        assert!(signature_runtime_neutral(
            "def build(self, app)",
            "def build(self, app, *, force=False)"
        ));
    }

    #[test]
    fn python_appended_required_param_is_not_neutral() {
        // A new trailing parameter WITHOUT a default breaks existing calls.
        assert!(!signature_runtime_neutral(
            "def render(self, node)",
            "def render(self, node, inline)"
        ));
        // A required keyword-only parameter still breaks callers that omit it.
        assert!(!signature_runtime_neutral(
            "def build(self, app)",
            "def build(self, app, *, force)"
        ));
        // Removing a parameter is never neutral.
        assert!(!signature_runtime_neutral(
            "def render(self, node, inline=False)",
            "def render(self, node)"
        ));
        // Reordering a defaulted param ahead of a positional is not a prefix.
        assert!(!signature_runtime_neutral(
            "def f(self, a, b)",
            "def f(self, b, a, c=1)"
        ));
    }

    #[test]
    fn go_struct_added_field_is_runtime_neutral() {
        // The real a742e9f8df row: ListOptions gains a `Config` field mid-list.
        // Existing named-field consumers are unaffected.
        assert!(signature_runtime_neutral(
            "ListOptions struct { HttpClient func()(*http.Client, error) IO *iostreams.IOStreams BaseRepo func()(ghrepo.Interface, error) Organization string }",
            "ListOptions struct { HttpClient func()(*http.Client, error) IO *iostreams.IOStreams Config func()(config.Config, error) BaseRepo func()(ghrepo.Interface, error) Organization string }"
        ));
        // Appended field at the end is also additive.
        assert!(signature_runtime_neutral(
            "Opts struct { A int B string }",
            "Opts struct { A int B string C bool }"
        ));
    }

    #[test]
    fn go_struct_non_additive_changes_are_not_neutral() {
        // Field removal.
        assert!(!signature_runtime_neutral(
            "Opts struct { A int B string C bool }",
            "Opts struct { A int B string }"
        ));
        // Field rename.
        assert!(!signature_runtime_neutral(
            "Opts struct { A int Name string }",
            "Opts struct { A int Label string }"
        ));
        // Field retype.
        assert!(!signature_runtime_neutral(
            "Opts struct { A int B string }",
            "Opts struct { A int64 B string }"
        ));
        // Field reorder (no additions).
        assert!(!signature_runtime_neutral(
            "Opts struct { A int B string }",
            "Opts struct { B string A int }"
        ));
        // Type header rename is not a neutral field addition.
        assert!(!signature_runtime_neutral(
            "Opts struct { A int }",
            "Config struct { A int B string }"
        ));
    }

    #[test]
    fn rust_struct_is_not_treated_as_go_additive() {
        // Rust's `struct Name { … }` puts a name between keyword and brace, so
        // the Go-additive rule must not fire — a Rust field addition can still
        // break exhaustive constructors and is not silently neutralized here.
        assert!(!signature_runtime_neutral(
            "struct Opts { a: i32 }",
            "struct Opts { a: i32, b: bool }"
        ));
    }

    #[test]
    fn strengthened_only_change_emits_no_signature_or_breaking_comment() {
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let mut new = old.clone();
        new.signature = format!("constexpr {}", old.signature);
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 3,
                strong_consumer_count: 3,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string()],
                covering_tests: 0,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments.iter().any(|c| matches!(
                c.kind,
                InlineCommentKind::SignatureChange | InlineCommentKind::Breaking
            )),
            "qualifier strengthening must not read as signature change or breaking"
        );
    }

    #[test]
    fn python_annotation_only_change_emits_no_signature_or_breaking_comment() {
        let mut old = test_entity_with_span(
            "ReprFailDoctest.toterminal",
            "src/_pytest/doctest.py",
            122,
            126,
        );
        old.signature = "def toterminal(self, tw)".to_string();
        let mut new = old.clone();
        new.signature = "def toterminal(self, tw) -> None".to_string();
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 5,
                strong_consumer_count: 5,
                contract_consumer_count: 0,
                consumer_files: vec![
                    "src/_pytest/doctest.py".to_string(),
                    "testing/test_doctest.py".to_string(),
                ],
                covering_tests: 0,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments.iter().any(|c| matches!(
                c.kind,
                InlineCommentKind::SignatureChange | InlineCommentKind::Breaking
            )),
            "annotation-only Python changes must not read as runtime contract changes: {comments:?}"
        );
    }

    #[test]
    fn command_contract_absent_on_one_side_is_no_signal() {
        let old = test_entity_with_span("runner", "cmd/run.go", 1, 20);
        let mut new = old.clone();
        new.metadata.extra.insert(
            COMMAND_EFFECT_CONTRACT_KEY.to_string(),
            serde_json::json!({"schema_version": 1, "effects": []}),
        );
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &ImpactReport::default());
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::CommandEffectContract),
            "key present on only one side is persist-path coverage skew, not a change"
        );
    }

    #[test]
    fn consumer_fanout_decides_on_entity_count_not_file_count() {
        // Two distinct consumer entities that live in the SAME file: one file,
        // two entities. The fanout decision is graph-native — it keys on the
        // consumer ENTITY count (2 >= threshold), so it fires even though the
        // consumers project onto a single file. A file-count decision would
        // have stayed silent here; that is exactly the file-first behavior this
        // rule must not have.
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let new = old.clone();
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 2,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                // Both consumers in one file: file count (1) is below threshold,
                // entity count (2) is at it.
                consumer_files: vec!["src/shared.rs".to_string()],
                covering_tests: 0,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        let fanout: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(
            fanout.len(),
            1,
            "fanout fires on 2 consumer entities even though they share one file"
        );
        assert!(fanout[0]
            .message
            .contains("2 distinct non-test consumer(s) across 1 file(s)"));
    }

    #[test]
    fn private_body_only_consumer_fanout_does_not_gate() {
        let mut old = test_entity_with_span(
            "_getconftestmodules",
            "src/_pytest/config/__init__.py",
            399,
            422,
        );
        old.visibility = Visibility::Private;
        let new = old.clone();
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 4,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                consumer_files: vec![
                    "src/_pytest/config/__init__.py".to_string(),
                    "testing/test_conftest.py".to_string(),
                ],
                covering_tests: 0,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::ConsumerFanout),
            "private helper body-only fanout must stay visible as context, not gate: {comments:?}"
        );
    }

    #[test]
    fn consumer_fanout_silent_below_threshold_and_on_surface_changes() {
        let old = test_entity_with_span("narrow_fn", "src/narrow.rs", 1, 20);
        let new = old.clone();
        let consumer = test_entity_with_span("only_use", "src/only.rs", 1, 5);

        // One consumer file: below threshold, silent.
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![consumer.clone()],
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 1,
                strong_consumer_count: 1,
                contract_consumer_count: 0,
                consumer_files: vec!["src/only.rs".to_string()],
                covering_tests: 0,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        assert!(!comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::ConsumerFanout));

        // Signature change with wide fanout: the breaking/signature channels
        // own it; fanout stays silent.
        let mut resigned = old.clone();
        resigned.signature = "fn narrow_fn(extra: u8)".to_string();
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: resigned.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: resigned.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![consumer],
            changed_ids: vec![resigned.id],
            entity_impacts: vec![EntityImpact {
                entity_id: resigned.id,
                consumer_count: 2,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 0,
                consumers_migrated_in_diff: 0,
                call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        assert!(!comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::ConsumerFanout));
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::Breaking));
    }

    #[test]
    fn visibility_reduction_produces_comment() {
        let old = test_entity_with_span("public_fn", "src/lib.rs", 10, 20);
        let mut new = old.clone();
        new.visibility = Visibility::Private;

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::VisibilityChange));
    }

    #[test]
    fn rename_produces_comment() {
        let old = test_entity_with_span("old_name", "src/lib.rs", 1, 5);
        let mut new = old.clone();
        new.name = "new_name".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::Renamed));
    }

    #[test]
    fn comments_sorted_by_file_then_line() {
        let e1 = test_entity_with_span("fn_b", "src/b.rs", 10, 20);
        let e2 = test_entity_with_span("fn_a", "src/a.rs", 5, 15);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: e1.id,
                    kind: EntityChangeKind::Added(e1.clone()),
                },
                EntityChange {
                    entity_id: e2.id,
                    kind: EntityChangeKind::Added(e2.clone()),
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        // src/a.rs should come before src/b.rs
        let files: Vec<&str> = comments.iter().map(|c| c.file.as_str()).collect();
        let a_pos = files.iter().position(|f| *f == "src/a.rs").unwrap();
        let b_pos = files.iter().position(|f| *f == "src/b.rs").unwrap();
        assert!(a_pos < b_pos);
    }

    #[test]
    fn group_by_file_groups_correctly() {
        let e1 = test_entity_with_span("fn_a", "src/a.rs", 1, 5);
        let e2 = test_entity_with_span("fn_b", "src/a.rs", 10, 20);
        let e3 = test_entity_with_span("fn_c", "src/b.rs", 1, 5);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: e1.id,
                    kind: EntityChangeKind::Added(e1.clone()),
                },
                EntityChange {
                    entity_id: e2.id,
                    kind: EntityChangeKind::Added(e2.clone()),
                },
                EntityChange {
                    entity_id: e3.id,
                    kind: EntityChangeKind::Added(e3.clone()),
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        let grouped = group_by_file(&comments);
        assert_eq!(grouped.len(), 2);
        // src/a.rs has two entities so at least 2 comments (could have coverage gap comments too)
        assert!(grouped["src/a.rs"].len() >= 2);
        assert!(grouped["src/b.rs"].len() >= 1);
    }
}
