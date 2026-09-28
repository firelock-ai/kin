// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Color for the human-facing CLI surfaces.
//!
//! The lines painted here are composed daemon-side and reach the CLI as plain
//! strings that callers and tests read verbatim, so color is applied at print
//! time instead of at composition time. Each painter recognizes one known line
//! shape, rebuilds it from the captured pieces, and returns the input untouched
//! when nothing matches. Stripping the escapes from a painted line yields the
//! original line, and every painter is a no-op when color is off, so redirected
//! output stays byte-identical to the composed line.
//!
//! Words are never painted a fixed colour, because no single colour reads on
//! both a dark and a light background: xterm 255, which entity names used to
//! take, is 1.2:1 on white. Text keeps the terminal's own foreground. Entity
//! names and counts are bold, paths are plain, and secondary text such as
//! kinds, resolution tags, reference sites and the `@` between a name and its
//! path is faint. Success takes the theme's green and a warning the theme's
//! yellow in bold, which every theme tunes for its own background.

use regex::Regex;
use std::io::IsTerminal;
use std::sync::OnceLock;

pub const RESET: &str = "\x1b[0m";
/// Bold, in the terminal's own foreground: names and counts.
pub const BOLD: &str = "\x1b[1m";
/// Faint, in the terminal's own foreground: secondary text.
pub const FAINT: &str = "\x1b[2m";
/// The theme's green: success.
pub const GREEN: &str = "\x1b[32m";
/// The theme's yellow, in bold: a warning.
pub const WARN: &str = "\x1b[1;33m";

/// Whether painted output is wanted, decided once per process.
pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        wanted(
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").is_some(),
            std::env::var("TERM").ok().as_deref(),
        )
    })
}

/// The colour decision for given inputs, split from the environment read so a
/// caller that gathers its own inputs, and a test, reach the same rule.
///
/// A set `NO_COLOR` turns colour off whatever its value, and so does
/// `TERM=dumb`.
pub(crate) fn wanted(stdout_is_terminal: bool, no_color: bool, term: Option<&str>) -> bool {
    stdout_is_terminal && !no_color && term != Some("dumb")
}

pub fn paint_refs_line(line: &str) -> String {
    if enabled() {
        paint_refs(line)
    } else {
        line.to_string()
    }
}

pub fn paint_impact_line(line: &str) -> String {
    if enabled() {
        paint_impact(line)
    } else {
        line.to_string()
    }
}

pub fn paint_clone_line(line: &str) -> String {
    if enabled() {
        paint_clone(line)
    } else {
        line.to_string()
    }
}

pub fn paint_history_line(line: &str) -> String {
    if enabled() {
        paint_history(line)
    } else {
        line.to_string()
    }
}

fn compiled(slot: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    slot.get_or_init(|| Regex::new(pattern).unwrap())
}

fn paint_refs(line: &str) -> String {
    static HEADER: OnceLock<Regex> = OnceLock::new();
    static COUNT: OnceLock<Regex> = OnceLock::new();
    static ENTRY: OnceLock<Regex> = OnceLock::new();
    static PROJECTION: OnceLock<Regex> = OnceLock::new();
    static COMPACT: OnceLock<Regex> = OnceLock::new();

    // The focal is named by its id and the file it is projected into, the
    // address every row below carries too. The address stays plain.
    let header = compiled(
        &HEADER,
        r"^References to '(.*)' -> (\S+) \(([^)]+)\) (\[[^\]]+\].*)$",
    );
    if let Some(caps) = header.captures(line) {
        return format!(
            "References to '{}' -> {BOLD}{}{RESET} {FAINT}({}){RESET} {}",
            &caps[1], &caps[2], &caps[3], &caps[4]
        );
    }

    // The headline carries the unconfirmed candidates it held out of itself, so
    // the count and the rows it is not counting are read together. The suffix
    // is optional and the literal tail is captured rather than rebuilt, because
    // an unmatched line here prints as plain text and loses its color silently.
    let count = compiled(
        &COUNT,
        r"^referenced by (\d+) entities(?:, plus (\d+)( unconfirmed candidates? not in that count))?:$",
    );
    if let Some(caps) = count.captures(line) {
        return match (caps.get(2), caps.get(3)) {
            (Some(unconfirmed), Some(tail)) => format!(
                "referenced by {BOLD}{}{RESET} entities, plus {BOLD}{}{RESET}{}:",
                &caps[1],
                unconfirmed.as_str(),
                tail.as_str()
            ),
            _ => format!("referenced by {BOLD}{}{RESET} entities:", &caps[1]),
        };
    }

    // A row names its entity by id, then the file it is projected into when
    // it has one; the resolution marker trails the relation bracket, and the
    // reference sites trail that. Anchoring on any one shape loses the color
    // silently, because an unmatched line prints as plain text. An entity the
    // graph cannot vouch for carries `(span stale)` after its projection, and
    // it stays part of the plain address.
    let entry = compiled(
        &ENTRY,
        r"^  (.+?) (\[[0-9a-fA-F-]+\](?: \(projection: .+?\))?(?: \(span stale\))?) (\[[^\]]*\](?: \([^)]*\))?(?: sites .*)?)$",
    );
    // The candidate note every resolving command shares.
    if let Some(rest) = line.strip_prefix("note: ") {
        return format!("{FAINT}note:{RESET} {rest}");
    }

    // The terminal layout: the file a group of callers is projected into, then
    // each caller name first with its sites, and the count of callers left to
    // `--all`.
    let projection = compiled(&PROJECTION, r"^  \(projection: (.+)\)$");
    if let Some(caps) = projection.captures(line) {
        return format!("  {FAINT}(projection:{RESET} {}{FAINT}){RESET}", &caps[1]);
    }
    if line == "  (no projection)" {
        return format!("{FAINT}{line}{RESET}");
    }
    let compact = compiled(&COMPACT, r"^    (\S+)( {2,})(\S.*)$");
    if let Some(caps) = compact.captures(line) {
        return format!(
            "    {BOLD}{}{RESET}{}{FAINT}{}{RESET}",
            &caps[1], &caps[2], &caps[3]
        );
    }
    if line.starts_with("  and ") && line.ends_with("for the full list") {
        return format!("{FAINT}{line}{RESET}");
    }

    if let Some(caps) = entry.captures(line) {
        return format!(
            "  {BOLD}{}{RESET} {} {FAINT}{}{RESET}",
            &caps[1], &caps[2], &caps[3]
        );
    }

    line.to_string()
}

fn paint_impact(line: &str) -> String {
    static HEADER: OnceLock<Regex> = OnceLock::new();
    static COUNT: OnceLock<Regex> = OnceLock::new();
    static HOPS: OnceLock<Regex> = OnceLock::new();
    static ENTITY: OnceLock<Regex> = OnceLock::new();
    static NOTE: OnceLock<Regex> = OnceLock::new();

    // `(span stale)` after the path is part of the location when the graph
    // cannot vouch for the line, so it stays inside the plain location.
    let header = compiled(
        &HEADER,
        r"^Impact analysis for '(.*)' \(([^)]+)\)(?: @ (\S+(?: \(span stale\))?))?:$",
    );
    if let Some(caps) = header.captures(line) {
        let at = caps
            .get(3)
            .map(|loc| format!(" {FAINT}@{RESET} {}", loc.as_str()))
            .unwrap_or_default();
        return format!(
            "Impact analysis for '{BOLD}{}{RESET}' {FAINT}({}){RESET}{at}:",
            &caps[1], &caps[2]
        );
    }

    let count = compiled(
        &COUNT,
        r"^  (\d+) local entities impacted within (\d+) (hops?):$",
    );
    if let Some(caps) = count.captures(line) {
        return format!(
            "  {BOLD}{}{RESET} local entities impacted within {} {}:",
            &caps[1], &caps[2], &caps[3]
        );
    }

    // The callers a change breaks first.
    if line == "  1 hop (direct callers):" {
        return format!("{WARN}{line}{RESET}");
    }

    let hops = compiled(&HOPS, r"^  \d+ hops:$");
    if hops.is_match(line) {
        return format!("{BOLD}{line}{RESET}");
    }

    let entity = compiled(
        &ENTITY,
        r"^    - (.+) \(([^)]+)\)(?: @ (\S+(?: \(span stale\))?))?$",
    );
    if let Some(caps) = entity.captures(line) {
        let at = caps
            .get(3)
            .map(|loc| format!(" {FAINT}@{RESET} {}", loc.as_str()))
            .unwrap_or_default();
        return format!(
            "    - {BOLD}{}{RESET} {FAINT}({}){RESET}{at}",
            &caps[1], &caps[2]
        );
    }

    let note = compiled(&NOTE, r"^  Note: (.*)$");
    if let Some(caps) = note.captures(line) {
        return format!("  {FAINT}Note:{RESET} {}", &caps[1]);
    }
    // The candidate note every resolving command shares.
    if let Some(rest) = line.strip_prefix("note: ") {
        return format!("{FAINT}note:{RESET} {rest}");
    }

    line.to_string()
}

fn paint_clone(line: &str) -> String {
    static EXTRACTED: OnceLock<Regex> = OnceLock::new();
    static DURATION: OnceLock<Regex> = OnceLock::new();
    static ADMITTED_FIELD: OnceLock<Regex> = OnceLock::new();

    if line.starts_with("Cloned Git transport and admitted exact Kin repository authority at ") {
        return format!("{GREEN}{line}{RESET}");
    }

    // The indented field rows of the admission summary. The labels are
    // enumerated rather than matched generically so an unrelated indented
    // `label: value` line still passes through untouched.
    let admitted_field = compiled(
        &ADMITTED_FIELD,
        r"^  (Repository|Workspace|Authority generation|Semantic enrichment): (.+)$",
    );
    if let Some(caps) = admitted_field.captures(line) {
        return format!("  {FAINT}{}:{RESET} {}", &caps[1], &caps[2]);
    }

    if line == "=== Kin Migration Complete ===" {
        return format!("{BOLD}{line}{RESET}");
    }

    let extracted = compiled(&EXTRACTED, r"^((?:Entities|Relations) extracted: )(.+)$");
    if let Some(caps) = extracted.captures(line) {
        return format!("{}{BOLD}{}{RESET}", &caps[1], &caps[2]);
    }

    let duration = compiled(&DURATION, r"^(Duration: )(.+)$");
    if let Some(caps) = duration.captures(line) {
        return format!("{}{BOLD}{}{RESET}", &caps[1], &caps[2]);
    }

    if line.starts_with("Clone complete.") {
        return format!("{GREEN}{line}{RESET}");
    }

    line.to_string()
}

fn paint_history(line: &str) -> String {
    static ROW: OnceLock<Regex> = OnceLock::new();

    // Author and subject are separated by the formatter's column padding, so
    // the two-or-more space runs are what tell the fields apart. The commit and
    // its date are the row's secondary text; its author and subject are what
    // a reader reads.
    let row = compiled(&ROW, r"^  ([0-9a-fA-F]{6,12}  \S+)( {2,}\S.*? {2,}\S.*)$");
    if let Some(caps) = row.captures(line) {
        return format!("  {FAINT}{}{RESET}{}", &caps[1], &caps[2]);
    }

    line.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_ansi(painted: &str) -> String {
        let escape = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
        escape.replace_all(painted, "").to_string()
    }

    fn assert_painted(painted: &str, plain: &str, expected: &str) {
        assert_ne!(painted, plain, "line was not painted: {plain}");
        assert!(
            painted.contains(expected),
            "missing {expected:?} in {painted:?}"
        );
        assert_eq!(strip_ansi(painted), plain, "round trip changed the line");
    }

    /// A `kin refs` answer as the product composes it.
    ///
    /// The styler is fed these lines rather than strings written here to match
    /// its regexes, because a hand-written fixture agrees with the pattern by
    /// construction and stays green when the composed row moves underneath it.
    /// That is how the anchored `:line` row survived both spanless locations
    /// and the trailing resolution marker without a red test.
    fn real_refs_response_lines() -> Vec<String> {
        real_refs_response_lines_in(None)
    }

    /// The same answer, laid out in `view` when one is given.
    fn real_refs_response_lines_in(view: Option<crate::commands::refs::RefsView>) -> Vec<String> {
        use crate::commands::refs::{build_refs_response_quoted, RefsRequest, RefsSpine};
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, RelationKind,
            SemanticFingerprint, SourceSpan, Visibility,
        };

        fn entity(name: &str, rel_path: &str, start_line: Option<u32>) -> Entity {
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
                    equivalence_hash: Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(rel_path)),
                span: start_line.map(|line| SourceSpan {
                    file: FilePathId::new(rel_path),
                    start_byte: 0,
                    end_byte: 0,
                    start_line: line,
                    start_col: 1,
                    end_line: line,
                    end_col: 1,
                }),
                signature: format!("fn {name}()"),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

        let target = entity("probe_symbol", "target_mod.rs", Some(0));
        // One caller carries a span and one does not, so the answer holds both
        // location shapes a row can take.
        let spanned = entity("spanned_caller", "spanned.rs", Some(2));
        let spanless = entity("spanless_caller", "spanless.rs", None);

        let graph = InMemoryGraph::new();
        for record in [&target, &spanned, &spanless] {
            graph.upsert_entity(record).unwrap();
        }
        // Two confidences, so the rows carry two different resolution markers
        // and a painter that assumed one value would be caught. The weaker one
        // is the receiver-method fan-out tier, which is what puts its row under
        // the candidate heading. One caller's edge also carries site spans and
        // the other's does not, so the answer holds both shapes the trailing
        // site clause can take: a list of lines, and a named absence.
        let site_span = |row: u32| SourceSpan {
            file: FilePathId::new("spanned.rs"),
            start_byte: 0,
            end_byte: 1,
            start_line: row,
            start_col: 0,
            end_line: row,
            end_col: 1,
        };
        let sited_evidence = vec![
            kin_model::relation::RelationEvidence {
                source_span: Some(site_span(6)),
                ..Default::default()
            },
            kin_model::relation::RelationEvidence {
                source_span: Some(site_span(8)),
                ..Default::default()
            },
        ];
        for (caller, confidence, evidence) in [
            (&spanned, 1.0f32, sited_evidence),
            (
                &spanless,
                kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE,
                Vec::new(),
            ),
        ] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::References,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence,
                })
                .unwrap();
        }

        build_refs_response_quoted(
            &layout,
            &graph,
            &RefsRequest {
                entity: "probe_symbol".to_string(),
                kind: "all".to_string(),
            },
            // This fixture asserts PAINTING, not absence honesty, and it holds
            // references, so no verdict renders on either envelope.
            &kin_mcp::Envelope::daemon(),
            RefsSpine::absent(),
            &kin_mcp::handlers::common::NoCallerText,
            view,
        )
        .unwrap()
        .lines
    }

    /// Every escape a painter writes is bold, faint, the theme's green or
    /// yellow, or a reset, never a fixed 256-colour index or a 24-bit colour,
    /// which read on one background and vanish on the other.
    fn assert_theme_aware(painted: &str) {
        let escape = Regex::new(r"\x1b\[([0-9;]*)m").unwrap();
        for found in escape.captures_iter(painted) {
            assert!(
                matches!(&found[1], "0" | "1" | "2" | "32" | "1;33"),
                "{painted:?} carries the escape {:?}, which is not theme-aware",
                &found[0]
            );
        }
    }

    #[test]
    fn refs_lines_the_product_composed_are_painted() {
        let lines = real_refs_response_lines();

        let header = lines.first().expect("a response opens with its header");
        let painted = paint_refs(header);
        assert_painted(&painted, header, &format!("{BOLD}probe_symbol{RESET}"));
        // The header names the focal by id and projection after the faint
        // kind, keeps that address whole and plain, and carries no file line.
        assert!(
            painted.contains(&format!("{FAINT}(Function){RESET} [")),
            "the kind must be faint and the address follow it: {painted:?}"
        );
        assert!(
            painted.ends_with(" (projection: target_mod.rs)"),
            "the focal's address must stay whole and plain: {painted:?}"
        );
        assert!(!header.contains("target_mod.rs:"), "{header:?}");
        assert_theme_aware(&painted);

        // One real caller and one receiver-name candidate, so the headline counts
        // one and the candidate keeps its own heading. Both rows are still
        // rendered, which is what this test is about.
        let count = lines
            .iter()
            .find(|line| line.starts_with("referenced by "))
            .unwrap_or_else(|| panic!("no count line in {lines:?}"));
        let painted_count = paint_refs(count);
        assert_painted(&painted_count, count, &format!("{BOLD}1"));
        // The headline names the row it is not counting, on the same line, and
        // both numbers are painted. An unmatched count line prints as plain
        // text, so widening the sentence without widening the rule is a silent
        // regression.
        assert_eq!(
            count, "referenced by 1 entities, plus 1 unconfirmed candidate not in that count:",
            "the headline carries its unconfirmed candidates: {lines:?}"
        );
        assert_eq!(
            painted_count.matches(&format!("{BOLD}1{RESET}")).count(),
            2,
            "both the counted and the unconfirmed number are bold: {painted_count:?}"
        );
        assert_theme_aware(&painted_count);
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("1 receiver-name candidate ")),
            "the withheld candidate must be named under its own heading: {lines:?}"
        );

        let rows: Vec<&str> = lines
            .iter()
            .filter(|line| line.starts_with("  "))
            .map(String::as_str)
            .collect();
        assert_eq!(rows.len(), 2, "one row per caller: {lines:?}");

        let spanned = rows
            .iter()
            .copied()
            .find(|row| row.contains("spanned_caller"))
            .unwrap_or_else(|| panic!("no spanned row in {rows:?}"));
        let painted = paint_refs(spanned);
        assert_painted(
            &painted,
            spanned,
            &format!("  {BOLD}spanned_caller{RESET} ["),
        );
        assert!(
            painted.contains(&format!(" (projection: spanned.rs) {FAINT}[References]")),
            "the caller's address must stay whole and plain: {painted:?}"
        );
        assert!(
            !spanned.contains("spanned.rs:"),
            "no file line: {spanned:?}"
        );
        // Graph rows 6 and 8 inside a caller that starts on row 2.
        assert!(
            painted.ends_with(&format!(
                "{FAINT}[References] (type_resolved) sites +4, +6{RESET}"
            )),
            "the relation bracket, the resolution marker and the reference sites \
             must be faint, not left as plain text after a painted row: {painted:?}"
        );
        assert_theme_aware(&painted);

        let spanless = rows
            .iter()
            .copied()
            .find(|row| row.contains("spanless_caller"))
            .unwrap_or_else(|| panic!("no spanless row in {rows:?}"));
        let painted = paint_refs(spanless);
        assert_painted(
            &painted,
            spanless,
            &format!("  {BOLD}spanless_caller{RESET} ["),
        );
        assert!(
            painted.contains(" (projection: spanless.rs) "),
            "a spanless caller's address must stay whole and plain: {painted:?}"
        );
        assert!(
            painted.ends_with(&format!(
                "{FAINT}[References] (name_only) sites none (no_evidence_span){RESET}"
            )),
            "a named site absence must be painted the same way a site list is: \
             {painted:?}"
        );
        assert_theme_aware(&painted);

        // The tier note every weaker row brings.
        let note = lines
            .iter()
            .find(|line| line.starts_with("note: "))
            .unwrap_or_else(|| panic!("no tier note in {lines:?}"));
        let painted = paint_refs(note);
        assert_painted(&painted, note, &format!("{FAINT}note:{RESET} "));
    }

    /// The terminal layout is painted from the lines the product composes: the
    /// projection a group sits under, and each caller's name and sites.
    #[test]
    fn refs_lines_of_the_terminal_layout_are_painted() {
        let lines = real_refs_response_lines_in(Some(crate::commands::refs::RefsView {
            width: 80,
            callers: crate::commands::refs::RefsView::CALLERS,
        }));
        let heading = lines
            .iter()
            .find(|line| line.as_str() == "  (projection: spanned.rs)")
            .unwrap_or_else(|| panic!("no projection heading in {lines:?}"));
        let painted = paint_refs(heading);
        assert_painted(
            &painted,
            heading,
            &format!("  {FAINT}(projection:{RESET} spanned.rs{FAINT}){RESET}"),
        );
        assert_theme_aware(&painted);
        let row = lines
            .iter()
            .find(|line| line.starts_with("    spanned_caller "))
            .unwrap_or_else(|| panic!("no caller row in {lines:?}"));
        let painted = paint_refs(row);
        assert_painted(&painted, row, &format!("    {BOLD}spanned_caller{RESET}"));
        assert!(
            painted.contains(&format!("{FAINT}+4, +6")),
            "the sites are faint: {painted:?}"
        );
        assert_theme_aware(&painted);
    }

    /// A projection path may hold parentheses of its own, as a route group
    /// such as `app/(shop)/page.tsx` does, and the row is still painted whole.
    #[test]
    fn refs_row_with_parentheses_in_its_projection_is_painted() {
        let row =
            "  page [3fcd4028-db62-4c50-aafe-ec3bf7258a58] (projection: app/(shop)/page.tsx) \
                   [Calls] (import_scoped) sites +2 `load`";
        let painted = paint_refs(row);
        assert_painted(&painted, row, &format!("  {BOLD}page{RESET} ["));
        assert!(
            painted.ends_with(&format!(
                " (projection: app/(shop)/page.tsx) {FAINT}[Calls] (import_scoped) sites +2 `load`{RESET}"
            )),
            "{painted:?}"
        );
        assert_theme_aware(&painted);
    }

    #[test]
    fn refs_ignores_unknown_lines() {
        let plain = "No incoming Calls relations.";
        assert_eq!(paint_refs(plain), plain);
        assert_eq!(paint_refs(""), "");
    }

    #[test]
    fn impact_header_and_counts_are_painted() {
        let header = "Impact analysis for 'handler' (Function) @ src/api.rs:42:";
        let painted = paint_impact(header);
        assert_painted(&painted, header, &format!("{BOLD}handler{RESET}"));
        assert!(painted.ends_with(&format!(
            "{FAINT}(Function){RESET} {FAINT}@{RESET} src/api.rs:42:"
        )));
        assert_theme_aware(&painted);

        let count = "  7 local entities impacted within 3 hops:";
        assert_painted(&paint_impact(count), count, &format!("{BOLD}7{RESET}"));
    }

    #[test]
    fn impact_header_without_location_is_painted() {
        let plain = "Impact analysis for 'handler' (Function):";
        assert_painted(&paint_impact(plain), plain, &format!("{BOLD}handler"));
    }

    #[test]
    fn impact_hop_groups_and_entities_are_painted() {
        let direct = "  1 hop (direct callers):";
        assert_painted(&paint_impact(direct), direct, WARN);

        let further = "  2 hops:";
        assert_painted(&paint_impact(further), further, BOLD);

        let entity = "    - render (Function) @ src/view.rs:8";
        let painted = paint_impact(entity);
        assert_painted(&painted, entity, &format!("{BOLD}render{RESET}"));
        assert!(painted.ends_with(&format!("{FAINT}@{RESET} src/view.rs:8")));
        assert_theme_aware(&painted);
    }

    #[test]
    fn impact_note_dims_only_the_label() {
        let plain = "  Note: 3 matches; showing the deterministic first match.";
        let painted = paint_impact(plain);
        assert_painted(&painted, plain, &format!("{FAINT}Note:{RESET}"));
    }

    #[test]
    fn impact_ignores_unknown_lines() {
        let plain = "Entity 'nope' not found in this repo's graph.";
        assert_eq!(paint_impact(plain), plain);

        let empty = "  No local downstream impact found.";
        assert_eq!(paint_impact(empty), empty);
    }

    #[test]
    fn clone_admission_summary_lines_are_painted() {
        let admitted =
            "Cloned Git transport and admitted exact Kin repository authority at demo-repo";
        assert_painted(&paint_clone(admitted), admitted, GREEN);

        let repository = "  Repository: 0c8f1d6a-4b2e-4f3a-9d51-6d0b7f2c1a44";
        let painted = paint_clone(repository);
        assert_painted(
            &painted,
            repository,
            &format!("{FAINT}Repository:{RESET} 0c8f1d6a-4b2e-4f3a-9d51-6d0b7f2c1a44"),
        );

        let generation = "  Authority generation: 1";
        assert_painted(
            &paint_clone(generation),
            generation,
            &format!("{FAINT}Authority generation:{RESET} 1"),
        );

        let enrichment = "  Semantic enrichment: not run";
        assert_painted(
            &paint_clone(enrichment),
            enrichment,
            &format!("{FAINT}Semantic enrichment:{RESET} not run"),
        );
    }

    #[test]
    fn clone_summary_lines_are_painted() {
        let header = "=== Kin Migration Complete ===";
        assert_painted(&paint_clone(header), header, BOLD);

        let entities = "Entities extracted: 3805";
        assert_painted(&paint_clone(entities), entities, &format!("{BOLD}3805"));

        let relations = "Relations extracted: 9120";
        assert_painted(&paint_clone(relations), relations, &format!("{BOLD}9120"));

        let duration = "Duration: 4213ms";
        assert_painted(&paint_clone(duration), duration, &format!("{BOLD}4213ms"));

        let done = "Clone complete. Kin repository ready at demo-repo";
        assert_painted(&paint_clone(done), done, GREEN);
    }

    #[test]
    fn clone_ignores_unknown_lines() {
        let plain = "Repository: /tmp/demo-repo";
        assert_eq!(paint_clone(plain), plain);
    }

    #[test]
    fn history_row_is_painted() {
        let plain = "  a1b2c3d4e5f6  2026-07-27  Troy Fortin          Add lane teardown";
        let painted = paint_history(plain);
        assert_painted(
            &painted,
            plain,
            &format!("  {FAINT}a1b2c3d4e5f6  2026-07-27{RESET}  Troy Fortin"),
        );
        assert!(painted.ends_with("Add lane teardown"), "{painted:?}");
        assert_theme_aware(&painted);
    }

    #[test]
    fn history_ignores_unknown_lines() {
        let header = "History for 'run' (Function, Rust) at a1b2c3d4e5f6:";
        assert_eq!(paint_history(header), header);
        assert_eq!(
            paint_history("  No history recorded"),
            "  No history recorded"
        );
    }

    /// Every painter, fed every line shape it paints, writes only
    /// theme-aware escapes.
    #[test]
    fn every_painter_writes_only_theme_aware_escapes() {
        for line in [
            "References to 'x' -> x (Function) @ a.rs:1",
            "referenced by 3 entities, plus 1 unconfirmed candidate not in that count:",
            "  f @ a.rs:2 [Calls] (type_resolved) sites 3",
            "note: the tag after each row is its resolution tier.",
        ] {
            assert_theme_aware(&paint_refs(line));
        }
        for line in [
            "Impact analysis for 'h' (Function) @ a.rs:1:",
            "  2 local entities impacted within 2 hops:",
            "  1 hop (direct callers):",
            "  2 hops:",
            "    - r (Function) @ a.rs:3",
            "  Note: one.",
        ] {
            assert_theme_aware(&paint_impact(line));
        }
        for line in [
            "Cloned Git transport and admitted exact Kin repository authority at r",
            "  Repository: id",
            "=== Kin Migration Complete ===",
            "Entities extracted: 1",
            "Duration: 1ms",
            "Clone complete. Kin repository ready at r",
        ] {
            assert_theme_aware(&paint_clone(line));
        }
        assert_theme_aware(&paint_history(
            "  a1b2c3d4e5f6  2026-07-27  Troy Fortin          Add lane teardown",
        ));
    }
}
