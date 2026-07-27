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

use regex::Regex;
use std::io::IsTerminal;
use std::sync::OnceLock;

pub const RESET: &str = "\x1b[0m";
pub const ACCENT: &str = "\x1b[38;5;44m";
pub const ACCENT_BOLD: &str = "\x1b[1;38;5;51m";
pub const ACCENT_DIM: &str = "\x1b[2;38;5;44m";
pub const GREEN: &str = "\x1b[38;5;114m";
pub const AMBER_BOLD: &str = "\x1b[1;38;5;179m";
pub const DIM: &str = "\x1b[38;5;245m";
pub const FAINT: &str = "\x1b[38;5;239m";
pub const BRIGHT: &str = "\x1b[38;5;255m";
pub const BOLD_WHITE: &str = "\x1b[1;38;5;255m";
pub const BOLD: &str = "\x1b[1m";

/// Whether painted output is wanted, decided once per process.
pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && !std::env::var("TERM").is_ok_and(|term| term == "dumb")
    })
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

    let header = compiled(
        &HEADER,
        r"^References to '(.*)' -> (\S+) \(([^)]+)\) @ (.+)$",
    );
    if let Some(caps) = header.captures(line) {
        return format!(
            "References to '{}' -> {BOLD_WHITE}{}{RESET} {DIM}({}){RESET} @ {ACCENT}{}{RESET}",
            &caps[1], &caps[2], &caps[3], &caps[4]
        );
    }

    let count = compiled(&COUNT, r"^referenced by (\d+) entities:$");
    if let Some(caps) = count.captures(line) {
        return format!("referenced by {ACCENT_BOLD}{}{RESET} entities:", &caps[1]);
    }

    let entry = compiled(&ENTRY, r"^  (.+) @ (\S+:\d+) \[([^\]]*)\]$");
    if let Some(caps) = entry.captures(line) {
        return format!(
            "  {BRIGHT}{}{RESET} @ {ACCENT}{}{RESET} {FAINT}[{}]{RESET}",
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

    let header = compiled(
        &HEADER,
        r"^Impact analysis for '(.*)' \(([^)]+)\)(?: @ (\S+))?:$",
    );
    if let Some(caps) = header.captures(line) {
        let at = caps
            .get(3)
            .map(|loc| format!(" @ {ACCENT_DIM}{}{RESET}", loc.as_str()))
            .unwrap_or_default();
        return format!(
            "Impact analysis for '{ACCENT_BOLD}{}{RESET}' {DIM}({}){RESET}{at}:",
            &caps[1], &caps[2]
        );
    }

    let count = compiled(
        &COUNT,
        r"^  (\d+) local entities impacted within (\d+) (hops?):$",
    );
    if let Some(caps) = count.captures(line) {
        return format!(
            "  {BOLD_WHITE}{}{RESET} local entities impacted within {} {}:",
            &caps[1], &caps[2], &caps[3]
        );
    }

    if line == "  1 hop (direct callers):" {
        return format!("{AMBER_BOLD}{line}{RESET}");
    }

    let hops = compiled(&HOPS, r"^  \d+ hops:$");
    if hops.is_match(line) {
        return format!("{BOLD_WHITE}{line}{RESET}");
    }

    let entity = compiled(&ENTITY, r"^    - (.+) \(([^)]+)\)(?: @ (\S+))?$");
    if let Some(caps) = entity.captures(line) {
        let at = caps
            .get(3)
            .map(|loc| format!(" @ {ACCENT_DIM}{}{RESET}", loc.as_str()))
            .unwrap_or_default();
        return format!(
            "    - {BOLD_WHITE}{}{RESET} {DIM}({}){RESET}{at}",
            &caps[1], &caps[2]
        );
    }

    let note = compiled(&NOTE, r"^  Note: (.*)$");
    if let Some(caps) = note.captures(line) {
        return format!("  {DIM}Note:{RESET} {}", &caps[1]);
    }

    line.to_string()
}

fn paint_clone(line: &str) -> String {
    static EXTRACTED: OnceLock<Regex> = OnceLock::new();
    static DURATION: OnceLock<Regex> = OnceLock::new();

    if line == "=== Kin Migration Complete ===" {
        return format!("{BOLD}{line}{RESET}");
    }

    let extracted = compiled(&EXTRACTED, r"^((?:Entities|Relations) extracted: )(.+)$");
    if let Some(caps) = extracted.captures(line) {
        return format!("{}{ACCENT_BOLD}{}{RESET}", &caps[1], &caps[2]);
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
    // the two-or-more space runs are what tell the fields apart.
    let row = compiled(
        &ROW,
        r"^  ([0-9a-fA-F]{6,12})  (\S+)( {2,})(\S.*?)( {2,})(\S.*)$",
    );
    if let Some(caps) = row.captures(line) {
        return format!(
            "  {ACCENT_DIM}{}{RESET}  {DIM}{}{RESET}{}{DIM}{}{RESET}{}{BRIGHT}{}{RESET}",
            &caps[1], &caps[2], &caps[3], &caps[4], &caps[5], &caps[6]
        );
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

    #[test]
    fn refs_header_is_painted() {
        let plain = "References to 'probe' -> probe_symbol (Function) @ src/target.rs";
        let painted = paint_refs(plain);
        assert_painted(&painted, plain, &format!("{BOLD_WHITE}probe_symbol"));
        assert!(painted.contains(&format!("{ACCENT}src/target.rs")));
        assert!(painted.contains(&format!("{DIM}(Function)")));
    }

    #[test]
    fn refs_count_and_entry_are_painted() {
        let count = "referenced by 2 entities:";
        assert_painted(&paint_refs(count), count, &format!("{ACCENT_BOLD}2"));

        let entry = "  disk_only @ src/caller.rs:3 [Calls, References]";
        let painted = paint_refs(entry);
        assert_painted(&painted, entry, &format!("{BRIGHT}disk_only"));
        assert!(painted.contains(&format!("{ACCENT}src/caller.rs:3")));
        assert!(painted.contains(&format!("{FAINT}[Calls, References]")));
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
        assert_painted(&painted, header, &format!("{ACCENT_BOLD}handler"));
        assert!(painted.contains(&format!("{ACCENT_DIM}src/api.rs:42")));

        let count = "  7 local entities impacted within 3 hops:";
        assert_painted(&paint_impact(count), count, &format!("{BOLD_WHITE}7"));
    }

    #[test]
    fn impact_header_without_location_is_painted() {
        let plain = "Impact analysis for 'handler' (Function):";
        assert_painted(
            &paint_impact(plain),
            plain,
            &format!("{ACCENT_BOLD}handler"),
        );
    }

    #[test]
    fn impact_hop_groups_and_entities_are_painted() {
        let direct = "  1 hop (direct callers):";
        assert_painted(&paint_impact(direct), direct, AMBER_BOLD);

        let further = "  2 hops:";
        assert_painted(&paint_impact(further), further, BOLD_WHITE);

        let entity = "    - render (Function) @ src/view.rs:8";
        let painted = paint_impact(entity);
        assert_painted(&painted, entity, &format!("{BOLD_WHITE}render"));
        assert!(painted.contains(&format!("{ACCENT_DIM}src/view.rs:8")));
    }

    #[test]
    fn impact_note_dims_only_the_label() {
        let plain = "  Note: 3 matches; showing the deterministic first match.";
        let painted = paint_impact(plain);
        assert_painted(&painted, plain, &format!("{DIM}Note:{RESET}"));
    }

    #[test]
    fn impact_ignores_unknown_lines() {
        let plain = "Entity 'nope' not found in this repo's graph.";
        assert_eq!(paint_impact(plain), plain);

        let empty = "  No local downstream impact found.";
        assert_eq!(paint_impact(empty), empty);
    }

    #[test]
    fn clone_summary_lines_are_painted() {
        let header = "=== Kin Migration Complete ===";
        assert_painted(&paint_clone(header), header, BOLD);

        let entities = "Entities extracted: 3805";
        assert_painted(
            &paint_clone(entities),
            entities,
            &format!("{ACCENT_BOLD}3805"),
        );

        let relations = "Relations extracted: 9120";
        assert_painted(
            &paint_clone(relations),
            relations,
            &format!("{ACCENT_BOLD}9120"),
        );

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
        assert_painted(&painted, plain, &format!("{ACCENT_DIM}a1b2c3d4e5f6"));
        assert!(painted.contains(&format!("{DIM}2026-07-27")));
        assert!(painted.contains(&format!("{DIM}Troy Fortin")));
        assert!(painted.contains(&format!("{BRIGHT}Add lane teardown")));
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
}
