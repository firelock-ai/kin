//! Opt-in, local-first telemetry for `kin locate` (5.11/R12).
//!
//! Default OFF. When the operator opts in — via the `KIN_LOCATE_TELEMETRY` env
//! var or a `.kin/telemetry/consent` marker file — each locate query spools an
//! append-only JSONL event under `.kin/telemetry/`. Local only: nothing is ever
//! uploaded and no daemon/network is involved. See
//! `crates/kin-cli/docs/locate-telemetry-design.md`.
//!
//! The pure helpers here ([`telemetry_enabled`], [`spool_file_name`],
//! [`append_event`]) are unit-tested directly; the consent-gated wiring into the
//! locate path lives in `locate.rs`.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Schema version for spooled telemetry events. Bump on any breaking change so
/// downstream readers can gate on it.
pub const TELEMETRY_SCHEMA_VERSION: u32 = 1;

/// One ranked result as recorded in a [`LocateQueryEvent`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TelemetryResult {
    pub path: String,
    pub rank: usize,
    pub score: f32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
    /// Best entity Kin attributed to this file, when entity identity is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_entity: Option<String>,
}

/// One pruned/funnel candidate as recorded in a [`LocateQueryEvent`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TelemetryFunnelEntry {
    pub path: String,
    pub score: f32,
    pub reason: String,
}

/// A spooled locate-query telemetry event (`kind = "locate_query"`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LocateQueryEvent {
    pub schema_version: u32,
    pub kind: String,
    pub ts_unix_ms: u64,
    pub query: String,
    pub max_files: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring_track: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<TelemetryResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub funnel: Vec<TelemetryFunnelEntry>,
}

impl LocateQueryEvent {
    /// Build a `locate_query` event shell; callers fill `scoring_track`,
    /// `results`, and `funnel`.
    pub fn new(ts_unix_ms: u64, query: impl Into<String>, max_files: usize) -> Self {
        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            kind: "locate_query".to_string(),
            ts_unix_ms,
            query: query.into(),
            max_files,
            scoring_track: None,
            results: Vec::new(),
            funnel: Vec::new(),
        }
    }
}

/// Resolve telemetry consent. The `KIN_LOCATE_TELEMETRY` env value wins when
/// decisive (`1`/`true`/`yes`/`on` → enabled, `0`/`false`/`no`/`off` → forced
/// off); otherwise the consent marker file's presence governs; default OFF.
///
/// Pure (env value and marker presence are passed in) so the precedence is
/// unit-testable without mutating process env or the filesystem.
pub fn telemetry_enabled(env_value: Option<&str>, consent_marker_present: bool) -> bool {
    match env_value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "true" | "yes" | "on") => return true,
        Some("0" | "false" | "no" | "off") => return false,
        _ => {}
    }
    consent_marker_present
}

/// Telemetry spool directory for a `.kin` root.
pub fn telemetry_dir(kin_root: &Path) -> PathBuf {
    kin_root.join("telemetry")
}

/// Durable consent marker path for a `.kin` root: create it to opt in, delete it
/// to revoke.
pub fn consent_marker_path(kin_root: &Path) -> PathBuf {
    telemetry_dir(kin_root).join("consent")
}

/// Day-bucketed spool file name (UTC) for an event timestamp, e.g.
/// `locate-2026-06-10.jsonl`.
pub fn spool_file_name(ts_unix_ms: u64) -> String {
    use chrono::{TimeZone, Utc};
    let secs = (ts_unix_ms / 1000) as i64;
    let date = Utc
        .timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!("locate-{date}.jsonl")
}

/// Append one event as a JSON line to the day's spool file under `dir`, creating
/// the directory if needed. Returns the file written. Best-effort by contract:
/// callers must treat an `Err` as "telemetry unavailable", never as a locate
/// failure.
pub fn append_event(dir: &Path, event: &LocateQueryEvent) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(spool_file_name(event.ts_unix_ms));
    let mut line = serde_json::to_string(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    file.write_all(line.as_bytes())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_env_overrides_marker_else_marker_governs() {
        // Env decisive both ways, overriding the marker.
        assert!(telemetry_enabled(Some("1"), false));
        assert!(telemetry_enabled(Some("true"), false));
        assert!(!telemetry_enabled(Some("0"), true));
        assert!(!telemetry_enabled(Some("off"), true));
        // Env absent / non-decisive → marker governs.
        assert!(telemetry_enabled(None, true));
        assert!(!telemetry_enabled(None, false));
        assert!(!telemetry_enabled(Some(""), false));
        assert!(telemetry_enabled(Some("garbage"), true));
        // Default is OFF.
        assert!(!telemetry_enabled(None, false));
    }

    #[test]
    fn spool_file_name_is_utc_day_bucketed() {
        assert_eq!(spool_file_name(0), "locate-1970-01-01.jsonl");
        // 2021-01-01T00:00:00Z = 1609459200 s.
        assert_eq!(
            spool_file_name(1_609_459_200_000),
            "locate-2021-01-01.jsonl"
        );
    }

    #[test]
    fn append_event_writes_jsonl_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let spool = telemetry_dir(dir.path());
        let mut ev = LocateQueryEvent::new(0, "where is the parser", 6);
        ev.scoring_track = Some("BroadBlend".to_string());
        ev.results.push(TelemetryResult {
            path: "src/x.rs".to_string(),
            rank: 0,
            score: 1.25,
            signals: vec!["entity_resolve".to_string()],
            top_entity: Some("entity:abc".to_string()),
        });
        ev.funnel.push(TelemetryFunnelEntry {
            path: "src/y.rs".to_string(),
            score: 0.04,
            reason: "below_support_floor".to_string(),
        });

        let p1 = append_event(&spool, &ev).unwrap();
        // Second event same day → appended to the same file (two lines).
        append_event(&spool, &ev).unwrap();

        let contents = std::fs::read_to_string(&p1).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "events append, not overwrite");
        let parsed: LocateQueryEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed, ev, "event round-trips through JSONL");
        assert_eq!(parsed.schema_version, TELEMETRY_SCHEMA_VERSION);
        assert_eq!(parsed.kind, "locate_query");
    }

    #[test]
    fn consent_marker_path_is_under_telemetry_dir() {
        let root = Path::new("/tmp/repo/.kin");
        assert_eq!(
            consent_marker_path(root),
            Path::new("/tmp/repo/.kin/telemetry/consent")
        );
    }
}
