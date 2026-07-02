// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Central registry, validation, and safe parsing for the `KIN_*` environment
//! surface.
//!
//! Kin reads well over three hundred `KIN_*` variables across the CLI, daemon,
//! MCP server, and the locate/ranking pipeline. Historically each read site
//! parsed its own variable with a bespoke helper that *silently* fell back to a
//! default on a typo, an out-of-range value, or an unparseable string. That
//! silence is the hazard: an operator who flips a knob and fat-fingers the name
//! (or the value) gets the default with no signal, and a correctness-relevant
//! override can depress retrieval quality invisibly.
//!
//! This module makes the surface explicit and loud:
//!
//! * [`registry`] enumerates every *supported* variable with its kind, default,
//!   correctness sensitivity, and a one-line description.
//! * [`audit_env`] / [`enforce_startup_env`] scan the live process environment
//!   at startup: unknown `KIN_*` names warn, invalid values fail loud (hard
//!   error for correctness-relevant vars), and non-default correctness overrides
//!   are logged so behavior drift is never silent.
//! * [`env_ms_bound`] / [`env_secs_bound_f64`] are the shared parse helpers for
//!   `*_TIMEOUT_MS` / `*_BUDGET_MS` / `*_TIMEOUT_SECS` bound knobs, where `0`
//!   means **disabled / unbounded** — never an instant zero-length timeout that
//!   guts the operation it was meant to protect.
//! * [`render_reference_markdown`] renders the human reference doc directly from
//!   the registry, and a test asserts the committed doc has not drifted.

use std::time::Duration;

mod generated {
    include!("env_registry_generated.rs");
}
pub use generated::GENERATED_KNOBS;

/// Value-kind of a `KIN_*` variable. Drives both validation and the documented
/// contract for what an operator may set.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// Truthy/falsy flag (`1`/`true`/`yes`/`on` vs `0`/`false`/`no`/`off`).
    Bool,
    /// Non-negative integer.
    Usize,
    /// Finite, non-negative float (locate/ranking weights, penalties, floors).
    NonNegF32,
    /// Comma-separated list of non-negative integers.
    UsizeSet,
    /// Non-negative number of seconds (whole or fractional). No special `0`
    /// meaning is claimed — `0` is a real zero-second value at the read site.
    Secs,
    /// Millisecond timeout/latency-budget bound. `0` means **unbounded /
    /// disabled**, parsed through [`env_ms_bound`].
    MsBound,
    /// Fractional-seconds timeout/budget bound. `0` (or any non-positive value)
    /// means **unbounded / disabled**, parsed through [`env_secs_bound_f64`].
    SecsBound,
    /// Free-form string (identifiers, hosts, opaque values).
    Str,
    /// Filesystem path.
    Path,
    /// URL / endpoint.
    Url,
    /// Secret or credential. Presence is reported; the value is never logged.
    Secret,
    /// One of a fixed set of recognized string values. An unrecognized value is
    /// warned (it silently falls back to the default at the read site).
    OneOf(&'static [&'static str]),
}

/// How much a variable can hurt if it is set wrong or drifts from its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Changes retrieval / ranking / output correctness or data safety. An
    /// invalid value is a **hard startup error**; a non-default value is logged
    /// loudly so the override is never silent.
    Correctness,
    /// Changes performance, resources, or lifecycle but not answer correctness.
    /// An invalid value is a loud warning.
    Operational,
    /// Debug, telemetry, or logging only. Safe to set.
    Diagnostic,
    /// Secret / credential. Presence is noted; the value is never printed.
    Secret,
}

impl Sensitivity {
    /// Whether the variable is flagged correctness-relevant (used by callers and
    /// the generated reference).
    pub fn is_correctness_relevant(self) -> bool {
        matches!(self, Sensitivity::Correctness)
    }

    fn label(self) -> &'static str {
        match self {
            Sensitivity::Correctness => "correctness",
            Sensitivity::Operational => "operational",
            Sensitivity::Diagnostic => "diagnostic",
            Sensitivity::Secret => "secret",
        }
    }
}

/// A single supported `KIN_*` variable.
#[derive(Debug, Clone, Copy)]
pub struct EnvVarSpec {
    /// Full variable name, e.g. `KIN_RANK_SEMANTIC`.
    pub name: &'static str,
    /// Value kind (parse + validation contract).
    pub kind: Kind,
    /// Human-readable default (empty string means "unset by default").
    pub default: &'static str,
    /// Correctness sensitivity.
    pub sensitivity: Sensitivity,
    /// One-line description.
    pub summary: &'static str,
}

impl EnvVarSpec {
    fn kind_label(&self) -> &'static str {
        match self.kind {
            Kind::Bool => "bool",
            Kind::Usize => "usize",
            Kind::NonNegF32 => "float>=0",
            Kind::UsizeSet => "usize list",
            Kind::Secs => "seconds>=0",
            Kind::MsBound => "ms bound (0=unbounded)",
            Kind::SecsBound => "seconds bound (0=unbounded)",
            Kind::Str => "string",
            Kind::Path => "path",
            Kind::Url => "url",
            Kind::Secret => "secret",
            Kind::OneOf(_) => "enum",
        }
    }
}

/// Hand-curated operational, safety, and correctness variables — everything that
/// is not an auto-extracted locate/ranking tuning knob (those live in
/// [`GENERATED_KNOBS`]). Grouped by area for review.
#[rustfmt::skip]
pub const OPERATIONAL: &[EnvVarSpec] = &[
    // ---- validation control ---------------------------------------------------
    EnvVarSpec { name: "KIN_ENV_VALIDATION", kind: Kind::OneOf(&["off", "warn", "strict"]), default: "warn", sensitivity: Sensitivity::Operational, summary: "startup env validation mode: off, warn (default), or strict" },
    // ---- correctness / retrieval-affecting ------------------------------------
    EnvVarSpec { name: "KIN_INIT_WARM_CACHE", kind: Kind::Bool, default: "true", sensitivity: Sensitivity::Correctness, summary: "reuse a warm init cache; a cross-store warm cache can depress F1, so an override is loud" },
    EnvVarSpec { name: "KIN_SEMLOC_RERANK", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "enable semantic-locate reranking of daemon locate results" },
    EnvVarSpec { name: "KIN_SEARCH_MODE", kind: Kind::OneOf(&["precise"]), default: "", sensitivity: Sensitivity::Correctness, summary: "search strictness; 'precise' rejects broad show-body searches" },
    EnvVarSpec { name: "KIN_DISABLE_SPINE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "disable the spine federation layer, narrowing retrieval scope" },
    EnvVarSpec { name: "KIN_LOCATE_PROFILE", kind: Kind::OneOf(&["minimal", "standard", "performance"]), default: "", sensitivity: Sensitivity::Correctness, summary: "locate capability profile; unset auto-detects from cores/RAM" },
    EnvVarSpec { name: "KIN_LOCATE_SYMBOL_CAP", kind: Kind::Usize, default: "25", sensitivity: Sensitivity::Correctness, summary: "cap on symbols surfaced per locate result" },
    EnvVarSpec { name: "KIN_LOCATE_CROSS_ENCODER_MODEL", kind: Kind::Str, default: "", sensitivity: Sensitivity::Correctness, summary: "override the cross-encoder rerank model id" },
    EnvVarSpec { name: "KIN_LOCATE_CROSS_ENCODER_REVISION", kind: Kind::Str, default: "", sensitivity: Sensitivity::Correctness, summary: "override the cross-encoder rerank model revision" },
    EnvVarSpec { name: "KIN_REQUIRE_COMPLETE_EMBEDDINGS", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "require full embedding coverage before answering locate/search" },
    EnvVarSpec { name: "KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "bypass the embedding-coverage correctness gate" },
    EnvVarSpec { name: "KIN_STRICT_BUILD_MATCH", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "require a strict historical build match when resolving a ref view" },
    EnvVarSpec { name: "KIN_ALLOW_MASS_DELETION", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "permit reconcile to apply mass deletions (data-destructive)" },
    EnvVarSpec { name: "KIN_WRITE_VETO", kind: Kind::OneOf(&["warn", "enforce", "off"]), default: "warn", sensitivity: Sensitivity::Correctness, summary: "write-veto mode: 'warn' (default) annotates would-be vetoes into foreign-held scopes, 'enforce' rejects them with a 409, 'off' disables" },
    EnvVarSpec { name: "KIN_DAEMON_LOCATE_ONLY", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "daemon serves locate-only from a snapshot, changing what it answers" },
    EnvVarSpec { name: "KIN_DAEMON_DISABLE_LSP", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "disable LSP enrichment in the daemon, reducing relation coverage" },
    EnvVarSpec { name: "KIN_COCHANGE_MAX_FAN_OUT", kind: Kind::Usize, default: "15", sensitivity: Sensitivity::Correctness, summary: "cap on co-change fan-out per entity (co-change ranking signal)" },
    EnvVarSpec { name: "KIN_COCHANGE_MAX_FILES_PER_COMMIT", kind: Kind::Usize, default: "20", sensitivity: Sensitivity::Correctness, summary: "cap on files per commit considered for the co-change signal" },

    // ---- locate timeout / budget bounds (0 = unbounded, never instant) --------
    // These route through the shared zero-safe bound helpers, so `0` disables the
    // bound rather than firing an instant zero-length timeout that guts retrieval.
    EnvVarSpec { name: "KIN_LOCATE_MULTIHOP_TIMEOUT_MS", kind: Kind::MsBound, default: "profile-dependent (200/500/1000 ms)", sensitivity: Sensitivity::Correctness, summary: "multihop BFS timeout; 0 disables the bound (still capped by depth/frontier)" },
    EnvVarSpec { name: "KIN_LOCATE_RERANK_LATENCY_BUDGET_MS", kind: Kind::MsBound, default: "profile-dependent (1500 ms accuracy / 0 compat)", sensitivity: Sensitivity::Correctness, summary: "cross-encoder rerank latency budget; 0 disables the latency gate" },

    // ---- retrieval quality profile and its profile-gated levers ---------------
    // KIN_PROFILE selects the versioned retrieval profile; the levers below
    // default per-profile and an explicit value always wins over the profile.
    EnvVarSpec { name: "KIN_PROFILE", kind: Kind::Str, default: "compat-v0", sensitivity: Sensitivity::Correctness, summary: "retrieval quality profile: compat-v0 (default, pre-profile behavior) or accuracy-v1 (opt-in candidate pending A/B-tuned graduation); proof runs pin this explicitly" },
    EnvVarSpec { name: "KIN_LOCATE_TOTAL_TIMEOUT_SECS", kind: Kind::SecsBound, default: "90", sensitivity: Sensitivity::Correctness, summary: "total locate pipeline budget in seconds; 0 disables it (unbounded)" },
    EnvVarSpec { name: "KIN_LOCATE_PHASE_ENTITY_DISCOVERY_SECS", kind: Kind::SecsBound, default: "20", sensitivity: Sensitivity::Correctness, summary: "locate phase budget: entity discovery; 0 = unbounded" },
    EnvVarSpec { name: "KIN_LOCATE_PHASE_ENTITY_RESOLUTION_SECS", kind: Kind::SecsBound, default: "20", sensitivity: Sensitivity::Correctness, summary: "locate phase budget: entity resolution; 0 = unbounded" },
    EnvVarSpec { name: "KIN_LOCATE_PHASE_MULTIHOP_SECS", kind: Kind::SecsBound, default: "20", sensitivity: Sensitivity::Correctness, summary: "locate phase budget: multihop; 0 = unbounded" },
    EnvVarSpec { name: "KIN_LOCATE_PHASE_TEXT_SEARCH_SECS", kind: Kind::SecsBound, default: "10", sensitivity: Sensitivity::Correctness, summary: "locate phase budget: text search; 0 = unbounded" },
    EnvVarSpec { name: "KIN_LOCATE_PHASE_SOURCE_TEXT_SECS", kind: Kind::SecsBound, default: "10", sensitivity: Sensitivity::Correctness, summary: "locate phase budget: source text; 0 = unbounded" },
    EnvVarSpec { name: "KIN_LOCATE_PHASE_SCORING_SECS", kind: Kind::SecsBound, default: "10", sensitivity: Sensitivity::Correctness, summary: "locate phase budget: scoring; 0 = unbounded" },

    // ---- secrets --------------------------------------------------------------
    EnvVarSpec { name: "KIN_DAEMON_AUTH_TOKEN", kind: Kind::Secret, default: "", sensitivity: Sensitivity::Secret, summary: "bearer token for authenticated daemon requests" },
    EnvVarSpec { name: "KIN_SUPERVISOR_AUTH_TOKEN", kind: Kind::Secret, default: "", sensitivity: Sensitivity::Secret, summary: "bearer token for authenticated supervisor requests" },
    EnvVarSpec { name: "KIN_REGISTRY_CARGO_TOKEN", kind: Kind::Secret, default: "", sensitivity: Sensitivity::Secret, summary: "cargo registry auth token for publish" },

    // ---- daemon lifecycle / networking ---------------------------------------
    EnvVarSpec { name: "KIN_DAEMON_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "explicit daemon endpoint URL (skip local discovery)" },
    EnvVarSpec { name: "KIN_DAEMON_BIN", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "override path to the kin-daemon binary" },
    EnvVarSpec { name: "KIN_DAEMON_BIND_HOST", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "host/interface the daemon binds its HTTP endpoint to" },
    EnvVarSpec { name: "KIN_DAEMON_REQUIRE_TOKEN", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "require a bearer token for all daemon requests" },
    EnvVarSpec { name: "KIN_DAEMON_ALLOW_EXEC", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "permit the daemon to run exec commands" },
    EnvVarSpec { name: "KIN_DAEMON_WATCH_PID", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "pid the daemon watches; it exits when that process dies" },
    EnvVarSpec { name: "KIN_DAEMON_EMBED_BATCH_SIZE", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "embedding batch size for daemon-side embed passes" },
    EnvVarSpec { name: "KIN_DAEMON_BOOTSTRAP_EXPORT_CONCURRENCY", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "concurrency for the daemon bootstrap export" },
    EnvVarSpec { name: "KIN_DAEMON_IDLE_TIMEOUT_SECS", kind: Kind::Secs, default: "3600", sensitivity: Sensitivity::Operational, summary: "auto-shutdown after this idle period; 0 disables idle shutdown" },
    EnvVarSpec { name: "KIN_DAEMON_READY_TIMEOUT_SECS", kind: Kind::Secs, default: "300", sensitivity: Sensitivity::Operational, summary: "how long to wait for a starting daemon to become ready" },
    EnvVarSpec { name: "KIN_DAEMON_EXISTING_READY_TIMEOUT_SECS", kind: Kind::Secs, default: "3", sensitivity: Sensitivity::Operational, summary: "readiness wait for an already-running daemon" },
    EnvVarSpec { name: "KIN_DAEMON_STARTUP_LOCK_TIMEOUT_SECS", kind: Kind::Secs, default: "", sensitivity: Sensitivity::Operational, summary: "how long to wait for the daemon startup lock" },
    EnvVarSpec { name: "KIN_DAEMON_BOOTSTRAP_TIMEOUT_SECS", kind: Kind::Secs, default: "", sensitivity: Sensitivity::Operational, summary: "timeout for daemon bootstrap-as-admin" },
    EnvVarSpec { name: "KIN_DAEMON_SCOPE_BUILD_TIMEOUT_SECS", kind: Kind::Secs, default: "", sensitivity: Sensitivity::Operational, summary: "timeout for a daemon-side scope graph build" },
    EnvVarSpec { name: "KIN_DAEMON_IDLE_FLUSH_SECS", kind: Kind::Secs, default: "2", sensitivity: Sensitivity::Operational, summary: "idle debounce before a full-graph persistence flush" },
    EnvVarSpec { name: "KIN_DAEMON_PERIODIC_FLUSH_SECS", kind: Kind::Secs, default: "30", sensitivity: Sensitivity::Operational, summary: "maximum interval before dirty graph state is flushed" },
    EnvVarSpec { name: "KIN_DAEMON_SHUTDOWN_GRACE_SECS", kind: Kind::Secs, default: "25", sensitivity: Sensitivity::Operational, summary: "grace before the shutdown watchdog force-exits; 0 escalates immediately" },
    EnvVarSpec { name: "KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS", kind: Kind::Secs, default: "8", sensitivity: Sensitivity::Operational, summary: "bound on tokio runtime teardown waiting for blocking tasks" },
    EnvVarSpec { name: "KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "allow the CLI to bootstrap an admin-scoped daemon" },
    EnvVarSpec { name: "KIN_STRICT_BEHAVIOR_ENV", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "escalate a CLI/daemon behavior-env divergence from a warning to a hard error" },

    // ---- supervisor -----------------------------------------------------------
    EnvVarSpec { name: "KIN_SUPERVISOR_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "explicit supervisor endpoint URL" },
    EnvVarSpec { name: "KIN_SUPERVISOR_BIND_HOST", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "host/interface the supervisor binds to" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REQUIRE_TOKEN", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "require a bearer token for supervisor requests" },
    EnvVarSpec { name: "KIN_SUPERVISOR_IDLE_TIMEOUT_SECS", kind: Kind::Secs, default: "3600", sensitivity: Sensitivity::Operational, summary: "supervisor auto-shutdown idle period; 0 disables idle shutdown" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REAP_CPU", kind: Kind::Bool, default: "true", sensitivity: Sensitivity::Operational, summary: "enable the CPU-heuristic zombie reaper; set falsey to disable" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REAP_CPU_PERCENT", kind: Kind::NonNegF32, default: "", sensitivity: Sensitivity::Operational, summary: "CPU percent threshold for the reaper heuristic" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REAP_CPU_SWEEPS", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "consecutive sweeps over threshold before reaping" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REAP_DISABLE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "disable the supervisor reaper entirely" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REAP_DUPLICATE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "reap duplicate daemon instances" },
    EnvVarSpec { name: "KIN_SUPERVISOR_ADOPT_DISABLE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "disable supervisor adoption of an existing daemon" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REDEPLOY_DISABLE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "disable supervisor auto-redeploy" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REDEPLOY_GRACE", kind: Kind::Secs, default: "", sensitivity: Sensitivity::Operational, summary: "grace period before a supervisor redeploy" },
    EnvVarSpec { name: "KIN_SUPERVISOR_REEXEC_DISABLE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "disable supervisor self-reexec on binary mtime change" },

    // ---- init / embed / registry / storage -----------------------------------
    EnvVarSpec { name: "KIN_INIT_CACHE_DIR", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "directory used for the init warm cache" },
    EnvVarSpec { name: "KIN_INIT_MAX_FILES", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "cap on files ingested during init" },
    EnvVarSpec { name: "KIN_EMBED_MAX_PASSES", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "cap on embedding passes per embed run" },
    EnvVarSpec { name: "KIN_EMBED_PASS_SECONDS", kind: Kind::Secs, default: "", sensitivity: Sensitivity::Operational, summary: "per-pass wall-clock budget for an embed run" },
    EnvVarSpec { name: "KIN_EMBED_HTTP_TIMEOUT_SECS", kind: Kind::Secs, default: "", sensitivity: Sensitivity::Operational, summary: "HTTP timeout for the embedding service client" },
    EnvVarSpec { name: "KIN_RESOURCE_PROFILE", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "resource profile hint for embed batch sizing" },
    EnvVarSpec { name: "KIN_INFER_METAL_PROFILE", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "Metal inference profile selection" },
    EnvVarSpec { name: "KIN_REGISTRY_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "kin registry base URL" },
    EnvVarSpec { name: "KIN_REGISTRY_BASE_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "kin registry base URL (alternate key)" },
    EnvVarSpec { name: "KIN_REGISTRY_NPM_AUTH_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "npm auth URL for the registry" },
    EnvVarSpec { name: "KIN_REGISTRY_PATH", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "local registry path override" },
    EnvVarSpec { name: "KIN_REMOTE_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "native remote endpoint URL" },
    EnvVarSpec { name: "KIN_API_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "hosted API base URL (release/pipeline commands)" },
    EnvVarSpec { name: "KIN_STORAGE", kind: Kind::Str, default: "local", sensitivity: Sensitivity::Operational, summary: "daemon storage backend selector (e.g. local, gcs)" },
    EnvVarSpec { name: "KIN_GCS_BUCKET", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "GCS bucket for remote storage" },
    EnvVarSpec { name: "KIN_GCS_PREFIX", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "GCS key prefix for remote storage" },

    // ---- identity / session / projection -------------------------------------
    EnvVarSpec { name: "KIN_ACTOR", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "actor identity recorded in provenance" },
    EnvVarSpec { name: "KIN_ORG_ID", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "organization id for federation/remote" },
    EnvVarSpec { name: "KIN_REPO_ID", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "active repo id override" },
    EnvVarSpec { name: "KIN_REPO_IDS", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "comma-separated repo ids the daemon should serve" },
    EnvVarSpec { name: "KIN_PRIMARY_REPO_ID", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "primary repo id for a multi-repo daemon" },
    EnvVarSpec { name: "KIN_SESSION", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "session id propagated to a child shell/exec" },
    EnvVarSpec { name: "KIN_SESSION_ID", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "session id used by daemon-delegated commands" },
    EnvVarSpec { name: "KIN_SESSION_DIR", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "session workspace root propagated to a child shell" },
    EnvVarSpec { name: "KIN_SOURCE_ROOT", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "projection source root for the current workspace" },
    EnvVarSpec { name: "KIN_WORKSPACE_ROOT", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "workspace root override for orchestration commands" },
    EnvVarSpec { name: "KIN_ORIGINAL_PATH", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "caller's original PATH preserved across a with/exec shim" },
    EnvVarSpec { name: "KIN_PLUGIN_DIR", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "plugin directory override" },
    EnvVarSpec { name: "KIN_CONTENT_MODE", kind: Kind::OneOf(&["deny"]), default: "", sensitivity: Sensitivity::Operational, summary: "content projection mode; 'deny' restricts native content" },
    EnvVarSpec { name: "KIN_DISCOVERY_MODE", kind: Kind::OneOf(&["deny"]), default: "", sensitivity: Sensitivity::Operational, summary: "filesystem discovery mode; 'deny' forces graph-only discovery" },
    EnvVarSpec { name: "KIN_CLAUDE_DISALLOWED_TOOLS", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "comma-separated tool names disallowed in a with-session" },
    EnvVarSpec { name: "KIN_NO_KEYRING", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "skip the OS keyring for credential storage" },
    EnvVarSpec { name: "KIN_NO_DAEMON", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "force in-process execution instead of the daemon" },
    EnvVarSpec { name: "KIN_ALLOW_OFFLINE_RESTORE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "allow restoring a backup without remote verification" },
    EnvVarSpec { name: "KIN_ALLOW_PARENT_STORE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "allow discovering a store in a parent directory" },
    EnvVarSpec { name: "KIN_BINARY_PATH", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "override the kin binary path for bench dispatch" },
    EnvVarSpec { name: "KIN_BUILD_GRAPH_TIMEOUT_SECS", kind: Kind::Secs, default: "60", sensitivity: Sensitivity::Operational, summary: "timeout for building a historical ref-view graph" },
    EnvVarSpec { name: "KIN_MCP_TOOL_PROFILE", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "MCP tool exposure profile" },

    // ---- diagnostics / benchmarking ------------------------------------------
    EnvVarSpec { name: "KIN_LOCATE_DEBUG", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "emit locate pipeline debug output" },
    EnvVarSpec { name: "KIN_LOCATE_TELEMETRY", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "emit locate telemetry" },
    EnvVarSpec { name: "KIN_LOCATE_PIPELINE_REPORT", kind: Kind::Str, default: "", sensitivity: Sensitivity::Diagnostic, summary: "write a locate pipeline report (path or flag)" },
    EnvVarSpec { name: "KIN_SCOPE_TIMING", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "print scope graph build timing to stderr" },
    EnvVarSpec { name: "KIN_PROFILE_OUT", kind: Kind::Path, default: "", sensitivity: Sensitivity::Diagnostic, summary: "write a command profiling session to this path" },
    EnvVarSpec { name: "KIN_PROFILE_SUMMARY", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "print a profiling summary at command exit" },
    EnvVarSpec { name: "KIN_PROFILE_SAMPLE_MS", kind: Kind::Usize, default: "250", sensitivity: Sensitivity::Diagnostic, summary: "resource sampling interval for the profiler" },
    EnvVarSpec { name: "KIN_PROFILE_DISABLE_RESOURCES", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "disable resource sampling in the profiler" },
    EnvVarSpec { name: "KIN_SHIM_LOG", kind: Kind::Str, default: "", sensitivity: Sensitivity::Diagnostic, summary: "log target for generated projection shims" },
    EnvVarSpec { name: "KIN_BENCHMARK", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "benchmark-mode marker for with-sessions" },
    EnvVarSpec { name: "KIN_CONTEXTBENCH_ALLOW_NONCITABLE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "allow non-citable inputs in the context benchmark" },
    EnvVarSpec { name: "KIN_CONTEXTBENCH_MAX_FILES", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Diagnostic, summary: "cap on files in the context benchmark" },
    EnvVarSpec { name: "KIN_CONTEXTBENCH_TEST_HINTS", kind: Kind::Str, default: "", sensitivity: Sensitivity::Diagnostic, summary: "test-hint injection for the context benchmark" },
    EnvVarSpec { name: "KIN_REGEN_ENV_DOC", kind: Kind::Str, default: "", sensitivity: Sensitivity::Diagnostic, summary: "dev/test tooling: set to regenerate docs/env-vars.md from the registry" },
];

/// The full registry: hand-curated operational/safety/correctness specs plus the
/// auto-extracted locate/ranking tuning knobs.
pub fn registry() -> Vec<EnvVarSpec> {
    let mut all: Vec<EnvVarSpec> = Vec::with_capacity(OPERATIONAL.len() + GENERATED_KNOBS.len());
    all.extend_from_slice(OPERATIONAL);
    all.extend_from_slice(GENERATED_KNOBS);
    all
}

/// Look up a spec by exact name.
pub fn spec(name: &str) -> Option<EnvVarSpec> {
    OPERATIONAL
        .iter()
        .chain(GENERATED_KNOBS.iter())
        .find(|s| s.name == name)
        .copied()
}

/// Whether a name is a supported `KIN_*` variable.
pub fn is_known(name: &str) -> bool {
    spec(name).is_some()
}

// ---------------------------------------------------------------------------
// Shared zero-safe parse helpers for bound knobs.
// ---------------------------------------------------------------------------

/// A parsed millisecond bound for a `*_TIMEOUT_MS` / `*_BUDGET_MS` knob.
///
/// The critical contract: an explicit `0` is [`MsBound::Unbounded`] — the bound
/// is *disabled*, never a zero-length timeout that fires instantly. This is the
/// difference between "turn the latency budget off" and "gate every single
/// call", which is exactly the footgun this type removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsBound {
    /// Active bound: fire when elapsed exceeds this many milliseconds.
    Limited(u64),
    /// Disabled bound: never fires (operator set `0`, or the default is off).
    Unbounded,
}

impl MsBound {
    /// As a [`Duration`]; [`MsBound::Unbounded`] maps to [`Duration::MAX`] so an
    /// `elapsed > timeout` comparison never trips.
    pub fn as_duration(self) -> Duration {
        match self {
            MsBound::Limited(ms) => Duration::from_millis(ms),
            MsBound::Unbounded => Duration::MAX,
        }
    }

    /// As milliseconds where `0` conventionally means unbounded (matches budget
    /// checks of the form `budget == 0 || elapsed <= budget`).
    pub fn as_millis_u128(self) -> u128 {
        match self {
            MsBound::Limited(ms) => ms as u128,
            MsBound::Unbounded => 0,
        }
    }

    /// Whether the bound is disabled.
    pub fn is_unbounded(self) -> bool {
        matches!(self, MsBound::Unbounded)
    }
}

/// Pure parser for a millisecond bound. `raw` is the environment value.
///
/// * unset / unparseable → `default`
/// * explicit `0` → [`MsBound::Unbounded`]
/// * `n > 0` → [`MsBound::Limited(n)`]
pub fn parse_ms_bound(raw: Option<&str>, default: MsBound) -> MsBound {
    match raw.map(str::trim) {
        Some(s) => match s.parse::<u64>() {
            Ok(0) => MsBound::Unbounded,
            Ok(n) => MsBound::Limited(n),
            Err(_) => default,
        },
        None => default,
    }
}

/// Read a `*_TIMEOUT_MS` / `*_BUDGET_MS` bound knob from the environment,
/// treating `0` as unbounded. See [`parse_ms_bound`].
pub fn env_ms_bound(name: &str, default: MsBound) -> MsBound {
    parse_ms_bound(std::env::var(name).ok().as_deref(), default)
}

/// Pure parser for a fractional-seconds bound. Returns seconds, where a
/// non-positive explicit value maps to `f64::INFINITY` (unbounded) so an
/// `elapsed > budget` comparison never trips.
///
/// * unset / unparseable / NaN → `default_secs`
/// * `n > 0` → `n`
/// * `n <= 0` (including `0`) → `f64::INFINITY`
pub fn parse_secs_bound_f64(raw: Option<&str>, default_secs: f64) -> f64 {
    match raw.map(str::trim) {
        Some(s) => match s.parse::<f64>() {
            Ok(n) if n.is_nan() => default_secs,
            Ok(n) if n > 0.0 && n.is_finite() => n,
            Ok(_) => f64::INFINITY,
            Err(_) => default_secs,
        },
        None => default_secs,
    }
}

/// Read a fractional-seconds timeout/budget knob from the environment, treating
/// `0` (and any non-positive value) as unbounded. See [`parse_secs_bound_f64`].
pub fn env_secs_bound_f64(name: &str, default_secs: f64) -> f64 {
    parse_secs_bound_f64(std::env::var(name).ok().as_deref(), default_secs)
}

// ---------------------------------------------------------------------------
// Validation.
// ---------------------------------------------------------------------------

const BOOL_TRUE: &[&str] = &["1", "true", "yes", "on"];
const BOOL_FALSE: &[&str] = &["0", "false", "no", "off"];

fn is_bool_token(v: &str) -> bool {
    let l = v.trim().to_ascii_lowercase();
    BOOL_TRUE.contains(&l.as_str()) || BOOL_FALSE.contains(&l.as_str())
}

/// Validate a value string against a spec. `Ok(())` means valid; `Err(reason)`
/// describes why it is not (the caller decides error-vs-warn by sensitivity).
pub fn validate_value(spec: &EnvVarSpec, raw: &str) -> Result<(), String> {
    let v = raw.trim();
    match spec.kind {
        Kind::Bool => {
            if is_bool_token(v) {
                Ok(())
            } else {
                Err(format!(
                    "expected a boolean (1/true/yes/on or 0/false/no/off), got {raw:?}"
                ))
            }
        }
        Kind::Usize => v
            .parse::<u64>()
            .map(|_| ())
            .map_err(|_| format!("expected a non-negative integer, got {raw:?}")),
        Kind::NonNegF32 => match v.parse::<f32>() {
            Ok(n) if n.is_finite() && n >= 0.0 => Ok(()),
            _ => Err(format!("expected a finite float >= 0, got {raw:?}")),
        },
        Kind::UsizeSet => {
            let all_ok = v
                .split(',')
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .all(|f| f.parse::<u64>().is_ok());
            if all_ok && v.chars().any(|c| c.is_ascii_digit()) {
                Ok(())
            } else {
                Err(format!(
                    "expected a comma-separated list of integers, got {raw:?}"
                ))
            }
        }
        Kind::Secs => match v.parse::<f64>() {
            Ok(n) if n.is_finite() && n >= 0.0 => Ok(()),
            _ => Err(format!(
                "expected a non-negative number of seconds, got {raw:?}"
            )),
        },
        Kind::MsBound => v.parse::<u64>().map(|_| ()).map_err(|_| {
            format!("expected non-negative milliseconds (0 = unbounded), got {raw:?}")
        }),
        Kind::SecsBound => match v.parse::<f64>() {
            Ok(n) if n.is_finite() => Ok(()),
            _ => Err(format!(
                "expected a finite number of seconds (0 = unbounded), got {raw:?}"
            )),
        },
        Kind::OneOf(opts) => {
            if opts.iter().any(|o| o.eq_ignore_ascii_case(v)) {
                Ok(())
            } else {
                Err(format!("expected one of {opts:?}, got {raw:?}"))
            }
        }
        // Free-form values are always structurally valid.
        Kind::Str | Kind::Path | Kind::Url | Kind::Secret => Ok(()),
    }
}

/// Whether `raw` differs from the spec's documented default. Numeric kinds are
/// compared by value so `1` and `1.0` do not read as drift. An empty documented
/// default means "unset by default", so any present value is non-default.
fn is_non_default(spec: &EnvVarSpec, raw: &str) -> bool {
    let v = raw.trim();
    if spec.default.is_empty() {
        return !v.is_empty();
    }
    match spec.kind {
        Kind::Bool => {
            let norm = |s: &str| BOOL_TRUE.contains(&s.trim().to_ascii_lowercase().as_str());
            norm(v) != norm(spec.default)
        }
        Kind::Usize | Kind::MsBound => match (v.parse::<u64>(), spec.default.parse::<u64>()) {
            (Ok(a), Ok(b)) => a != b,
            _ => v != spec.default,
        },
        Kind::NonNegF32 | Kind::Secs | Kind::SecsBound => {
            match (v.parse::<f64>(), spec.default.parse::<f64>()) {
                (Ok(a), Ok(b)) => (a - b).abs() > f64::EPSILON,
                _ => v != spec.default,
            }
        }
        Kind::OneOf(_) => !v.eq_ignore_ascii_case(spec.default),
        _ => v != spec.default,
    }
}

/// Severity of an audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warn,
    Info,
}

/// A single audit finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub var: String,
    pub severity: Severity,
    pub message: String,
}

/// Result of auditing an environment.
#[derive(Debug, Default, Clone)]
pub struct AuditReport {
    /// Unknown `KIN_*` names (not in the registry).
    pub unknown: Vec<String>,
    /// Invalid values (parse/range failures).
    pub invalid: Vec<Finding>,
    /// Valid but non-default correctness-relevant overrides (behavior drift).
    pub non_default: Vec<Finding>,
}

impl AuditReport {
    /// Whether the audit found a condition that should hard-fail startup:
    /// an invalid value on a correctness-relevant var (or, when `strict`, any
    /// invalid value or any unknown name).
    pub fn has_hard_errors(&self) -> bool {
        self.invalid.iter().any(|f| f.severity == Severity::Error)
    }
}

/// `KIN_*` prefixes owned by sibling ecosystem components (e.g. kin-vfs sets
/// `KIN_VFS_*` on processes running inside a projection). They legitimately
/// appear in the kin binary's environment but are not part of its own surface,
/// so they are neither validated nor flagged as unknown — otherwise every kin
/// invocation inside a kin-vfs projection would emit a spurious typo warning.
const EXTERNAL_PREFIXES: &[&str] = &["KIN_VFS_"];

/// Audit an environment (any iterator of name/value pairs). Pure: it never reads
/// or mutates the process environment, so it is deterministic and testable.
///
/// `strict` upgrades unknown names and every invalid value to hard errors.
pub fn audit_env<I>(vars: I, strict: bool) -> AuditReport
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut report = AuditReport::default();
    for (name, value) in vars {
        if !name.starts_with("KIN_") {
            continue;
        }
        if name == "KIN_ENV_VALIDATION" {
            continue; // the control var validates itself in enforce_startup_env
        }
        if EXTERNAL_PREFIXES.iter().any(|p| name.starts_with(p)) {
            continue; // owned by a sibling component (e.g. kin-vfs); not our surface
        }
        match spec(&name) {
            None => report.unknown.push(name),
            Some(s) => {
                // An empty value behaves like "unset" at every read site (the
                // parse helpers fall back to the default on empty/unparseable
                // input), so it is never treated as an invalid override here.
                if value.trim().is_empty() {
                    continue;
                }
                match validate_value(&s, &value) {
                    Err(reason) => {
                        // OneOf mismatches are always a warning (an unrecognized
                        // enum value falls back to the default at the read site)
                        // rather than a hard stop, unless strict mode is requested.
                        let is_enum = matches!(s.kind, Kind::OneOf(_));
                        let hard =
                            strict || (s.sensitivity == Sensitivity::Correctness && !is_enum);
                        report.invalid.push(Finding {
                            var: name.clone(),
                            severity: if hard {
                                Severity::Error
                            } else {
                                Severity::Warn
                            },
                            message: reason,
                        });
                    }
                    Ok(()) => {
                        if s.sensitivity == Sensitivity::Correctness && is_non_default(&s, &value) {
                            let shown = if matches!(s.kind, Kind::Secret) {
                                "<redacted>".to_string()
                            } else {
                                value.clone()
                            };
                            report.non_default.push(Finding {
                                var: name.clone(),
                                severity: Severity::Info,
                                message: format!(
                                    "set to non-default value {shown:?} (default {:?}); {}",
                                    s.default, s.summary
                                ),
                            });
                        }
                    }
                }
            }
        }
    }
    report.unknown.sort();
    report.invalid.sort_by(|a, b| a.var.cmp(&b.var));
    report.non_default.sort_by(|a, b| a.var.cmp(&b.var));
    report
}

/// Startup validation mode, resolved from `KIN_ENV_VALIDATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    Off,
    Warn,
    Strict,
}

/// Resolve the validation mode from a raw value (unset → `Warn`).
pub fn resolve_mode(raw: Option<&str>) -> ValidationMode {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("off") | Some("0") | Some("false") => ValidationMode::Off,
        Some("strict") => ValidationMode::Strict,
        _ => ValidationMode::Warn,
    }
}

/// Validate the live process environment at startup and emit findings through
/// `tracing`. Returns `Err(message)` when startup should abort (a correctness
/// variable holds an invalid value, or `strict` mode found any problem). The
/// caller is expected to print the message and exit non-zero.
///
/// Controlled by `KIN_ENV_VALIDATION`: `off` skips entirely, `warn` (default)
/// warns and only hard-fails on invalid correctness values, `strict` hard-fails
/// on any unknown name or invalid value.
pub fn enforce_startup_env() -> Result<(), String> {
    let mode = resolve_mode(std::env::var("KIN_ENV_VALIDATION").ok().as_deref());
    if mode == ValidationMode::Off {
        return Ok(());
    }
    let strict = mode == ValidationMode::Strict;
    let report = audit_env(std::env::vars(), strict);

    if !report.unknown.is_empty() {
        if strict {
            return Err(format!(
                "unrecognized KIN_* environment variable(s) (strict mode): {}. \
                 Check for typos or remove them; see docs/env-vars.md.",
                report.unknown.join(", ")
            ));
        }
        tracing::warn!(
            unknown = %report.unknown.join(", "),
            "unrecognized KIN_* environment variable(s); possible typo — these have no effect (see docs/env-vars.md)"
        );
    }

    for f in &report.invalid {
        match f.severity {
            Severity::Error => {}
            _ => tracing::warn!(var = %f.var, "invalid value for {}: {}", f.var, f.message),
        }
    }

    // Loud, non-silent behavior drift: one line each for a handful, else a
    // single summary so a fully-tuned run does not spam the log.
    if !report.non_default.is_empty() {
        if report.non_default.len() <= 12 {
            for f in &report.non_default {
                tracing::warn!(var = %f.var, "correctness-relevant override active: {} {}", f.var, f.message);
            }
        } else {
            let names: Vec<&str> = report.non_default.iter().map(|f| f.var.as_str()).collect();
            tracing::warn!(
                count = report.non_default.len(),
                vars = %names.join(", "),
                "{} correctness-relevant KIN_* overrides active (behavior differs from defaults)",
                report.non_default.len()
            );
        }
    }

    let hard: Vec<&Finding> = report
        .invalid
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .collect();
    if !hard.is_empty() {
        let detail = hard
            .iter()
            .map(|f| format!("{}: {}", f.var, f.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "invalid KIN_* environment value(s): {detail}. \
             Fix the value(s) or unset the variable(s); see docs/env-vars.md."
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reference documentation, rendered from the registry.
// ---------------------------------------------------------------------------

fn doc_group(name: &str) -> &'static str {
    // Order matters: first match wins, most specific first.
    const GROUPS: &[(&str, &str)] = &[
        ("KIN_ENV_VALIDATION", "Validation control"),
        ("KIN_LOCATE_", "Locate pipeline tuning"),
        ("KIN_RANK_", "Ranking weights"),
        ("KIN_SEMLOC_", "Semantic-locate tuning"),
        ("KIN_COCHANGE_", "Co-change signal"),
        ("KIN_SUPERVISOR_", "Supervisor"),
        ("KIN_DAEMON_", "Daemon"),
        ("KIN_REGISTRY_", "Registry"),
        ("KIN_EMBED_", "Embedding"),
        ("KIN_INFER_", "Inference"),
        ("KIN_INIT_", "Init"),
        ("KIN_GCS_", "Storage"),
        ("KIN_CONTEXTBENCH_", "Benchmarking"),
        ("KIN_PROFILE_", "Diagnostics"),
        ("KIN_SESSION", "Session & projection"),
        ("KIN_SOURCE_ROOT", "Session & projection"),
        ("KIN_DISCOVERY_MODE", "Session & projection"),
        ("KIN_CONTENT_MODE", "Session & projection"),
        ("KIN_SHIM_LOG", "Session & projection"),
    ];
    for (prefix, group) in GROUPS {
        if name.starts_with(prefix) {
            return group;
        }
    }
    "General"
}

/// Render the full reference doc as Markdown, directly from the registry. This
/// is the single source of truth for `docs/env-vars.md`; the drift test asserts
/// they match.
pub fn render_reference_markdown() -> String {
    let mut specs = registry();
    // Deterministic: by group order, then name.
    const GROUP_ORDER: &[&str] = &[
        "Validation control",
        "General",
        "Daemon",
        "Supervisor",
        "Registry",
        "Embedding",
        "Inference",
        "Init",
        "Storage",
        "Session & projection",
        "Co-change signal",
        "Ranking weights",
        "Semantic-locate tuning",
        "Locate pipeline tuning",
        "Diagnostics",
        "Benchmarking",
    ];
    let order_of = |g: &str| {
        GROUP_ORDER
            .iter()
            .position(|x| *x == g)
            .unwrap_or(usize::MAX)
    };
    specs.sort_by(|a, b| {
        order_of(doc_group(a.name))
            .cmp(&order_of(doc_group(b.name)))
            .then_with(|| a.name.cmp(b.name))
    });

    let total = specs.len();
    let correctness = specs
        .iter()
        .filter(|s| s.sensitivity.is_correctness_relevant())
        .count();

    let mut out = String::new();
    out.push_str("<!-- @generated by kin_core::env_registry::render_reference_markdown -->\n");
    out.push_str("<!-- Do not edit by hand. Regenerate with: KIN_REGEN_ENV_DOC=1 cargo test -p kin-core env_doc_matches_registry -->\n\n");
    out.push_str("# Kin environment variables\n\n");
    out.push_str(&format!(
        "This is the authoritative list of supported `KIN_*` environment variables \
         ({total} total, {correctness} correctness-relevant), generated from the \
         central registry in `kin-core`.\n\n"
    ));
    out.push_str(
        "At CLI and daemon startup Kin validates this surface (`KIN_ENV_VALIDATION`, \
         default `warn`):\n\n",
    );
    out.push_str("- an unrecognized `KIN_*` name is warned (a likely typo — it has no effect);\n");
    out.push_str("- an invalid value is a hard startup error for a **correctness** variable, otherwise a warning;\n");
    out.push_str("- a correctness variable set away from its default is logged, so behavior drift is never silent.\n\n");
    out.push_str(
        "Variables owned by sibling components (e.g. `KIN_VFS_*` from kin-vfs) are \
         recognized as external and left alone.\n\n",
    );
    out.push_str(
        "**Zero-bound rule.** For a `*_TIMEOUT_MS`, `*_BUDGET_MS`, or bounded `*_TIMEOUT_SECS` \
         knob, `0` means **disabled / unbounded** — the bound never fires. It is never an \
         instant zero-length timeout.\n\n",
    );
    out.push_str(
        "Sensitivity legend: **correctness** (affects retrieval/ranking/output or data \
         safety), **operational** (perf/resources/lifecycle), **diagnostic** (debug/telemetry), \
         **secret** (credential; value never logged).\n\n",
    );

    let mut current = "";
    for s in &specs {
        let g = doc_group(s.name);
        if g != current {
            out.push_str(&format!("\n## {g}\n\n"));
            out.push_str("| Variable | Kind | Default | Sensitivity | Description |\n");
            out.push_str("| --- | --- | --- | --- | --- |\n");
            current = g;
        }
        let default = if s.default.is_empty() {
            "*(unset)*"
        } else {
            s.default
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            s.name,
            s.kind_label(),
            default,
            s.sensitivity.label(),
            s.summary,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_well_formed() {
        let all = registry();
        assert!(
            all.len() > 300,
            "expected the full surface, got {}",
            all.len()
        );
        let mut seen = std::collections::HashSet::new();
        for s in &all {
            assert!(
                s.name.starts_with("KIN_"),
                "{} must start with KIN_",
                s.name
            );
            assert!(
                seen.insert(s.name),
                "duplicate registry entry for {}",
                s.name
            );
            assert!(!s.summary.is_empty(), "{} needs a summary", s.name);
        }
    }

    #[test]
    fn generated_and_operational_are_disjoint() {
        let op: std::collections::HashSet<&str> = OPERATIONAL.iter().map(|s| s.name).collect();
        for s in GENERATED_KNOBS {
            assert!(
                !op.contains(s.name),
                "{} is in both operational and generated tables",
                s.name
            );
        }
    }

    #[test]
    fn known_hazard_vars_are_present_and_correctness_relevant() {
        for name in [
            "KIN_INIT_WARM_CACHE",
            "KIN_LOCATE_MULTIHOP_TIMEOUT_MS",
            "KIN_LOCATE_RERANK_LATENCY_BUDGET_MS",
            "KIN_LOCATE_TOTAL_TIMEOUT_SECS",
            "KIN_RANK_SEMANTIC",
        ] {
            let s = spec(name).unwrap_or_else(|| panic!("{name} must be registered"));
            assert!(
                s.sensitivity.is_correctness_relevant(),
                "{name} must be correctness-relevant"
            );
        }
    }

    #[test]
    fn bound_knobs_have_bound_kinds() {
        assert!(matches!(
            spec("KIN_LOCATE_MULTIHOP_TIMEOUT_MS").unwrap().kind,
            Kind::MsBound
        ));
        assert!(matches!(
            spec("KIN_LOCATE_RERANK_LATENCY_BUDGET_MS").unwrap().kind,
            Kind::MsBound
        ));
        assert!(matches!(
            spec("KIN_LOCATE_TOTAL_TIMEOUT_SECS").unwrap().kind,
            Kind::SecsBound
        ));
        assert!(matches!(
            spec("KIN_LOCATE_PHASE_MULTIHOP_SECS").unwrap().kind,
            Kind::SecsBound
        ));
    }

    #[test]
    fn unknown_var_is_flagged() {
        let report = audit_env(
            [(
                "KIN_LOCATE_WEIGHT_EMBEDDINGZ".to_string(),
                "1.0".to_string(),
            )],
            false,
        );
        assert_eq!(
            report.unknown,
            vec!["KIN_LOCATE_WEIGHT_EMBEDDINGZ".to_string()]
        );
    }

    #[test]
    fn external_sibling_prefixes_are_not_flagged() {
        // KIN_VFS_* is owned by kin-vfs; running kin inside a projection must not
        // spew "unknown variable" warnings for it.
        let report = audit_env(
            [
                ("KIN_VFS_SOCK".to_string(), "/tmp/kin.sock".to_string()),
                ("KIN_VFS_WORKSPACE".to_string(), "/repo".to_string()),
            ],
            true, // even strict mode leaves sibling-component vars alone
        );
        assert!(report.unknown.is_empty());
        assert!(report.invalid.is_empty());
    }

    #[test]
    fn non_kin_vars_are_ignored() {
        let report = audit_env([("PATH".to_string(), "/bin".to_string())], false);
        assert!(report.unknown.is_empty() && report.invalid.is_empty());
    }

    #[test]
    fn invalid_correctness_value_is_hard_error() {
        let report = audit_env(
            [("KIN_RANK_SEMANTIC".to_string(), "not-a-float".to_string())],
            false,
        );
        assert!(
            report.has_hard_errors(),
            "correctness parse failure must hard-error"
        );
        assert_eq!(report.invalid[0].severity, Severity::Error);
    }

    #[test]
    fn invalid_operational_value_is_warning_only() {
        let report = audit_env(
            [(
                "KIN_DAEMON_READY_TIMEOUT_SECS".to_string(),
                "soon".to_string(),
            )],
            false,
        );
        assert!(!report.has_hard_errors());
        assert_eq!(report.invalid[0].severity, Severity::Warn);
    }

    #[test]
    fn negative_weight_is_rejected() {
        let report = audit_env(
            [("KIN_RANK_SEMANTIC".to_string(), "-0.5".to_string())],
            false,
        );
        assert!(report.has_hard_errors());
    }

    #[test]
    fn enum_typo_warns_not_errors() {
        // OneOf mismatch on a correctness var is a loud warning, not a hard stop.
        let report = audit_env(
            [("KIN_SEARCH_MODE".to_string(), "percise".to_string())],
            false,
        );
        assert!(!report.has_hard_errors());
        assert_eq!(report.invalid.len(), 1);
        assert_eq!(report.invalid[0].severity, Severity::Warn);
        // ...but strict mode escalates it.
        let strict = audit_env(
            [("KIN_SEARCH_MODE".to_string(), "percise".to_string())],
            true,
        );
        assert!(strict.has_hard_errors());
    }

    #[test]
    fn strict_mode_escalates_unknown() {
        let report = audit_env([("KIN_MADE_UP".to_string(), "x".to_string())], true);
        // Unknown is surfaced; enforce_startup_env turns it into an error in strict.
        assert_eq!(report.unknown, vec!["KIN_MADE_UP".to_string()]);
    }

    #[test]
    fn empty_value_is_treated_as_unset() {
        // KIN_RANK_SEMANTIC="" must not hard-error (empty == unset at read sites).
        let report = audit_env([("KIN_RANK_SEMANTIC".to_string(), "".to_string())], false);
        assert!(!report.has_hard_errors());
        assert!(report.invalid.is_empty());
        assert!(report.non_default.is_empty());
        // ...but an empty *unknown* name is still surfaced as a likely typo.
        let unknown = audit_env([("KIN_TYPOED_KNOB".to_string(), "".to_string())], false);
        assert_eq!(unknown.unknown, vec!["KIN_TYPOED_KNOB".to_string()]);
    }

    #[test]
    fn non_default_correctness_is_recorded() {
        let report = audit_env(
            [("KIN_RANK_SEMANTIC".to_string(), "0.5".to_string())],
            false,
        );
        assert_eq!(report.non_default.len(), 1);
        assert_eq!(report.non_default[0].var, "KIN_RANK_SEMANTIC");
    }

    #[test]
    fn default_value_is_not_flagged_non_default() {
        // 0.28 is the documented default; "0.280" is numerically equal.
        let report = audit_env(
            [("KIN_RANK_SEMANTIC".to_string(), "0.280".to_string())],
            false,
        );
        assert!(
            report.non_default.is_empty(),
            "numeric-equal default must not read as drift"
        );
    }

    #[test]
    fn secret_value_is_never_echoed() {
        // Secrets are operational-for-validation; presence must not echo the value.
        let report = audit_env(
            [("KIN_DAEMON_AUTH_TOKEN".to_string(), "s3cr3t".to_string())],
            false,
        );
        assert!(report.invalid.is_empty());
        assert!(
            report
                .non_default
                .iter()
                .all(|f| !f.message.contains("s3cr3t")),
            "secret value must never appear in a finding"
        );
    }

    // ---- zero-semantics helpers -------------------------------------------

    #[test]
    fn ms_bound_zero_is_unbounded_not_instant() {
        assert_eq!(
            parse_ms_bound(Some("0"), MsBound::Limited(500)),
            MsBound::Unbounded
        );
        assert_eq!(
            parse_ms_bound(Some("0"), MsBound::Limited(500)).as_duration(),
            Duration::MAX
        );
        assert_eq!(
            parse_ms_bound(Some("0"), MsBound::Limited(500)).as_millis_u128(),
            0
        );
    }

    #[test]
    fn ms_bound_positive_is_limited() {
        assert_eq!(
            parse_ms_bound(Some("250"), MsBound::Unbounded),
            MsBound::Limited(250)
        );
        assert_eq!(
            parse_ms_bound(Some(" 250 "), MsBound::Unbounded),
            MsBound::Limited(250)
        );
        assert_eq!(
            parse_ms_bound(Some("250"), MsBound::Unbounded).as_duration(),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn ms_bound_unset_or_garbage_uses_default() {
        assert_eq!(
            parse_ms_bound(None, MsBound::Limited(500)),
            MsBound::Limited(500)
        );
        assert_eq!(
            parse_ms_bound(Some("abc"), MsBound::Limited(500)),
            MsBound::Limited(500)
        );
        assert_eq!(
            parse_ms_bound(Some("-5"), MsBound::Limited(500)),
            MsBound::Limited(500)
        );
    }

    #[test]
    fn secs_bound_zero_is_unbounded() {
        assert_eq!(parse_secs_bound_f64(Some("0"), 90.0), f64::INFINITY);
        assert_eq!(parse_secs_bound_f64(Some("-1"), 90.0), f64::INFINITY);
        // An unbounded budget never trips an `elapsed > budget` gate: any finite
        // elapsed is strictly less than the (infinite) budget.
        let budget = parse_secs_bound_f64(Some("0"), 90.0);
        assert!(budget.is_infinite());
        assert!(1e9_f64 < budget);
    }

    #[test]
    fn secs_bound_positive_and_default() {
        assert_eq!(parse_secs_bound_f64(Some("45.5"), 90.0), 45.5);
        assert_eq!(parse_secs_bound_f64(None, 90.0), 90.0);
        assert_eq!(parse_secs_bound_f64(Some("junk"), 90.0), 90.0);
        assert_eq!(parse_secs_bound_f64(Some("nan"), 90.0), 90.0);
    }

    // ---- documentation drift ----------------------------------------------

    #[test]
    fn env_doc_matches_registry() {
        let rendered = render_reference_markdown();
        let doc_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/env-vars.md");

        if std::env::var_os("KIN_REGEN_ENV_DOC").is_some() {
            std::fs::write(&doc_path, &rendered).expect("write regenerated env doc");
            return;
        }

        let committed = match std::fs::read_to_string(&doc_path) {
            Ok(c) => c,
            Err(_) => {
                // Not available in a packaged/published context; skip rather than
                // fail. In-workspace CI always has the file, so drift is enforced.
                eprintln!("env-vars.md not found at {doc_path:?}; skipping drift check");
                return;
            }
        };
        assert_eq!(
            committed, rendered,
            "docs/env-vars.md is out of sync with the env registry. \
             Regenerate: KIN_REGEN_ENV_DOC=1 cargo test -p kin-core env_doc_matches_registry"
        );
    }
}
