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
    // ---- install / setup root -------------------------------------------------
    EnvVarSpec { name: "KIN_HOME", kind: Kind::Path, default: "~/.kin", sensitivity: Sensitivity::Operational, summary: "preferred root for the managed Kin install used by the launcher, setup, and shell hooks" },
    EnvVarSpec { name: "KIN_DIR", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "compatibility alias for the managed Kin install root; KIN_HOME wins when both are set" },
    EnvVarSpec { name: "KIN_VERSION", kind: Kind::Str, default: "latest", sensitivity: Sensitivity::Operational, summary: "release version selected by the shell and PowerShell installers" },
    EnvVarSpec { name: "KIN_BASE_URL", kind: Kind::Url, default: "GitHub Releases", sensitivity: Sensitivity::Operational, summary: "release mirror base URL used by the shell and PowerShell installers" },
    EnvVarSpec { name: "KIN_NO_SETUP", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "skip the installer's post-install setup wizard when set truthy" },
    EnvVarSpec { name: "KIN_REGISTRY_REPAIR", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "allow the POSIX installer to repair safe registry ownership modes" },
    EnvVarSpec { name: "KIN_MANAGED_BIN", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "explicit native Kin binary used by the @kinlab/kin launcher instead of provisioning" },
    EnvVarSpec { name: "KIN_NO_PROVISION", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "forbid network provisioning by the @kinlab/kin launcher" },
    EnvVarSpec { name: "KIN_LAUNCHER_ADOPT", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "force the @kinlab/kin launcher to provision its pinned release, including an intentional downgrade" },
    // ---- correctness / retrieval-affecting ------------------------------------
    EnvVarSpec { name: "KIN_SEMLOC_RERANK", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "enable semantic-locate reranking of daemon locate results" },
    EnvVarSpec { name: "KIN_SEARCH_MODE", kind: Kind::OneOf(&["precise"]), default: "", sensitivity: Sensitivity::Correctness, summary: "search strictness; 'precise' rejects broad show-body searches" },
    EnvVarSpec { name: "KIN_DISABLE_SPINE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "disable the spine federation layer, narrowing retrieval scope" },
    EnvVarSpec { name: "KIN_LOCATE_PROFILE", kind: Kind::OneOf(&["minimal", "standard", "performance"]), default: "", sensitivity: Sensitivity::Correctness, summary: "locate capability profile; unset auto-detects from cores/RAM" },
    EnvVarSpec { name: "KIN_LOCATE_SYMBOL_CAP", kind: Kind::Usize, default: "25", sensitivity: Sensitivity::Correctness, summary: "cap on symbols surfaced per locate result" },
    EnvVarSpec { name: "KIN_LOCATE_CROSS_ENCODER_MODEL", kind: Kind::Str, default: "", sensitivity: Sensitivity::Correctness, summary: "override the cross-encoder rerank model id" },
    EnvVarSpec { name: "KIN_LOCATE_CROSS_ENCODER_REVISION", kind: Kind::Str, default: "", sensitivity: Sensitivity::Correctness, summary: "override the cross-encoder rerank model revision" },
    EnvVarSpec { name: "KIN_LOCATE_AUTO_QUERY_FANOUT", kind: Kind::Bool, default: "true", sensitivity: Sensitivity::Correctness, summary: "automatic identifier-distilled sharp variant for single-query locate, fused only when the primary ranking is unsure; falsy disables" },
    EnvVarSpec { name: "KIN_REQUIRE_COMPLETE_EMBEDDINGS", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "require full embedding coverage before answering locate/search" },
    EnvVarSpec { name: "KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "bypass the embedding-coverage correctness gate" },
    EnvVarSpec { name: "KIN_STRICT_BUILD_MATCH", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "require a strict historical build match when resolving a ref view" },
    EnvVarSpec { name: "KIN_ALLOW_MASS_DELETION", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "permit reconcile to apply mass deletions (data-destructive)" },
    EnvVarSpec { name: "KIN_DAEMON_DISABLE_FILESYSTEM_RECONCILE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "disable daemon filesystem watching and reconcile/sync ingestion so remote graph authority cannot be overwritten by a checkout" },
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
    EnvVarSpec { name: "KIN_REGISTRY_OCI_WRITE_TOKEN", kind: Kind::Secret, default: "", sensitivity: Sensitivity::Secret, summary: "OCI registry auth token for mutations" },
    EnvVarSpec { name: "KIN_REGISTRY_STARTUP_REPAIR", kind: Kind::Str, default: "1", sensitivity: Sensitivity::Operational, summary: "set 0/false to disable the cargo registry migrate-on-boot repair" },

    // ---- daemon lifecycle / networking ---------------------------------------
    EnvVarSpec { name: "KIN_DAEMON_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "explicit daemon endpoint URL (skip local discovery)" },
    EnvVarSpec { name: "KIN_DAEMON_BIN", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "override path to the kin-daemon binary" },
    EnvVarSpec { name: "KIN_DAEMON_BIND_HOST", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "host/interface the daemon binds its HTTP endpoint to" },
    EnvVarSpec { name: "KIN_DAEMON_STOP_TIMEOUT_SECS", kind: Kind::Secs, default: "30", sensitivity: Sensitivity::Operational, summary: "ceiling in seconds kin daemon stop waits for a signaled daemon to exit" },
    EnvVarSpec { name: "KIN_DAEMON_REQUIRE_TOKEN", kind: Kind::Bool, default: "true", sensitivity: Sensitivity::Operational, summary: "require a bearer token for all daemon requests; set falsy to opt out" },
    EnvVarSpec { name: "KIN_DAEMON_WATCH_PID", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "pid the daemon watches; it exits when that process dies" },
    EnvVarSpec { name: "KIN_DAEMON_EMBED_BATCH_SIZE", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "embedding batch size for daemon-side embed passes" },
    EnvVarSpec { name: "KIN_DAEMON_AUTO_EMBED", kind: Kind::Bool, default: "true", sensitivity: Sensitivity::Operational, summary: "let the daemon start background embedding on its own; set falsy to defer until an explicit embed request" },
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
    EnvVarSpec { name: "KIN_SUPERVISOR_STARTUP_GENERATION", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "internal versioned supervisor launch capability generation" },
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
    EnvVarSpec { name: "KIN_EMBED_MAX_PASSES", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "cap on embedding passes per embed run" },
    EnvVarSpec { name: "KIN_EMBED_PASS_SECONDS", kind: Kind::Secs, default: "", sensitivity: Sensitivity::Operational, summary: "per-pass wall-clock budget for an embed run" },
    EnvVarSpec { name: "KIN_EMBED_MAX_TOTAL_SECONDS", kind: Kind::Secs, default: "600", sensitivity: Sensitivity::Operational, summary: "total wall-clock budget for a single `kin embed` under the interactive/small resource profiles; the run stops at the budget with a resumable partial index; unconstrained profiles ignore it" },
    EnvVarSpec { name: "KIN_EMBED_HTTP_TIMEOUT_SECS", kind: Kind::Secs, default: "", sensitivity: Sensitivity::Operational, summary: "HTTP timeout for the embedding service client" },
    EnvVarSpec { name: "KIN_DAEMON_HTTP_TIMEOUT_SECS", kind: Kind::Secs, default: "300", sensitivity: Sensitivity::Operational, summary: "per-request HTTP timeout for the CLI's daemon client; 0 or invalid falls back to 300, and long-running requests (large-repo review) need a higher value" },
    EnvVarSpec { name: "KIN_RESOURCE_PROFILE", kind: Kind::OneOf(&["proof", "interactive", "throughput", "ci"]), default: "interactive", sensitivity: Sensitivity::Correctness, summary: "runtime resource profile (kin-cli/kin-daemon/kin-infer/kin-db): proof/interactive/throughput/ci; unset, the kin binaries select interactive at startup (value-preserving Metal kernels, proof's embedding budgets), while a library caller that never selects still resolves to proof; throughput additionally scales the batch budgets, may engage CPU/GPU hybrid embedding and overlaps persist with compute, and is non-citable" },
    EnvVarSpec { name: "KIN_INFER_METAL_PROFILE", kind: Kind::Str, default: "", sensitivity: Sensitivity::Operational, summary: "Metal inference profile selection" },
    EnvVarSpec { name: "KIN_REGISTRY_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "kin registry base URL" },
    EnvVarSpec { name: "KIN_REGISTRY_BASE_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "kin registry base URL (alternate key)" },
    EnvVarSpec { name: "KIN_REGISTRY_NPM_AUTH_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "npm auth URL for the registry" },
    EnvVarSpec { name: "KIN_REGISTRY_PATH", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "local registry path override" },
    EnvVarSpec { name: "KIN_REMOTE_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "native remote endpoint URL" },
    EnvVarSpec { name: "KIN_REMOTE_BASE_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "KinLab base URL for remote and federation calls" },
    EnvVarSpec { name: "KIN_REMOTE_BEARER_TOKEN", kind: Kind::Secret, default: "", sensitivity: Sensitivity::Secret, summary: "KinLab bearer token used when no stored auth session is present" },
    EnvVarSpec { name: "KIN_REMOTE_AUTH_TOKEN", kind: Kind::Secret, default: "", sensitivity: Sensitivity::Secret, summary: "fallback KinLab auth token read after KIN_REMOTE_BEARER_TOKEN" },
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
    EnvVarSpec { name: "KIN_CONTENT_MODE", kind: Kind::OneOf(&["deny"]), default: "", sensitivity: Sensitivity::Operational, summary: "content projection mode; 'deny' restricts native content" },
    EnvVarSpec { name: "KIN_DISCOVERY_MODE", kind: Kind::OneOf(&["deny"]), default: "", sensitivity: Sensitivity::Operational, summary: "filesystem discovery mode; 'deny' forces graph-only discovery" },
    EnvVarSpec { name: "KIN_NO_KEYRING", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "skip the OS keyring for credential storage" },
    EnvVarSpec { name: "KIN_NO_DAEMON", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "force in-process execution instead of the daemon" },
    EnvVarSpec { name: "KIN_ALLOW_OFFLINE_RESTORE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "allow restoring a backup without remote verification" },
    EnvVarSpec { name: "KIN_ALLOW_PARENT_STORE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "allow discovering a store in a parent directory" },
    EnvVarSpec { name: "KIN_BINARY_PATH", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "override the kin binary path for bench dispatch" },
    EnvVarSpec { name: "KIN_BUILD_GRAPH_TIMEOUT_SECS", kind: Kind::Secs, default: "60", sensitivity: Sensitivity::Operational, summary: "timeout for building a historical ref-view graph" },
    EnvVarSpec { name: "KIN_MCP_TOOL_PROFILE", kind: Kind::Str, default: "agent-default", sensitivity: Sensitivity::Operational, summary: "MCP tool surface: agent-default (curated, the default), full (every tool), benchmark, context-bench" },
    EnvVarSpec { name: "KIN_MCP_REPO", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "bind `kin mcp start` to this repository instead of the launch directory" },
    EnvVarSpec { name: "KIN_MCP_CACHE_DIR", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "cache directory override for the npm MCP wrapper's managed Kin binary" },
    EnvVarSpec { name: "KIN_MCP_KIN_BINARY", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "explicit native Kin binary used by the @kinlab/kin-mcp wrapper" },
    EnvVarSpec { name: "KIN_MCP_RELEASE_BASE_URL", kind: Kind::Url, default: "GitHub Releases", sensitivity: Sensitivity::Operational, summary: "release mirror base URL used by the @kinlab/kin-mcp wrapper" },
    EnvVarSpec { name: "KIN_MCP_AUTO_INIT", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "allow the @kinlab/kin-mcp wrapper to initialize a missing repository before startup" },

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
    EnvVarSpec { name: "KIN_CONTEXTBENCH_ALLOW_NONCITABLE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "allow non-citable inputs in the context benchmark" },
    EnvVarSpec { name: "KIN_CONTEXTBENCH_MAX_FILES", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Diagnostic, summary: "cap on files in the context benchmark" },
    EnvVarSpec { name: "KIN_CONTEXTBENCH_TEST_HINTS", kind: Kind::Str, default: "", sensitivity: Sensitivity::Diagnostic, summary: "test-hint injection for the context benchmark" },
    EnvVarSpec { name: "KIN_REGEN_ENV_DOC", kind: Kind::Str, default: "", sensitivity: Sensitivity::Diagnostic, summary: "dev/test tooling: set to regenerate docs/env-vars.md from the registry" },
];

/// Behavior levers **read by sibling first-party crates** that are linked into, or
/// projected around, the kin runtime — kin-db (`embed/mod.rs`), kin-infer
/// (`gpu.rs`, `resource.rs`), and the kin-vfs shim. Kin's own binary never calls
/// `env::var` for these names (a sibling does), so they carry into kin's process
/// environment yet cannot be discovered by the workspace-completeness test. Left
/// unregistered, the startup audit would report them as "unrecognized … no effect"
/// even though setting them changes real behavior — the exact false negative this
/// table removes.
///
/// The kind, default, and sensitivity of each entry are lifted from the actual read
/// site, so both the audit and `docs/env-vars.md` stay honest. `Correctness` marks a
/// lever that shifts embedding/inference *output* (model, provider, prefix, compute
/// device, precision, or split); `Operational` marks a perf/cache/lifecycle lever
/// that leaves numerical output identical.
///
/// The kin-db rows are **machine-checked** against the pinned crate by
/// `every_kin_db_env_read_is_registered`, which enumerates the vendored source of the
/// exact version in `Cargo.lock`. The other rows are still hand-maintained: those
/// crates resolve through the private cargo registry the same way, but their levers
/// need the per-variable reachability judgement the kin-db sweep already has, so
/// adding, renaming, or removing one there means updating this table by hand.
#[rustfmt::skip]
pub const DOWNSTREAM: &[EnvVarSpec] = &[
    // ---- kin-infer: compute backend / dispatch --------------------------------
    EnvVarSpec { name: "KIN_INFER_CPU_BACKEND", kind: Kind::OneOf(&["pure-rust", "pure_rust", "accelerate"]), default: "accelerate", sensitivity: Sensitivity::Correctness, summary: "kin-infer CPU matmul backend: 'pure-rust' forces the deterministic pure-Rust GEMM for bit-reproducible runs; 'accelerate' uses Apple Accelerate BLAS (the macOS default). BLAS differs from pure-Rust in the last ULPs" },
    EnvVarSpec { name: "KIN_INFER_OCCUPANCY_DISPATCH", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "kin-infer Metal occupancy-informed pointwise threadgroup sizing; numerically identical to the one-simdgroup baseline (a perf A/B lever), default off" },
    // ---- kin-db: embedding compute path (shifts embedding vectors) ------------
    EnvVarSpec { name: "KIN_EMBED_BACKEND", kind: Kind::OneOf(&["auto", "cpu", "metal", "gpu"]), default: "auto", sensitivity: Sensitivity::Correctness, summary: "kin-db embedding compute backend: auto (default) uses batched Metal, 'cpu' forces the SIMD/pure path, 'metal'/'gpu' forces Metal; cpu vs metal shifts embeddings in the last ULPs" },
    EnvVarSpec { name: "KIN_EMBED_HYBRID", kind: Kind::Str, default: "off", sensitivity: Sensitivity::Correctness, summary: "kin-db hybrid CPU/GPU embedding split: off (default), 'seq'/'floor' for the sequence-length floor, or any other truthy value for the balanced split; engaging the CPU twin computes some vectors off the Metal device" },
    EnvVarSpec { name: "KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN", kind: Kind::Usize, default: "256", sensitivity: Sensitivity::Correctness, summary: "kin-db hybrid CPU lane cutoff: entities tokenized at or below this sequence length embed on the CPU twin, heavier ones on Metal; 0 or invalid falls back to 256" },
    EnvVarSpec { name: "KIN_EMBED_HYBRID_GPU_TPUT_RATIO", kind: Kind::NonNegF32, default: "", sensitivity: Sensitivity::Correctness, summary: "kin-db hybrid split ratio: pins the GPU:CPU throughput ratio for the balanced split; unset (or <= 0) measures it adaptively per batch" },
    // ---- kin-db: embedding cache (perf/lifecycle, identical vectors) ----------
    EnvVarSpec { name: "KIN_EMBED_CACHE", kind: Kind::Bool, default: "true", sensitivity: Sensitivity::Operational, summary: "kin-db on-disk embedding cache; set to 0 to disable and always recompute (only the literal '0' disables), default on" },
    EnvVarSpec { name: "KIN_EMBED_CACHE_BUDGET_GB", kind: Kind::NonNegF32, default: "", sensitivity: Sensitivity::Operational, summary: "kin-db on-disk embedding cache disk budget in GB for `kin cache gc`; unset (default) evicts nothing, so the cache is pruned only by an explicit budget or command" },
    EnvVarSpec { name: "KIN_EMBED_CACHE_DIR", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "kin-db on-disk embedding cache directory; unset uses ~/.kin/cache/embeddings" },
    // ---- kin-db: provider and model selection (changes every vector) ----------
    EnvVarSpec { name: "KIN_EMBED_PROVIDER", kind: Kind::OneOf(&["local", "hf", "huggingface", "bge", "openai", "lmstudio", "lm-studio", "openai-compat", "openai-compatible", "compatible"]), default: "local", sensitivity: Sensitivity::Correctness, summary: "kin-db embedding provider: 'local' (default) embeds in-process, 'openai'/'lmstudio'/'openai-compatible' call an OpenAI-compatible endpoint; an unrecognized value warns and falls back to local" },
    EnvVarSpec { name: "KIN_EMBED_MODEL_ID", kind: Kind::Str, default: "nomic-ai/nomic-embed-text-v1.5", sensitivity: Sensitivity::Correctness, summary: "kin-db local embedding model id (a Hugging Face repo id or a local model directory); also the fallback model for an OpenAI-compatible provider. Changing it changes every vector and can change the dimension" },
    EnvVarSpec { name: "KIN_EMBED_MODEL_REVISION", kind: Kind::Str, default: "main", sensitivity: Sensitivity::Correctness, summary: "kin-db local embedding model revision resolved alongside KIN_EMBED_MODEL_ID; a different revision is a different set of weights" },
    EnvVarSpec { name: "KIN_EMBED_OPENAI_MODEL", kind: Kind::Str, default: "", sensitivity: Sensitivity::Correctness, summary: "kin-db OpenAI-compatible embedding model, taking precedence over KIN_EMBED_MODEL_ID; unset defaults per profile (text-embedding-3-small for openai, text-embedding-nomic-embed-text-v1.5 otherwise)" },
    EnvVarSpec { name: "KIN_EMBED_OPENAI_DIMENSIONS", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Correctness, summary: "kin-db requested output dimension for an OpenAI-compatible provider; must be > 0, and unset uses the model's native dimension" },
    EnvVarSpec { name: "KIN_EMBED_OPENAI_SEND_DIMENSIONS", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "kin-db sends the requested dimension in the OpenAI-compatible request body, changing the vectors the endpoint returns; only 1/true/TRUE/yes/YES enable it at the read site" },
    EnvVarSpec { name: "KIN_EMBED_OPENAI_QUERY_PREFIX", kind: Kind::Str, default: "", sensitivity: Sensitivity::Correctness, summary: "kin-db instruction prefix prepended to query text for an OpenAI-compatible provider; unset derives the model's documented prefix, and a wrong prefix silently degrades retrieval" },
    EnvVarSpec { name: "KIN_EMBED_OPENAI_DOCUMENT_PREFIX", kind: Kind::Str, default: "", sensitivity: Sensitivity::Correctness, summary: "kin-db instruction prefix prepended to document text for an OpenAI-compatible provider; unset derives the model's documented prefix, and it must match the corpus a query is searched against" },
    EnvVarSpec { name: "KIN_EMBED_OPENAI_REQUEST_JSON", kind: Kind::Str, default: "", sensitivity: Sensitivity::Correctness, summary: "kin-db JSON object merged into every OpenAI-compatible embedding request body; an invalid object fails the embed run, and the overrides can change the returned vectors" },
    // ---- kin-db: OpenAI-compatible transport (endpoint, credential, timeout) --
    EnvVarSpec { name: "KIN_EMBED_OPENAI_BASE_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "kin-db OpenAI-compatible endpoint base URL; unset defaults per profile (https://api.openai.com/v1 for openai, http://localhost:1234/v1 otherwise)" },
    EnvVarSpec { name: "KIN_EMBED_BASE_URL", kind: Kind::Url, default: "", sensitivity: Sensitivity::Operational, summary: "kin-db fallback endpoint base URL read only when KIN_EMBED_OPENAI_BASE_URL is unset" },
    EnvVarSpec { name: "KIN_EMBED_OPENAI_API_KEY", kind: Kind::Secret, default: "", sensitivity: Sensitivity::Secret, summary: "kin-db credential for the OpenAI-compatible embedding endpoint; the openai profile falls back to OPENAI_API_KEY when this is unset" },
    EnvVarSpec { name: "KIN_EMBED_OPENAI_TIMEOUT_SECS", kind: Kind::Secs, default: "120", sensitivity: Sensitivity::Operational, summary: "kin-db per-request timeout for an OpenAI-compatible embedding call, in whole seconds; must be > 0" },
    // ---- kin-db: batch shape and pipeline (throughput, memory headroom) -------
    EnvVarSpec { name: "KIN_EMBED_BATCH_SIZE", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "kin-db entities drained per embedding chunk; must be > 0, and unset derives from the resource profile (cores x 16 clamped to 64..192, else 128)" },
    EnvVarSpec { name: "KIN_EMBED_MAX_BATCH_TOKENS", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "kin-db token-sum ceiling per embedding dispatch; must be > 0, and unset is backend-dependent (16384 Metal, 65536 CUDA). Raising it can exhaust GPU memory" },
    EnvVarSpec { name: "KIN_EMBED_MAX_ATTENTION_AREA", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Operational, summary: "kin-db attention-area ceiling (padded tokens x max sequence length) per embedding dispatch; must be > 0, unset is backend-dependent, and the request is still capped per backend" },
    EnvVarSpec { name: "KIN_EMBED_PIPELINED", kind: Kind::Bool, default: "", sensitivity: Sensitivity::Correctness, summary: "kin-db staged embed pipeline overlapping prep, forward, and persist; unset engages it only under the throughput resource profile, and an explicit value overrides in either direction. The serial path is what keeps persisted vector order byte-for-byte, so forcing it on makes a run non-citable" },
    // ---- kin-db: embedding diagnostics and fault injection --------------------
    EnvVarSpec { name: "KIN_EMBED_BATCH_TRACE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Diagnostic, summary: "kin-db per-sub-batch embedding shape and forward-timing trace; any non-empty value other than '0' enables it" },
    EnvVarSpec { name: "KIN_EMBED_TEST_FORCE_METAL_OOM", kind: Kind::Usize, default: "", sensitivity: Sensitivity::Diagnostic, summary: "kin-db fault injection: replaces the first N Metal embedding dispatches with a synthetic out-of-memory so the CPU-degrade retry path can be exercised; unset or non-positive disarms it" },
    // ---- kin-db: lexical ranking weight ---------------------------------------
    EnvVarSpec { name: "KIN_LOCATE_WEIGHT_FILE_PATH", kind: Kind::NonNegF32, default: "0", sensitivity: Sensitivity::Correctness, summary: "kin-db BM25 field weight for the file path; 0 (the default) keeps file paths out of lexical scoring so entities rank on names, signatures, and bodies, and any positive value indexes path text and changes ranking" },
    // ---- kin-vfs shim: projection authority -----------------------------------
    EnvVarSpec { name: "KIN_NO_VFS", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Operational, summary: "kin-vfs shim projection bypass: set to 1 to skip VFS initialization and exec the real binary directly (only the literal '1' bypasses), default off" },
    EnvVarSpec { name: "KIN_VFS_DISABLE", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "kin-vfs interception kill switch: the literal 1 disables every projected read and write, default off" },
    EnvVarSpec { name: "KIN_VFS_STRICT", kind: Kind::Bool, default: "false", sensitivity: Sensitivity::Correctness, summary: "require graph-authoritative projection misses to fail loud when the daemon is unreachable instead of passing through to raw files" },
    // ---- container entrypoint (shell-consumed; inherited by the daemon) -------
    EnvVarSpec { name: "KIN_WORKSPACE_DIR", kind: Kind::Path, default: "", sensitivity: Sensitivity::Operational, summary: "docker-entrypoint workspace override for both storage modes; unset uses /tmp/kin-workspace (backed by an emptyDir in k8s); set to /workspace to opt into a legacy mounted volume" },
];

/// The full registry: hand-curated operational/safety/correctness specs, the
/// hand-tracked downstream sibling-crate levers, plus the auto-extracted
/// locate/ranking tuning knobs.
pub fn registry() -> Vec<EnvVarSpec> {
    let mut all: Vec<EnvVarSpec> =
        Vec::with_capacity(OPERATIONAL.len() + DOWNSTREAM.len() + GENERATED_KNOBS.len());
    all.extend_from_slice(OPERATIONAL);
    all.extend_from_slice(DOWNSTREAM);
    all.extend_from_slice(GENERATED_KNOBS);
    all
}

/// Look up a spec by exact name.
pub fn spec(name: &str) -> Option<EnvVarSpec> {
    OPERATIONAL
        .iter()
        .chain(DOWNSTREAM.iter())
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
            "unrecognized KIN_* environment variable(s); these have no effect and are probably typos (see docs/env-vars.md)"
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
        ("KIN_HOME", "Install & launch"),
        ("KIN_DIR", "Install & launch"),
        ("KIN_VERSION", "Install & launch"),
        ("KIN_BASE_URL", "Install & launch"),
        ("KIN_NO_SETUP", "Install & launch"),
        ("KIN_REGISTRY_REPAIR", "Install & launch"),
        ("KIN_MANAGED_BIN", "Install & launch"),
        ("KIN_NO_PROVISION", "Install & launch"),
        ("KIN_LAUNCHER_", "Install & launch"),
        ("KIN_MCP_", "Install & launch"),
        ("KIN_BINARY_PATH", "Install & launch"),
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
        ("KIN_HYDRATE_", "Diagnostics"),
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
        "Install & launch",
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
    out.push_str("- an unrecognized `KIN_*` name is warned as a likely typo, because setting it has no effect;\n");
    out.push_str("- an invalid value is a hard startup error for a **correctness** variable, otherwise a warning;\n");
    out.push_str("- a correctness variable set away from its default is logged, so behavior drift is never silent.\n\n");
    out.push_str(
        "Variables owned by sibling components (e.g. `KIN_VFS_*` from kin-vfs) are \
         recognized as external and left alone.\n\n",
    );
    out.push_str(
        "**Zero-bound rule.** For a `*_TIMEOUT_MS`, `*_BUDGET_MS`, or bounded `*_TIMEOUT_SECS` \
         knob, `0` means **disabled / unbounded**, so the bound never fires. It is never an \
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
    fn tables_are_pairwise_disjoint() {
        // No name may appear in more than one source table; `registry()` simply
        // concatenates them, so an overlap would silently double-count.
        for (a_name, a) in [
            ("operational", OPERATIONAL),
            ("downstream", DOWNSTREAM),
            ("generated", GENERATED_KNOBS),
        ] {
            for (b_name, b) in [
                ("operational", OPERATIONAL),
                ("downstream", DOWNSTREAM),
                ("generated", GENERATED_KNOBS),
            ] {
                if a_name >= b_name {
                    continue; // each unordered pair once
                }
                let a_names: std::collections::HashSet<&str> = a.iter().map(|s| s.name).collect();
                for s in b {
                    assert!(
                        !a_names.contains(s.name),
                        "{} is in both the {a_name} and {b_name} tables",
                        s.name
                    );
                }
            }
        }
    }

    #[test]
    fn known_hazard_vars_are_present_and_correctness_relevant() {
        for name in [
            "KIN_DAEMON_DISABLE_FILESYSTEM_RECONCILE",
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

    // ---- downstream sibling-crate levers ----------------------------------

    #[test]
    fn downstream_levers_are_registered_not_unknown() {
        // The bug this closes: these levers are consumed by kin-db / kin-infer /
        // the kin-vfs shim but were absent from the registry, so the startup audit
        // called them "unrecognized … no effect" while they were changing real
        // behavior. Registered, they must never surface as unknown.
        for name in [
            "KIN_INFER_CPU_BACKEND",
            "KIN_INFER_OCCUPANCY_DISPATCH",
            "KIN_EMBED_BACKEND",
            "KIN_EMBED_HYBRID",
            "KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN",
            "KIN_EMBED_HYBRID_GPU_TPUT_RATIO",
            "KIN_EMBED_CACHE",
            "KIN_EMBED_CACHE_DIR",
            "KIN_NO_VFS",
            "KIN_VFS_DISABLE",
            "KIN_VFS_STRICT",
        ] {
            assert!(
                spec(name).is_some(),
                "{name} must be registered in DOWNSTREAM"
            );
            let report = audit_env([(name.to_string(), "1".to_string())], false);
            assert!(
                report.unknown.is_empty(),
                "{name} must be recognized, not reported unknown: {:?}",
                report.unknown
            );
        }
    }

    #[test]
    fn installer_and_wrapper_variables_are_registered_not_unknown() {
        // These variables are consumed before the native process starts, but
        // shell and Node launchers intentionally inherit them into `kin`.
        // Calling them "unrecognized ... no effect" there is false and made a
        // normal KIN_MCP_AUTO_INIT first run look misconfigured.
        for (name, value) in [
            ("KIN_VERSION", "0.4.6"),
            ("KIN_BASE_URL", "file:///tmp/kin-releases"),
            ("KIN_NO_SETUP", "1"),
            ("KIN_REGISTRY_REPAIR", "1"),
            ("KIN_MANAGED_BIN", "/tmp/kin"),
            ("KIN_NO_PROVISION", "1"),
            ("KIN_LAUNCHER_ADOPT", "1"),
            ("KIN_MCP_KIN_BINARY", "/tmp/kin"),
            (
                "KIN_MCP_RELEASE_BASE_URL",
                "https://github.example/releases",
            ),
            ("KIN_MCP_AUTO_INIT", "1"),
        ] {
            assert!(spec(name).is_some(), "{name} must be registered");
            let report = audit_env([(name.to_string(), value.to_string())], false);
            assert!(
                report.unknown.is_empty(),
                "{name} must be recognized, not reported unknown: {:?}",
                report.unknown
            );
            assert!(
                report.invalid.is_empty(),
                "{name} test value must validate: {:?}",
                report.invalid
            );
        }
    }

    #[test]
    fn downstream_correctness_lever_override_is_loud() {
        // A behavior-relevant downstream lever set off its default gets the same
        // "correctness-relevant override active" treatment as any correctness var —
        // behavior drift is never silent.
        let cpu = audit_env(
            [("KIN_EMBED_BACKEND".to_string(), "cpu".to_string())],
            false,
        );
        assert!(
            cpu.non_default.iter().any(|f| f.var == "KIN_EMBED_BACKEND"),
            "forcing the embedding backend to cpu must be recorded as active drift"
        );
        // A resource profile pinned to throughput (a non-citable mode) likewise.
        let tput = audit_env(
            [("KIN_RESOURCE_PROFILE".to_string(), "throughput".to_string())],
            false,
        );
        assert!(
            tput.non_default
                .iter()
                .any(|f| f.var == "KIN_RESOURCE_PROFILE"),
            "throughput profile must be surfaced as a live behavior override"
        );
        // An operational downstream lever (numerically identical output) is not
        // drift and must stay quiet.
        let occ = audit_env(
            [("KIN_INFER_OCCUPANCY_DISPATCH".to_string(), "1".to_string())],
            false,
        );
        assert!(
            occ.non_default.is_empty(),
            "a numerically-identical perf lever must not be logged as correctness drift"
        );
    }

    // ---- strict mode against a real embedding configuration ----------------

    /// Every `KIN_EMBED_*` / `KIN_LOCATE_*` name kin-db reads, with a value a real
    /// operator could set. Kept as pairs so strict mode is exercised against values,
    /// not just names: a registered variable whose documented kind contradicts its
    /// read site would validate here and fail.
    const KIN_DB_EMBED_CONFIGURATION: &[(&str, &str)] = &[
        ("KIN_EMBED_PROVIDER", "openai-compatible"),
        ("KIN_EMBED_MODEL_ID", "nomic-ai/nomic-embed-text-v1.5"),
        ("KIN_EMBED_MODEL_REVISION", "main"),
        ("KIN_EMBED_OPENAI_MODEL", "text-embedding-3-small"),
        ("KIN_EMBED_OPENAI_BASE_URL", "http://localhost:1234/v1"),
        ("KIN_EMBED_BASE_URL", "http://localhost:1234/v1"),
        ("KIN_EMBED_OPENAI_API_KEY", "sk-not-a-real-key"),
        ("KIN_EMBED_OPENAI_DIMENSIONS", "768"),
        ("KIN_EMBED_OPENAI_SEND_DIMENSIONS", "1"),
        ("KIN_EMBED_OPENAI_TIMEOUT_SECS", "120"),
        ("KIN_EMBED_OPENAI_QUERY_PREFIX", "search_query: "),
        ("KIN_EMBED_OPENAI_DOCUMENT_PREFIX", "search_document: "),
        ("KIN_EMBED_OPENAI_REQUEST_JSON", "{\"encoding_format\":\"float\"}"),
        ("KIN_EMBED_BACKEND", "cpu"),
        ("KIN_EMBED_BATCH_SIZE", "128"),
        ("KIN_EMBED_MAX_BATCH_TOKENS", "16384"),
        ("KIN_EMBED_MAX_ATTENTION_AREA", "8388608"),
        ("KIN_EMBED_PIPELINED", "1"),
        ("KIN_EMBED_BATCH_TRACE", "1"),
        ("KIN_EMBED_TEST_FORCE_METAL_OOM", "2"),
        ("KIN_EMBED_CACHE", "0"),
        ("KIN_EMBED_CACHE_DIR", "/tmp/kin-embed-cache"),
        ("KIN_EMBED_CACHE_BUDGET_GB", "8"),
        ("KIN_EMBED_HYBRID", "seq"),
        ("KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN", "256"),
        ("KIN_EMBED_HYBRID_GPU_TPUT_RATIO", "3.5"),
        ("KIN_LOCATE_WEIGHT_FILE_PATH", "2.0"),
        ("KIN_RESOURCE_PROFILE", "throughput"),
    ];

    #[test]
    fn strict_mode_accepts_a_full_non_default_embedding_configuration() {
        // The bug this closes: `KIN_ENV_VALIDATION=strict` aborted startup for anyone
        // running a non-default embedding setup, because the variables kin-db reads
        // were unregistered. Strict mode must accept the whole configuration.
        let env: Vec<(String, String)> = KIN_DB_EMBED_CONFIGURATION
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        let report = audit_env(env, true);
        assert!(
            report.unknown.is_empty(),
            "a working embedding configuration must not be called a typo: {:?}",
            report.unknown
        );
        assert!(
            report.invalid.is_empty(),
            "a working embedding configuration must validate under strict mode: {:?}",
            report.invalid
        );
        assert!(
            !report.has_hard_errors(),
            "strict mode must not abort startup on a working embedding configuration"
        );
    }

    #[test]
    fn a_genuine_embed_typo_is_still_caught() {
        // The other side of the same guard: widening the registry must not make it
        // blind. A misspelling next to real variables is still unknown, still warns,
        // and still aborts strict startup.
        let typo = "KIN_EMBED_MODEL_IDD";
        assert!(spec(typo).is_none(), "{typo} must not be registered");

        let mut env: Vec<(String, String)> = vec![
            ("KIN_EMBED_PROVIDER".to_string(), "local".to_string()),
            (typo.to_string(), "some-model".to_string()),
        ];
        env.push(("KIN_EMBED_TYPO".to_string(), "1".to_string()));

        let warn = audit_env(env.clone(), false);
        assert_eq!(
            warn.unknown,
            vec![typo.to_string(), "KIN_EMBED_TYPO".to_string()],
            "an unknown KIN_EMBED_* name must still be reported"
        );

        let strict = audit_env(env, true);
        assert_eq!(
            strict.unknown.len(),
            2,
            "strict mode must still see the typos"
        );
    }

    #[test]
    fn the_openai_credential_is_registered_as_a_secret() {
        // A credential in the registry must be modeled as a secret, or a non-default
        // finding would print the key. Both the kind and the sensitivity carry it.
        let key = spec("KIN_EMBED_OPENAI_API_KEY").expect("credential must be registered");
        assert!(
            matches!(key.kind, Kind::Secret),
            "the embedding API key must be Kind::Secret so it is never echoed"
        );
        assert_eq!(
            key.sensitivity,
            Sensitivity::Secret,
            "the embedding API key must carry Sensitivity::Secret"
        );
        let report = audit_env(
            [(
                "KIN_EMBED_OPENAI_API_KEY".to_string(),
                "sk-live-must-never-appear".to_string(),
            )],
            true,
        );
        assert!(report.invalid.is_empty());
        assert!(
            !format!("{report:?}").contains("sk-live-must-never-appear"),
            "the embedding API key value must never reach a finding"
        );
    }

    // ---- pinned-dependency env-read parity --------------------------------

    /// Every `KIN_*` name that appears in the pinned kin-db's own `src/`. The
    /// enumeration arm below rebuilds this from the vendored crate; this list is what
    /// keeps the test non-vacuous where that source is not on disk, and it is also the
    /// control that proves the enumeration found a real tree rather than an empty one.
    ///
    /// Regenerate with the pinned version from `Cargo.lock`:
    ///
    /// ```text
    /// grep -rhoE '"KIN_[A-Z0-9_]+"' \
    ///   "$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/kin-db-<version>)/src" \
    ///   | tr -d '"' | sort -u
    /// ```
    const KIN_DB_ENV_READS: &[&str] = &[
        "KIN_EMBED_BACKEND",
        "KIN_EMBED_BASE_URL",
        "KIN_EMBED_BATCH_SIZE",
        "KIN_EMBED_BATCH_TRACE",
        "KIN_EMBED_CACHE",
        "KIN_EMBED_CACHE_BUDGET_GB",
        "KIN_EMBED_CACHE_DIR",
        "KIN_EMBED_HYBRID",
        "KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN",
        "KIN_EMBED_HYBRID_GPU_TPUT_RATIO",
        "KIN_EMBED_MAX_ATTENTION_AREA",
        "KIN_EMBED_MAX_BATCH_TOKENS",
        "KIN_EMBED_MODEL_ID",
        "KIN_EMBED_MODEL_REVISION",
        "KIN_EMBED_OPENAI_API_KEY",
        "KIN_EMBED_OPENAI_BASE_URL",
        "KIN_EMBED_OPENAI_DIMENSIONS",
        "KIN_EMBED_OPENAI_DOCUMENT_PREFIX",
        "KIN_EMBED_OPENAI_MODEL",
        "KIN_EMBED_OPENAI_QUERY_PREFIX",
        "KIN_EMBED_OPENAI_REQUEST_JSON",
        "KIN_EMBED_OPENAI_SEND_DIMENSIONS",
        "KIN_EMBED_OPENAI_TIMEOUT_SECS",
        "KIN_EMBED_PIPELINED",
        "KIN_EMBED_PROVIDER",
        "KIN_EMBED_TEST_FORCE_METAL_OOM",
        "KIN_LOCATE_WEIGHT_FILE_PATH",
        "KIN_RESOURCE_PROFILE",
    ];

    /// The kin-db version this workspace pins, read from `Cargo.lock` so the scan can
    /// never drift onto a different vendored copy than the one that gets linked.
    fn pinned_kin_db_version(root: &std::path::Path) -> Option<String> {
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).ok()?;
        let mut in_kin_db = false;
        for line in lock.lines() {
            let line = line.trim();
            if line == "[[package]]" {
                in_kin_db = false;
            } else if line == "name = \"kin-db\"" {
                in_kin_db = true;
            } else if in_kin_db {
                if let Some(rest) = line.strip_prefix("version = \"") {
                    return rest.strip_suffix('"').map(str::to_string);
                }
            }
        }
        None
    }

    /// Locate the vendored source of a pinned registry crate under the cargo home.
    /// Returns `None` when it is not on disk (a vendored or offline build layout).
    fn vendored_crate_src(crate_dir: &str) -> Option<std::path::PathBuf> {
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cargo")))?;
        let registries = std::fs::read_dir(cargo_home.join("registry/src")).ok()?;
        for registry in registries.flatten() {
            let candidate = registry.path().join(crate_dir).join("src");
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
        None
    }

    /// Every `KIN_*` string literal under `dir`. Deliberately over-inclusive: it does
    /// not try to recognize a read *shape*, because kin-db reads through several
    /// helpers (`env_nonempty`, `env_flag`, a bare `env::var`, and a `const` holding
    /// the name), and a shape-matching scan is exactly what under-counted this surface
    /// in the first place. A name that turns up here and is registered nowhere is the
    /// defect; a name that is genuinely not a variable belongs in the allowlist.
    fn scan_kin_literals(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
        let mut found = std::collections::BTreeSet::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let bytes = text.as_bytes();
                let mut from = 0;
                while let Some(rel) = text[from..].find("\"KIN_") {
                    let start = from + rel + 1;
                    let mut end = start;
                    while end < bytes.len()
                        && (bytes[end].is_ascii_uppercase()
                            || bytes[end].is_ascii_digit()
                            || bytes[end] == b'_')
                    {
                        end += 1;
                    }
                    if end < bytes.len() && bytes[end] == b'"' && end - start > "KIN_".len() {
                        found.insert(text[start..end].to_string());
                    }
                    from = start;
                }
            }
        }
        found
    }

    #[test]
    fn every_kin_db_env_read_is_registered() {
        // The gap this closes: kin-db reads its embedding surface from the process
        // environment, but the registry only knew a handful of those names, so the
        // startup audit called a working OpenAI-compatible setup "unrecognized … no
        // effect" and strict mode refused to start. A whole-repo grep in kin cannot
        // see any of it, because the reads live in a pinned registry dependency.
        let allow = load_dependency_env_allowlist(std::path::Path::new(env!(
            "CARGO_MANIFEST_DIR"
        )));
        let unregistered = |names: &std::collections::BTreeSet<String>| {
            names
                .iter()
                .filter(|n| !is_known(n) && !allow.contains(*n))
                .cloned()
                .collect::<Vec<_>>()
        };

        // Baseline arm: always runs, so the test can still fail where the vendored
        // source is absent (a packaged or offline build layout).
        let baseline: std::collections::BTreeSet<String> =
            KIN_DB_ENV_READS.iter().map(|s| s.to_string()).collect();
        assert!(
            unregistered(&baseline).is_empty(),
            "these KIN_* vars are read by the pinned kin-db but registered nowhere: {:?}",
            unregistered(&baseline)
        );

        // Enumeration arm: rebuild the read set from the vendored crate so a kin-db
        // that adds a variable, or a pin bump that brings one in, fails here instead
        // of silently drifting.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let Some(version) = pinned_kin_db_version(&root) else {
            eprintln!("Cargo.lock not readable; kin-db enumeration arm did not run");
            return;
        };
        let Some(src) = vendored_crate_src(&format!("kin-db-{version}")) else {
            eprintln!(
                "vendored kin-db-{version} source not on disk; enumeration arm did not run"
            );
            return;
        };
        let scanned = scan_kin_literals(&src);
        // Control: an enumeration that found nothing, or lost names the pinned list
        // already proves are there, means the scan pointed somewhere wrong. Without
        // this, an empty result would read as a clean parity pass.
        let lost: Vec<&String> = baseline.difference(&scanned).collect();
        assert!(
            lost.is_empty(),
            "the kin-db source scan at {src:?} lost known-present names {lost:?}; \
             the scan is not looking at the pinned crate"
        );
        assert!(
            unregistered(&scanned).is_empty(),
            "these KIN_* vars appear in kin-db-{version} source but are registered \
             nowhere (register them in DOWNSTREAM in env_registry.rs, or, for a name \
             that is genuinely not an operator-facing variable, add it to \
             crates/kin-core/dependency_env_allowlist.txt): {:?}",
            unregistered(&scanned)
        );
    }

    // ---- workspace env-read completeness ----------------------------------

    /// Extract every `KIN_*` name read through the direct `env::var` / `env::var_os`
    /// shape in `text`. Env *writes* (`set_var`, `remove_var`), helper-wrapped
    /// reads, and dynamic reads (a non-literal name) are intentionally excluded.
    fn scan_kin_env_reads(text: &str) -> Vec<String> {
        // Assemble the read-shape needles from a bare quote char so this scanner's
        // own source never contains the literal pattern it searches for.
        let q = '"';
        let needles = [format!("env::var({q}KIN_"), format!("env::var_os({q}KIN_")];
        let bytes = text.as_bytes();
        let mut found = Vec::new();
        for needle in &needles {
            let mut from = 0;
            while let Some(rel) = text[from..].find(needle.as_str()) {
                // `start` points at the 'K' of the KIN_ name.
                let start = from + rel + needle.len() - "KIN_".len();
                let mut end = start;
                while end < bytes.len() {
                    let c = bytes[end];
                    if c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_' {
                        end += 1;
                    } else {
                        break;
                    }
                }
                if end - start > "KIN_".len() {
                    found.push(text[start..end].to_string());
                }
                from += rel + needle.len();
            }
        }
        found
    }

    /// Load an intentional-exception allowlist (one `KIN_*` name per line, `#`
    /// comments and blanks ignored). Missing file → empty set.
    fn load_allowlist(path: &std::path::Path) -> std::collections::BTreeSet<String> {
        let mut set = std::collections::BTreeSet::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    set.insert(line.to_string());
                }
            }
        }
        set
    }

    /// Exceptions for kin's own read sites.
    fn load_env_var_allowlist(manifest: &std::path::Path) -> std::collections::BTreeSet<String> {
        load_allowlist(&manifest.join("env_var_allowlist.txt"))
    }

    /// Exceptions for names appearing in a pinned dependency's source.
    fn load_dependency_env_allowlist(
        manifest: &std::path::Path,
    ) -> std::collections::BTreeSet<String> {
        load_allowlist(&manifest.join("dependency_env_allowlist.txt"))
    }

    #[test]
    fn every_kin_env_read_in_workspace_is_registered() {
        // Guardrail for kin's OWN surface: scan the workspace source for direct
        // KIN_* env reads and assert each is registered. A new lever added to kin
        // without a registry entry would make the startup audit lie ("unrecognized
        // … no effect") about a live knob. Cross-repo consumers (kin-db, kin-infer,
        // kin-vfs) cannot be scanned from here — their levers are hand-tracked in
        // DOWNSTREAM; see that table's note. Helper-wrapped locate/ranking knobs are
        // extracted into GENERATED_KNOBS by scripts/gen_env_registry.py and are
        // covered by is_known() the same way.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.join("../..");
        // Skip in a packaged/published single-crate context (mirrors the doc test):
        // without the sibling crates there is nothing to scan.
        if !root.join("crates/kin-cli/src").is_dir() {
            eprintln!("workspace crates not present; skipping env-read completeness scan");
            return;
        }

        let allow = load_env_var_allowlist(manifest);
        let mut offenders: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                if path.is_dir() {
                    // Skip build output, vendored deps, and hidden/coordination dirs.
                    if file_name == "target"
                        || file_name == "node_modules"
                        || file_name.starts_with('.')
                    {
                        continue;
                    }
                    stack.push(path);
                } else if file_name.ends_with(".rs") {
                    let Ok(text) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    for read in scan_kin_env_reads(&text) {
                        if allow.contains(&read) || is_known(&read) {
                            continue;
                        }
                        offenders
                            .entry(read)
                            .or_insert_with(|| path.display().to_string());
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these KIN_* vars are read in kin source but not registered in the env \
             registry (register them in env_registry.rs, or, for a deliberate \
             exception, add them to crates/kin-core/env_var_allowlist.txt): {offenders:?}"
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
