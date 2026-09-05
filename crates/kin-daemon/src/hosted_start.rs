// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a hosted `kin-daemon` needs before it can serve, declared by the binary
//! that enforces it.
//!
//! # Why this exists
//!
//! The hosted start path has grown a requirement per release, and each one
//! reached production as a rollback rather than as a diff. A deployment cannot
//! read a requirement out of an image, so the deployment's env list was
//! hand-typed from a rollback narrative and was always one release behind the
//! binary it configured. `kin-daemon --compat-json` now carries
//! [`declaration`], so the config can be graded against the image it pins.
//!
//! The central `KIN_*` registry in `kin-core::env_registry` cannot answer this.
//! It covers `KIN_*` names only, and `GOOGLE_CLOUD_PROJECT`, the variable whose
//! absence produced the 2026-09-02 outage, is not one.
//!
//! # The shape of the declaration
//!
//! ```json
//! "hosted_start_requirements": {
//!   "schema": "kin.daemon.hosted-start.v1",
//!   "features": { "gcs": true, "firestore": true },
//!   "requirements": [
//!     {
//!       "name": "GOOGLE_CLOUD_PROJECT",
//!       "kind": "env",
//!       "required": true,
//!       "introduced_in": "0.6.2",
//!       "absence": "readiness-closed",
//!       "consequence": "...",
//!       "refusals": [{ "stage": "spine", "message": "..." }]
//!     }
//!   ]
//! }
//! ```
//!
//! `requirements` is sorted by name so a consumer can diff two images. `absence`
//! is derived from the stages, never stored, so it cannot disagree with them.
//!
//! # The two stages, and why they are not one flag
//!
//! [`Stage::Bind`] refusals happen in `create_state` before any I/O: the process
//! exits and nothing serves. [`Stage::Spine`] refusals happen in
//! `DaemonState::hosted_spine_contract`, which is not on the bind path, so the
//! daemon binds, loads the graph, and then answers 503 on `/readiness` forever.
//! That second shape is what the 2026-09-02 rollout hit, and a declaration that
//! called both of them "required" would not have told the grader that the
//! failure arrives after a successful start.
//!
//! # The single source of truth
//!
//! Every hosted requirement is one [`HostedStartRequirement`] const below, and
//! every refusal site reads its message from that const rather than spelling it
//! again. The table and the enforcing code stay bound by tests that fail in
//! opposite directions. `every_declared_bind_requirement_refuses_startup` (in
//! the daemon binary) and `every_declared_spine_requirement_closes_the_hosted_contract`
//! (in `state`) drive the real start path once per declared requirement and
//! fail on a declaration nothing enforces.
//! [`tests::the_hosted_start_path_reads_no_environment_of_its_own`] scans the
//! enforcing source and fails on a refusal added without a row here.
//!
//! # Feature gates are start requirements too
//!
//! A build without the `firestore` feature refuses hosted service whatever the
//! environment holds, because `create_spine_backend` cannot compare-and-swap a
//! cursor-bound head. `features` in the declaration reports that, so a pin can
//! be refused for a build that could never have served.

use std::collections::BTreeMap;

/// Whether a requirement carries a credential.
///
/// A `Secret` is never rendered with its value anywhere, and a deployment is
/// expected to source it from a secret store rather than a config literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Env,
    Secret,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Env => "env",
            Kind::Secret => "secret",
        }
    }
}

/// Where in hosted startup a requirement is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// `create_state`, before any object-store or Firestore traffic. The
    /// process refuses to start.
    Bind,
    /// `DaemonState::hosted_spine_contract`, reached after the process is
    /// already bound and serving liveness. Readiness stays closed instead.
    Spine,
}

impl Stage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Bind => "bind",
            Stage::Spine => "spine",
        }
    }
}

/// What an operator sees when the requirement is absent. Derived from the
/// stages a requirement is enforced at, so it can never contradict them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absence {
    /// The process exits during startup with the refusal on stderr.
    RefusesToStart,
    /// The process starts, binds, and answers 503 on `/readiness` with the
    /// refusal as the reason. Liveness stays green, which is the shape that
    /// reads as healthy to everything except the readiness gate.
    ReadinessClosed,
    /// Nothing refuses. The daemon takes a default and runs.
    ///
    /// Paired with `required: true` this is the dangerous class, and the whole
    /// reason the declaration reports `required` separately from what enforces
    /// it: the deployment must set the value because nothing in the binary will
    /// tell it that it didn't.
    Silent,
}

impl Absence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Absence::RefusesToStart => "refuses-to-start",
            Absence::ReadinessClosed => "readiness-closed",
            Absence::Silent => "silent",
        }
    }
}

/// One environment variable or secret the hosted start path reads.
#[derive(Debug, Clone, Copy)]
pub struct HostedStartRequirement {
    /// The environment variable name, exactly as the daemon reads it.
    pub name: &'static str,
    pub kind: Kind,
    /// Whether a hosted deployment has to set this.
    ///
    /// Deliberately independent of [`Self::refusals`]. Some requirements are
    /// needed and enforced; some are needed and enforced by nothing, which a
    /// declaration that conflated the two could not say. Read it with
    /// [`Self::absence`].
    pub required: bool,
    /// The first `kin` release whose hosted path refuses without this.
    ///
    /// A historical fact the running binary cannot derive, so it is recorded
    /// here and held to a well-formed version no later than this build by
    /// `introduced_in_is_a_released_version`. Read it as provenance for a
    /// deployment's version floor, not as something the binary measured.
    pub introduced_in: &'static str,
    /// One line an operator can act on, naming what breaks and when.
    pub consequence: &'static str,
    /// Every stage that refuses without this, with the verbatim message that
    /// stage prints. Empty for a requirement whose absence takes a default.
    pub refusals: &'static [(Stage, &'static str)],
}

impl HostedStartRequirement {
    /// The message the named stage prints when this is absent.
    ///
    /// Every refusal site calls this rather than spelling its message again,
    /// so the declaration and the refusal cannot drift apart.
    ///
    /// # Panics
    ///
    /// Panics if the requirement declares no refusal for that stage, which is a
    /// programming error: a site that refuses must have a row saying so.
    pub fn refusal(&self, stage: Stage) -> &'static str {
        self.refusals
            .iter()
            .find(|(declared, _)| *declared == stage)
            .map(|(_, message)| *message)
            .unwrap_or_else(|| {
                panic!(
                    "{} refuses at {} with no declared message; add the stage to its \
                     HostedStartRequirement",
                    self.name,
                    stage.as_str()
                )
            })
    }

    /// What an operator sees when this is absent, derived from the stages.
    ///
    /// A bind refusal dominates a spine one: a process that never starts cannot
    /// go on to close readiness.
    pub fn absence(&self) -> Absence {
        if self.enforced_at(Stage::Bind) {
            Absence::RefusesToStart
        } else if self.enforced_at(Stage::Spine) {
            Absence::ReadinessClosed
        } else {
            Absence::Silent
        }
    }

    /// Required, and nothing in the binary refuses without it.
    ///
    /// These are the rows a deployment grade should read first: the binary
    /// cannot defend itself against their absence, so the config is the only
    /// thing standing between the fleet and a pod that starts wrong and looks
    /// healthy doing it.
    pub fn required_but_unenforced(&self) -> bool {
        self.required && self.absence() == Absence::Silent
    }

    pub fn enforced_at(&self, stage: Stage) -> bool {
        self.refusals.iter().any(|(declared, _)| *declared == stage)
    }

    /// Read this requirement, refusing at the named stage with the declared
    /// message. An empty or untrimmed value counts as absent: a deployment that
    /// renders a blank value has not set it.
    pub fn require(&self, stage: Stage) -> Result<String, String> {
        match std::env::var(self.name) {
            Ok(value) if !value.trim().is_empty() => Ok(value),
            _ => Err(self.refusal(stage).to_string()),
        }
    }

    /// Read this requirement without refusing, for the optional ones.
    pub fn read(&self) -> Option<String> {
        std::env::var(self.name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }
}

// ---------------------------------------------------------------------------
// The requirements themselves.
// ---------------------------------------------------------------------------

pub const STORAGE: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_STORAGE",
    kind: Kind::Env,
    required: true,
    introduced_in: "0.6.0",
    consequence: "the daemon runs in local mode and every requirement below is skipped. It opens \
                  the pod's own disk instead of the bucket, builds an in-memory spine, needs no \
                  credential, logs \"using in-memory spine backend (local dev mode)\", and serves. \
                  Nothing refuses, because nothing at that point knows the deployment meant to be \
                  hosted. `--storage gcs` on the command line sets the same mode",
    refusals: &[],
};

pub const DAEMON_BIND_HOST: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_DAEMON_BIND_HOST",
    kind: Kind::Env,
    required: true,
    introduced_in: "0.6.0",
    consequence: "the daemon binds 127.0.0.1 and nothing outside the container can reach it. \
                  Hosted wants 0.0.0.0, which then requires KIN_DAEMON_AUTH_TOKEN: a non-loopback \
                  bind without one is refused",
    refusals: &[],
};

pub const GCS_BUCKET: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_GCS_BUCKET",
    kind: Kind::Env,
    required: true,
    introduced_in: "0.6.0",
    consequence: "no hosted graph storage: the daemon exits during startup",
    refusals: &[
        (
            Stage::Bind,
            "KIN_GCS_BUCKET env var required for --storage gcs",
        ),
        (
            Stage::Spine,
            "KIN_GCS_BUCKET is required for hosted durable spine",
        ),
    ],
};

pub const GCS_PREFIX: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_GCS_PREFIX",
    kind: Kind::Env,
    required: true,
    introduced_in: "0.6.2",
    consequence: "the daemon binds and then holds /readiness at 503: the durable spine scope is \
                  the bucket root, which is not an addressable fleet scope",
    refusals: &[(
        Stage::Spine,
        "KIN_GCS_PREFIX is required for hosted durable spine",
    )],
};

pub const RELEASE_DAEMON_DIGEST: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_RELEASE_DAEMON_DIGEST_INTERNAL",
    kind: Kind::Env,
    required: true,
    introduced_in: "0.6.2",
    consequence: "no reader admission identity, so publication fencing cannot name this process: \
                  the daemon exits during startup",
    refusals: &[(
        Stage::Bind,
        "KIN_RELEASE_DAEMON_DIGEST_INTERNAL is required for GCS graph publication admission",
    )],
};

pub const DAEMON_AUTH_TOKEN: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_DAEMON_AUTH_TOKEN",
    kind: Kind::Secret,
    required: true,
    introduced_in: "0.6.2",
    consequence: "the hosted publication-control API would be unauthenticated: the daemon exits \
                  during startup",
    refusals: &[(
        Stage::Bind,
        "KIN_DAEMON_AUTH_TOKEN is required for the hosted publication-control API",
    )],
};

pub const PUBLICATION_CONTROL_AUTH_TOKEN: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_PUBLICATION_CONTROL_AUTH_TOKEN",
    kind: Kind::Secret,
    required: true,
    introduced_in: "0.6.2",
    consequence: "no operator credential distinct from the ordinary daemon token, so a rollout \
                  could be driven by any authenticated caller: the daemon exits during startup. \
                  It must also differ from KIN_DAEMON_AUTH_TOKEN, which is refused separately",
    refusals: &[(
        Stage::Bind,
        "KIN_PUBLICATION_CONTROL_AUTH_TOKEN is required for hosted rollout administration",
    )],
};

pub const REPO_IDS: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_REPO_IDS",
    kind: Kind::Env,
    required: true,
    introduced_in: "0.6.2",
    consequence: "publication fencing has no fleet to fence: the daemon exits during startup. The \
                  durable spine additionally requires 1 through 64 canonical entries, and one \
                  that omits the served repo id is refused by name",
    refusals: &[
        (
            Stage::Bind,
            "KIN_REPO_IDS is required for GCS graph publication fencing",
        ),
        (
            Stage::Spine,
            "KIN_REPO_IDS must name the exact hosted spine fleet",
        ),
    ],
};

pub const GOOGLE_CLOUD_PROJECT: HostedStartRequirement = HostedStartRequirement {
    name: "GOOGLE_CLOUD_PROJECT",
    kind: Kind::Env,
    required: true,
    introduced_in: "0.6.2",
    consequence: "the daemon binds, loads the graph, and holds /readiness at 503 for as long as \
                  it runs, because the durable Firestore spine has no project. Liveness stays \
                  green throughout. A daemon before 0.6.2 does the opposite and must NOT be \
                  given this: it silently builds the legacy spine instead",
    refusals: &[(
        Stage::Spine,
        "GOOGLE_CLOUD_PROJECT is required for hosted durable spine",
    )],
};

pub const SPINE_LEGACY_DRAIN_PROOF: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_SPINE_LEGACY_DRAIN_PROOF_SHA256_INTERNAL",
    kind: Kind::Env,
    required: false,
    introduced_in: "0.6.2",
    consequence: "the first hosted rollout cannot write the one-way legacy-migration seal, and \
                  hosted spine reads stay refused until some rollout does. Needed once per \
                  database, not once per deployment",
    refusals: &[],
};

pub const FIRESTORE_DATABASE_ID: HostedStartRequirement = HostedStartRequirement {
    name: "FIRESTORE_DATABASE_ID",
    kind: Kind::Env,
    required: false,
    introduced_in: "0.6.2",
    consequence: "the durable spine uses the project's (default) Firestore database",
    refusals: &[],
};

pub const DAEMON_IDLE_TIMEOUT_SECS: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_DAEMON_IDLE_TIMEOUT_SECS",
    kind: Kind::Env,
    required: false,
    introduced_in: "0.6.0",
    consequence: "the daemon shuts itself down after an hour with no traffic. A hosted pod is \
                  then restarted and pays its startup cost again; set 0 to disable",
    refusals: &[],
};

pub const GCS_ENDPOINT: HostedStartRequirement = HostedStartRequirement {
    name: "KIN_GCS_ENDPOINT",
    kind: Kind::Env,
    required: false,
    introduced_in: "0.6.0",
    consequence: "graph storage goes to real Google Cloud Storage. Set only to redirect at an \
                  emulator, which the daemon then probes and refuses to start without",
    refusals: &[],
};

pub const STORAGE_EMULATOR_HOST: HostedStartRequirement = HostedStartRequirement {
    name: "STORAGE_EMULATOR_HOST",
    kind: Kind::Env,
    required: false,
    introduced_in: "0.6.0",
    consequence: "graph storage goes to real Google Cloud Storage. KIN_GCS_ENDPOINT takes \
                  precedence over this when both are set",
    refusals: &[],
};

/// Every hosted start requirement, in declaration order.
///
/// [`declaration`] sorts by name; this order is the reading order, grouped by
/// what an operator sets together.
pub const HOSTED_START_REQUIREMENTS: &[HostedStartRequirement] = &[
    STORAGE,
    DAEMON_BIND_HOST,
    GCS_BUCKET,
    GCS_PREFIX,
    RELEASE_DAEMON_DIGEST,
    DAEMON_AUTH_TOKEN,
    PUBLICATION_CONTROL_AUTH_TOKEN,
    REPO_IDS,
    GOOGLE_CLOUD_PROJECT,
    SPINE_LEGACY_DRAIN_PROOF,
    FIRESTORE_DATABASE_ID,
    DAEMON_IDLE_TIMEOUT_SECS,
    GCS_ENDPOINT,
    STORAGE_EMULATOR_HOST,
];

/// The schema name of the declaration block, versioned independently of the
/// compat payload around it so a consumer can require a shape.
pub const DECLARATION_SCHEMA: &str = "kin.daemon.hosted-start.v1";

/// The `hosted_start_requirements` block `--compat-json` prints.
///
/// Requirements are sorted by name so two images can be diffed directly.
pub fn declaration() -> serde_json::Value {
    let sorted: BTreeMap<&str, &HostedStartRequirement> = HOSTED_START_REQUIREMENTS
        .iter()
        .map(|requirement| (requirement.name, requirement))
        .collect();
    let requirements: Vec<serde_json::Value> = sorted
        .values()
        .map(|requirement| {
            let refusals: Vec<serde_json::Value> = requirement
                .refusals
                .iter()
                .map(|(stage, message)| {
                    serde_json::json!({ "stage": stage.as_str(), "message": message })
                })
                .collect();
            serde_json::json!({
                "name": requirement.name,
                "kind": requirement.kind.as_str(),
                "required": requirement.required,
                "introduced_in": requirement.introduced_in,
                "absence": requirement.absence().as_str(),
                "required_but_unenforced": requirement.required_but_unenforced(),
                "consequence": requirement.consequence,
                "refusals": refusals,
            })
        })
        .collect();
    serde_json::json!({
        "schema": DECLARATION_SCHEMA,
        "features": {
            "gcs": cfg!(feature = "gcs"),
            "firestore": cfg!(feature = "firestore"),
        },
        "requirements": requirements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two enforcing sources, embedded at compile time rather than read
    /// from disk, so the scan below cannot pass because a path was wrong.
    const DAEMON_BIN_SOURCE: &str = include_str!("bin/kin-daemon.rs");
    const STATE_SOURCE: &str = include_str!("state.rs");

    fn declared_names() -> Vec<&'static str> {
        HOSTED_START_REQUIREMENTS
            .iter()
            .map(|requirement| requirement.name)
            .collect()
    }

    /// The body of a named function, from its signature to the next item at the
    /// same indentation. Crude on purpose: it needs to bound a scan, not parse
    /// Rust, and `every_hosted_env_read_is_declared` proves it found something.
    fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} is no longer in the enforcing source"));
        let rest = &source[start..];
        let indent = signature.len() - signature.trim_start().len();
        let closer = format!("\n{}}}", " ".repeat(indent));
        let end = rest
            .find(&closer)
            .unwrap_or_else(|| panic!("{signature} has no closing brace at its own indentation"));
        &rest[..end]
    }

    /// Every `env::var("NAME")` inside a span, however it is qualified.
    fn env_reads(span: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut rest = span;
        while let Some(at) = rest.find("env::var(\"") {
            let after = &rest[at + "env::var(\"".len()..];
            if let Some(close) = after.find('"') {
                names.push(after[..close].to_string());
                rest = &after[close..];
            } else {
                break;
            }
        }
        names
    }

    /// The hosted start path reads its environment only through this registry.
    ///
    /// This is the arm that catches a refusal added without a declaration. A
    /// raw `env::var` inside either enforcing function is a hosted requirement
    /// no `--compat-json` consumer can see, so the seam is closed here rather
    /// than left to review.
    #[test]
    fn the_hosted_start_path_reads_no_environment_of_its_own() {
        // Positive control on the extractor itself. Without this, a broken
        // matcher would report "no raw reads" for a function full of them.
        assert_eq!(
            env_reads("let a = env::var(\"KIN_ONE\"); let b = std::env::var(\"KIN_TWO\");"),
            vec!["KIN_ONE".to_string(), "KIN_TWO".to_string()],
            "the env-read extractor does not find reads it is pointed at"
        );

        for (label, span) in [
            (
                "create_state",
                function_body(DAEMON_BIN_SOURCE, "fn create_state("),
            ),
            (
                "hosted_spine_contract",
                function_body(STATE_SOURCE, "    fn hosted_spine_contract(&self)"),
            ),
        ] {
            // Positive control on the span. A `function_body` that grabbed the
            // wrong text would make the assertion below pass vacuously.
            assert!(
                span.contains("hosted_start::"),
                "{label} no longer reads its requirements from this registry, so this scan is \
                 pointed at the wrong code"
            );
            assert!(
                !span.contains("env::var("),
                "{label} reads the environment directly: {:?}. Every hosted requirement must go \
                 through a HostedStartRequirement, or --compat-json cannot declare it and a \
                 deployment cannot know it needs it.",
                env_reads(span)
            );
        }
    }

    /// Every `HostedStartRequirement` const in this file is in the list the
    /// declaration renders. A const that is enforced but unlisted is invisible
    /// to a consumer, which is the same failure with a different shape.
    #[test]
    fn every_declared_const_is_in_the_rendered_list() {
        const THIS_SOURCE: &str = include_str!("hosted_start.rs");
        let marker = ": HostedStartRequirement = HostedStartRequirement {";
        let mut consts: Vec<&str> = Vec::new();
        for line in THIS_SOURCE.lines() {
            if let Some(head) = line.strip_prefix("pub const ") {
                if let Some(name) = head.strip_suffix(marker) {
                    consts.push(name);
                }
            }
        }

        // Positive control: the scan must find the consts this file defines.
        assert!(
            consts.contains(&"GOOGLE_CLOUD_PROJECT") && consts.contains(&"GCS_BUCKET"),
            "the const scan is not reading this file's declarations: {consts:?}"
        );
        assert_eq!(
            consts.len(),
            HOSTED_START_REQUIREMENTS.len(),
            "this file declares {} requirement consts but HOSTED_START_REQUIREMENTS lists {}. \
             Every const must be listed or --compat-json will not carry it: {consts:?}",
            consts.len(),
            HOSTED_START_REQUIREMENTS.len()
        );
    }

    /// A requirement that refuses at a stage carries that stage's message, and
    /// the message names the variable. A refusal an operator cannot grep for is
    /// the reason the deployment table was typed by hand.
    #[test]
    fn every_refusal_names_its_own_variable() {
        for requirement in HOSTED_START_REQUIREMENTS {
            for (stage, message) in requirement.refusals {
                assert!(
                    message.contains(requirement.name),
                    "{} refuses at {} with a message that does not name it: {message}",
                    requirement.name,
                    stage.as_str()
                );
                assert_eq!(requirement.refusal(*stage), *message);
            }
        }
    }

    /// Anything the binary refuses without is required. The converse is not
    /// asserted on purpose: `required_but_unenforced` names the rows where the
    /// deployment is the only thing holding the invariant, and erasing that
    /// distinction is what a single "required" flag would do.
    #[test]
    fn every_enforced_requirement_is_required() {
        for requirement in HOSTED_START_REQUIREMENTS {
            if !requirement.refusals.is_empty() {
                assert!(
                    requirement.required,
                    "{} is refused at startup but declared optional",
                    requirement.name
                );
            }
            assert_eq!(
                requirement.absence() == Absence::Silent,
                requirement.refusals.is_empty(),
                "{} derives an absence that disagrees with its refusals",
                requirement.name
            );
        }
    }

    /// The rows a deployment grade must read first are exactly the ones this
    /// fleet has been bitten by, and the set does not grow unnoticed.
    #[test]
    fn the_unenforced_requirements_are_the_known_ones() {
        let mut unenforced: Vec<&str> = HOSTED_START_REQUIREMENTS
            .iter()
            .filter(|requirement| requirement.required_but_unenforced())
            .map(|requirement| requirement.name)
            .collect();
        unenforced.sort_unstable();
        assert_eq!(
            unenforced,
            vec!["KIN_DAEMON_BIND_HOST", "KIN_STORAGE"],
            "the set of requirements nothing enforces has changed. Either the binary grew a \
             refusal (good, drop the row from this list) or hosted grew a requirement only the \
             config holds (say so here, so a grade can too)."
        );
    }

    /// Names are unique, so a consumer keying on name cannot silently lose one.
    #[test]
    fn requirement_names_are_unique() {
        let mut names = declared_names();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(total, names.len(), "a requirement name is declared twice");
    }

    /// `introduced_in` is a well-formed version no later than this build. It
    /// cannot be derived at runtime, so this holds it to the one property a
    /// running binary can check: a requirement cannot have been introduced by a
    /// release that does not exist yet.
    #[test]
    fn introduced_in_is_a_released_version() {
        let parse = |value: &str| -> Vec<u64> {
            value
                .split('.')
                .map(|part| {
                    part.parse::<u64>()
                        .unwrap_or_else(|_| panic!("{value} is not a dotted version"))
                })
                .collect()
        };
        let current = parse(env!("CARGO_PKG_VERSION"));
        for requirement in HOSTED_START_REQUIREMENTS {
            let introduced = parse(requirement.introduced_in);
            assert_eq!(
                introduced.len(),
                3,
                "{} names a non-semver introducing release {}",
                requirement.name,
                requirement.introduced_in
            );
            assert!(
                introduced <= current,
                "{} claims to have been introduced in {}, which is later than this build ({})",
                requirement.name,
                requirement.introduced_in,
                env!("CARGO_PKG_VERSION")
            );
        }
    }

    /// The rendered block keeps the shape a consumer parses.
    #[test]
    fn the_declaration_renders_every_requirement_sorted() {
        let rendered = declaration();
        assert_eq!(rendered["schema"], DECLARATION_SCHEMA);
        let requirements = rendered["requirements"]
            .as_array()
            .expect("requirements must be an array")
            .clone();
        assert_eq!(requirements.len(), HOSTED_START_REQUIREMENTS.len());

        let names: Vec<&str> = requirements
            .iter()
            .map(|entry| entry["name"].as_str().expect("a name"))
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "requirements must render sorted by name");

        for entry in &requirements {
            for field in [
                "name",
                "kind",
                "required",
                "introduced_in",
                "absence",
                "required_but_unenforced",
                "consequence",
                "refusals",
            ] {
                assert!(!entry[field].is_null(), "{field} is missing from {entry}");
            }
        }

        let project = requirements
            .iter()
            .find(|entry| entry["name"] == "GOOGLE_CLOUD_PROJECT")
            .expect("the variable the outage turned on must be declared");
        assert_eq!(project["absence"], "readiness-closed");
        assert_eq!(project["required"], true);
        assert_eq!(
            project["refusals"][0]["message"],
            "GOOGLE_CLOUD_PROJECT is required for hosted durable spine"
        );
    }
}
