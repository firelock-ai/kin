// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

/// `kin mcp start` — Start the MCP stdio server.
///
/// Starts a transport-only MCP server. Graph-backed tools are executed by the
/// repo daemon resolved through the supervisor route; MCP never loads or serves
/// a local graph snapshot in product mode.
///
/// Never hard-exits on a missing repository or an unreachable daemon: an agent
/// CLI that launches this as a global MCP entry from a non-Kin directory must
/// still get a working `initialize`/`tools/list` handshake, not a dead process
/// before the handshake. When no repository can be bound at startup, the
/// server starts anyway and each `tools/call` fails loud with a structured,
/// actionable error (see `kin_mcp::daemon_delegate::daemon_unavailable_tool_result`)
/// instead of the process silently never having started at all.
///
/// Answer early, load behind (FIR-2316): the stdio loop starts before the
/// daemon binding rather than after it. Resolving the repo daemon can spawn
/// one, and a cold start on a flagship-scale store takes minutes; awaiting it
/// here meant zero stdout frames for that whole window, without even the
/// `initialize` response, which no handshake probe or client timeout survives.
/// The binding now runs on a background task that publishes into a
/// [`kin_mcp::StartupDaemonBinding`]; `initialize` and `tools/list` answer
/// immediately, and a `tools/call` that arrives before the binding settles is
/// answered honestly that the daemon is still starting.
///
/// Attach early, start on request (FIR-3099). Answering early moved the wait
/// off the handshake; it did not make the work free. Resolving a repo daemon
/// STARTS one when none is serving, and a daemon that starts opens the store
/// and schedules the background embedding pass, so a session that made no Kin
/// call at all was paying for a full embed of that repository: measured at 1.80
/// GiB resident and 99 percent of a core sixty seconds after the handshake, on
/// a 657.8 KiB store, with the fleet's gpu lock held by somebody else. Every
/// bind this process performs before a caller asks for a graph answer therefore
/// attaches to a daemon that is already serving and starts none, which keeps a
/// warm session exactly as fast as it was; the first `tools/call` admits the
/// spawn, and the binding task waiting on that admission then starts the daemon
/// and settles as before.
///
/// `--no-spawn` is the probe contract (FIR-2341): this server binds only a
/// daemon that is already serving and never starts one, neither in the
/// startup binding nor through tool-call revival. It is carried as the
/// process-wide `KIN_NO_DAEMON=1` rather than as plumbing through every
/// resolution path, because every daemon-starting seam in this binary already
/// honors that variable, and a flag that covered fewer of them than the
/// variable does would be a probe mode with a spawn path left inside it.
pub async fn start(
    global: bool,
    repo: Option<PathBuf>,
    tool_profile: Option<String>,
    no_spawn: bool,
) -> Result<()> {
    if no_spawn {
        std::env::set_var("KIN_NO_DAEMON", "1");
        eprintln!(
            "Kin MCP: --no-spawn is set; this server will bind an already-running daemon but \
             never start one, and graph tool calls without a running daemon fail loud."
        );
    }
    let repo_override = resolve_repo_override(repo);
    if let Some(repo_dir) = &repo_override {
        if global {
            eprintln!(
                "Kin MCP: --repo/KIN_MCP_REPO pins {} for this server; registry mode will not \
                 repoint it.",
                repo_dir.display()
            );
        }
        if let Err(err) = std::env::set_current_dir(repo_dir) {
            eprintln!(
                "Kin MCP: --repo/KIN_MCP_REPO path {} could not be used as the working directory \
                 ({err}); continuing from the launch directory.",
                repo_dir.display()
            );
        }
    }

    let resolved_profile = resolve_tool_profile(
        tool_profile.as_deref(),
        std::env::var("KIN_MCP_TOOL_PROFILE").ok().as_deref(),
    );
    eprintln!("{}", resolved_profile.startup_notice());
    let mut config = served_config(resolved_profile.profile);
    // Paths the server compares, the client's folder against the repository
    // that answers, go through the same symlink resolution the binder uses.
    config.canonicalize = canonical_path;
    // Until the client names a workspace root, the folder it works in is the
    // one this server was launched in.
    config.client_root = std::env::current_dir().ok().map(|dir| canonical_path(&dir));
    // Every command an answer names is spelled so it runs for this reader: a
    // registry install runs Kin through `npx` and puts no `kin` on PATH.
    kin_mcp::first_contact::set_spelling(command_spelling());

    let startup = kin_mcp::StartupDaemonBinding::new();

    // The stdio server always binds through the MCP client's advertised
    // workspace roots: late, when nothing bound from --repo/KIN_MCP_REPO/cwd
    // (how editors that launch MCP servers from $HOME — Cursor, Windsurf, ... —
    // reach the open repo), and again whenever the client reports that its
    // workspace changed, so a window that moves to another folder does not keep
    // being answered from the folder it left.
    //
    // An explicit --repo/KIN_MCP_REPO that bound successfully is an operator
    // decision that workspace roots must not quietly overrule, so that pin never
    // follows the client to another repository. It still refuses to answer for
    // one: the binder reports the disagreement and the server fails loud, rather
    // than serving the pinned repository's graph for a workspace the client
    // moved away from. With the startup binding running behind the loop, whether
    // the pin bound is only known once it settles, so the binder reads it from
    // the shared handle at each invocation.
    let binder_startup = std::sync::Arc::clone(&startup);
    let repo_binder: Option<kin_mcp::RepoBinder> = Some(Box::new(
        move |roots: Vec<PathBuf>| -> Pin<Box<dyn Future<Output = kin_mcp::WorkspaceBinding> + Send>> {
            let startup = std::sync::Arc::clone(&binder_startup);
            Box::pin(async move {
                bind_first_kin_repo(
                    roots,
                    startup.pinned_by_operator(),
                    DaemonBindMode::for_admission(startup.daemon_spawn_admitted()),
                )
                .await
            })
        },
    ));

    // The MCP server revives dead repo daemons itself, from a crate that cannot
    // reach supervisor startup or registration. Publish them before serving so
    // a revived daemon joins supervisor routing like an autostarted one.
    crate::daemon_client::install_spawn_registrar();

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let init_served = config.serves_init();
    let bind_task = tokio::spawn(run_startup_binding(
        global,
        repo_override,
        cwd,
        std::sync::Arc::clone(&startup),
        init_served,
    ));

    // `kin_session_exec` runs toolchain commands in session workspaces through
    // this launcher, the way `kin_init` sets folders up through it.
    kin_mcp::session_exec::install_executor(crate::commands::agent_exec::executor());

    let served =
        kin_mcp::run_stdio_daemon(config, repo_binder, Some(startup), Some(repo_initializer()))
            .await
            .map_err(|e| anyhow::anyhow!("MCP server error: {}", e));

    // The client closed stdin, so this server is done. A daemon spawn already
    // in flight is detached and survives on its own by design, so the next
    // session finds it warm; only the wait is abandoned.
    bind_task.abort();

    served
}

/// The startup daemon binding `start` used to run inline, now driven behind
/// the stdio loop. Publishes every outcome into `startup` so the server can
/// answer `tools/call` honestly while this is still in flight.
async fn run_startup_binding(
    global: bool,
    repo_override: Option<PathBuf>,
    cwd: PathBuf,
    startup: std::sync::Arc<kin_mcp::StartupDaemonBinding>,
    init_served: bool,
) {
    // Name the repository being bound before the slow work starts, so the
    // still-starting report can say how far that daemon's startup has come.
    // The probe closure defers to the daemon-lifecycle IO boundary; this
    // module and the transport crate stay free of filesystem primitives.
    let discovered = kin_core::KinLayout::discover(&cwd);
    // Whether a repository existed here when this server started is the fact
    // that separates "the daemon went away" from "this server predates the
    // repository", and it is only knowable now. Recorded rather than inferred
    // later: once `kin init` has run, nothing on disk still says what the
    // launch directory looked like before it.
    kin_mcp::note_startup_repository(discovered.is_some());
    // Publish the operator pin now rather than when its daemon binds. The
    // workspace-roots binder reads it from this handle on the client's
    // `roots/list` answer, which on a cold repository now always arrives before
    // the bind settles, and a binder reading `false` would follow the client off
    // the repository `--repo`/`KIN_MCP_REPO` named. A pin that resolves to no
    // repository is still not a pin, which is why this is gated on discovery.
    if repo_override.is_some() && discovered.is_some() {
        startup.note_operator_pin();
    }
    if let Some(layout) = &discovered {
        let kin_root = layout.root().to_path_buf();
        startup.set_phase_probe(Box::new(move || {
            crate::daemon_client::daemon_startup_phase(&kin_root)
        }));
    }

    let unbound_reason = match bind_daemon_when_asked(&cwd, &startup).await {
        Ok(daemon_url) => {
            eprintln!("{}", session_authority_notice());
            eprintln!("Kin MCP: forwarding graph tools to repo daemon at {daemon_url}");
            let launch_dir = canonical_path(&cwd);
            let root = discovered
                .as_ref()
                .map(|layout| canonical_path(layout.working_dir()))
                .unwrap_or_else(|| launch_dir.clone());
            // Which repository answers, said once at startup, and said loudly
            // when it is not the folder this server was launched in: a folder
            // nested in another Kin repository is answered from that one.
            eprintln!("Kin MCP: serving the Kin repository at {}", root.display());
            if let Some(warning) =
                kin_mcp::first_contact::repository_identity(&root, Some(&launch_dir)).warning
            {
                eprintln!("Kin MCP: {warning}");
            }
            startup.resolve_bound(
                kin_mcp::BoundRepo { root, daemon_url },
                repo_override.is_some(),
            );
            return;
        }
        Err(reason) => {
            if !global {
                let init = kin_mcp::first_contact::kin_command(
                    "init .",
                    kin_mcp::first_contact::Spelling::here(),
                );
                // `kin_init` is a write, served only on a profile that writes.
                let set_up = if init_served {
                    format!("ask your agent to call kin_init, or run {init} in it")
                } else {
                    format!("run {init} in it")
                };
                eprintln!(
                    "Kin MCP: no repository bound at startup ({reason}). If the MCP client \
                     advertises workspace roots, Kin binds to the open repository after \
                     initialization. To set a folder up, {set_up}; or relaunch inside a Kin \
                     repository, or pass --repo <path> (or set KIN_MCP_REPO=<path>)."
                );
            } else {
                eprintln!("Kin MCP: the launch directory bound no repository ({reason}).");
            }
            reason
        }
    };

    // Registry mode: a launch directory that is no repository is the normal
    // case, not a failure. Resolve the startup repository from the global
    // registry instead, but never by guessing between several, which would
    // answer about a codebase nobody named.
    //
    // An operator pin that failed to bind is never rescued this way. Falling
    // through to the registry there would serve whichever repository the
    // registry happens to name while the operator asked for a specific one:
    // the same wrong-repository answer the roots binder refuses, reached
    // through the registry door instead.
    if registry_should_resolve(global, false, repo_override.is_some()) {
        if let Some(bound) = bind_from_registry(&startup).await {
            startup.resolve_bound(bound, false);
            return;
        }
    } else if global {
        if let Some(pinned) = &repo_override {
            eprintln!(
                "Kin MCP: --repo/KIN_MCP_REPO pins {}, which did not bind. Registry mode will not \
                 substitute another repository for a pin; fix the pinned repository or drop the \
                 pin.",
                pinned.display()
            );
        }
    }
    startup.resolve_unbound(unbound_reason);
}

// ── Tool profile ────────────────────────────────────────────────────────

/// Which tool surface this server exposes.
///
/// The curated agent belt is the default, and the whole surface is the opt-in.
/// It used to be the other way round, which meant the safe surface was
/// reachable only by going through `kin setup`: anything that wired MCP by hand
/// — a hand-written `.mcp.json`, a container entrypoint, a CI harness, another
/// tool spawning the server — silently received every tool the crate defines
/// and paid roughly twelve thousand extra tokens of schemas in every session,
/// with nothing saying a lighter profile existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpToolProfile {
    /// The curated belt every configured agent gets. The default.
    AgentDefault,
    /// The same belt with its write half removed: discovery and retrieval
    /// tools, no session and no transaction tools. A second served list for a
    /// client that only queries, not a mode: `AgentDefault` is unchanged and
    /// still serves every write tool.
    AgentQuery,
    /// The measured always-on set plus the tool search that reaches the rest.
    ///
    /// The smallest surface this binary serves and the first designed from
    /// measurement rather than from what a code-graph agent ought to want. It
    /// serves a small set plus discovery and invocation. `kin_tool_search`
    /// returns full schemas; `kin_tool_call` invokes hidden read-only operations
    /// through their normal checks. Mutations still require a direct tool.
    AgentSearch,
    /// One routed tool, `kin`, for a client that loads every tool it is handed
    /// and re-sends them all with every request: Codex CLI, Cursor, Gemini CLI,
    /// Windsurf, Antigravity and LM Studio. Its commands reach the belt's tools
    /// with that belt's defaults and envelope, writes included, so an eager
    /// client pays for one small tool definition per request instead of
    /// twenty-one, and `describe` and `call` reach every other tool.
    AgentRouted,
    /// `agent-routed` without a write path: the same one tool and commands,
    /// minus `session` and `mutate`, reaching only read-only tools.
    AgentRoutedQuery,
    /// The retrieval belt the benchmark arm drives.
    Benchmark,
    /// Read-only graph-native ContextBench belt: no write-side session or
    /// transaction tools, and no filesystem tools (there are none to expose).
    ContextBench,
    /// Every tool the crate defines. Explicit opt-in.
    Full,
}

/// The canonical token for each profile: what `KIN_MCP_TOOL_PROFILE` and
/// `--tool-profile` accept, in the order a help message should list them.
const TOOL_PROFILE_TOKENS: &[(&str, McpToolProfile)] = &[
    ("agent-default", McpToolProfile::AgentDefault),
    ("agent-query", McpToolProfile::AgentQuery),
    ("agent-search", McpToolProfile::AgentSearch),
    ("agent-routed", McpToolProfile::AgentRouted),
    ("agent-routed-query", McpToolProfile::AgentRoutedQuery),
    ("full", McpToolProfile::Full),
    ("benchmark", McpToolProfile::Benchmark),
    ("context-bench", McpToolProfile::ContextBench),
];

impl McpToolProfile {
    /// The tools this profile allows, or `None` for the unfiltered surface.
    pub(crate) fn allowed_tool_names(self) -> Option<&'static [&'static str]> {
        match self {
            Self::AgentDefault => Some(kin_mcp::agent_default_tool_names()),
            Self::AgentQuery => Some(kin_mcp::agent_query_tool_names()),
            Self::AgentSearch => Some(kin_mcp::agent_search_tool_names()),
            Self::AgentRouted | Self::AgentRoutedQuery => Some(kin_mcp::agent_routed_tool_names()),
            Self::Benchmark => Some(kin_mcp::benchmark_tool_names()),
            Self::ContextBench => Some(kin_mcp::context_bench_tool_names()),
            Self::Full => None,
        }
    }

    /// Whether this profile IS the curated agent belt: short descriptions,
    /// trimmed input schemas, and the compact `semantic_locate` shape.
    ///
    /// `agent-default`, `agent-query`, which is that belt with its write half
    /// removed, `agent-search`, which is the measured always-on slice of it, and
    /// the two routed profiles, which reach the belt through one tool: all of
    /// them serve the same short forms and defaults. `full` is the whole
    /// documented surface by definition. `benchmark` and `context-bench` keep
    /// the long forms and the shared payload because their bytes are an input
    /// to a citable result, and a benchmark number must not move because a
    /// description was rewritten or a payload was narrowed.
    pub(crate) fn is_agent_belt(self) -> bool {
        matches!(
            self,
            Self::AgentDefault
                | Self::AgentQuery
                | Self::AgentSearch
                | Self::AgentRouted
                | Self::AgentRoutedQuery
        )
    }

    /// The routed surface this profile serves, or `None` for a named one.
    pub(crate) fn routed_surface(self) -> Option<kin_mcp::routed::RoutedSurface> {
        match self {
            Self::AgentRouted => Some(kin_mcp::routed::RoutedSurface::WITH_WRITES),
            Self::AgentRoutedQuery => Some(kin_mcp::routed::RoutedSurface::READ_ONLY),
            _ => None,
        }
    }

    /// Whether this profile serves entity bodies with each line marked by its
    /// offset in the entity. Only the profiles with no Kin write path do, and a
    /// client that asks for exact bodies when it connects is served them anyway.
    pub(crate) fn numbers_entity_lines(self) -> bool {
        matches!(
            self,
            Self::AgentQuery | Self::AgentSearch | Self::AgentRoutedQuery
        )
    }

    /// Whether this profile's bytes are an input to a citable result.
    pub(crate) fn is_citable(self) -> bool {
        matches!(self, Self::Benchmark | Self::ContextBench)
    }

    /// Whether a client on this profile can write through Kin.
    #[cfg(test)]
    pub(crate) fn writes(self) -> bool {
        match self.routed_surface() {
            Some(surface) => surface.writes,
            None => kin_mcp::tools::serves_a_write_tool(
                self.allowed_tool_names()
                    .map(kin_mcp::tool_name_set)
                    .as_ref(),
            ),
        }
    }

    pub(crate) fn token(self) -> &'static str {
        TOOL_PROFILE_TOKENS
            .iter()
            .find(|(_, profile)| *profile == self)
            .map(|(token, _)| *token)
            .unwrap_or("agent-default")
    }

    /// How many tools this profile serves.
    fn tool_count(self) -> usize {
        match self.allowed_tool_names() {
            Some(names) => names.len(),
            None => kin_mcp::tool_definitions().tools.len(),
        }
    }
}

/// A resolved profile and how it was arrived at.
///
/// The source is carried rather than collapsed because an unconfigured server
/// and a misconfigured one must not report the same thing: the first is the
/// supported default, the second is a value nobody will otherwise notice was
/// ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedToolProfile {
    pub(crate) profile: McpToolProfile,
    pub(crate) source: ToolProfileSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolProfileSource {
    /// Nobody named a profile.
    Default,
    /// Named by `--tool-profile`.
    Flag,
    /// Named by `KIN_MCP_TOOL_PROFILE`.
    Env,
    /// A value was named and is not a profile. Carries what was asked for and
    /// where it came from, so the notice can quote it back.
    Unrecognized { origin: &'static str, value: String },
}

impl ResolvedToolProfile {
    /// One line on stderr at startup naming the surface actually being served.
    ///
    /// MCP stdio reserves stdout for the protocol, so this is the only channel
    /// available, and it is the whole point of the change: the previous default
    /// was invisible.
    pub(crate) fn startup_notice(&self) -> String {
        let profile = self.profile;
        let count = profile.tool_count();
        let token = profile.token();
        match &self.source {
            ToolProfileSource::Unrecognized { origin, value } => format!(
                "Kin MCP: {origin} requested tool profile '{value}', which is not a profile; \
                 serving the default '{token}' profile ({count} tools). Accepted profiles: {}.",
                accepted_tool_profiles()
            ),
            ToolProfileSource::Default => format!(
                "Kin MCP: serving the default '{token}' tool profile ({count} tools). Set \
                 KIN_MCP_TOOL_PROFILE=agent-query (or --tool-profile agent-query) for the same \
                 belt without the session and transaction tools ({} tools), which a \
                 query-only client re-sends in every prompt and never calls, \
                 KIN_MCP_TOOL_PROFILE=agent-search for the measured always-on set ({} tools) \
                 plus kin_tool_search and kin_tool_call for discovered operations, \
                 KIN_MCP_TOOL_PROFILE=agent-routed for one routed tool, for a client that \
                 sends every tool with every request, agent-routed-query for that tool without \
                 a write path, or KIN_MCP_TOOL_PROFILE=full for the complete {} tool surface; \
                 accepted profiles: {}.",
                McpToolProfile::AgentQuery.tool_count(),
                McpToolProfile::AgentSearch.tool_count(),
                McpToolProfile::Full.tool_count(),
                accepted_tool_profiles()
            ),
            ToolProfileSource::Flag => {
                format!("Kin MCP: serving the '{token}' tool profile ({count} tools) from --tool-profile.")
            }
            ToolProfileSource::Env => format!(
                "Kin MCP: serving the '{token}' tool profile ({count} tools) from \
                 KIN_MCP_TOOL_PROFILE."
            ),
        }
    }
}

/// Every profile token `kin mcp start` serves.
pub(crate) fn tool_profile_tokens() -> impl Iterator<Item = &'static str> {
    TOOL_PROFILE_TOKENS.iter().map(|(token, _)| *token)
}

/// Whether `value` names a profile `kin mcp start` serves, as its token.
pub(crate) fn is_tool_profile_token(value: &str) -> bool {
    TOOL_PROFILE_TOKENS.iter().any(|(token, _)| *token == value)
}

/// The profile a token names, or `None` for a value that is not one.
pub(crate) fn tool_profile_for_token(value: &str) -> Option<McpToolProfile> {
    TOOL_PROFILE_TOKENS
        .iter()
        .find(|(token, _)| *token == value)
        .map(|(_, profile)| *profile)
}

fn accepted_tool_profiles() -> String {
    TOOL_PROFILE_TOKENS
        .iter()
        .map(|(token, _)| *token)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolve the tool surface from an explicit flag, then the environment, then
/// the default.
///
/// A value nobody recognizes never silently becomes the full surface. That was
/// the shape of the original defect in miniature: an unnamed profile meant
/// "serve everything", so both an unconfigured server and a typo produced the
/// heavy surface with no signal. Now both land on the curated default and say
/// so.
pub(crate) fn resolve_tool_profile(flag: Option<&str>, env: Option<&str>) -> ResolvedToolProfile {
    for (origin, requested, source) in [
        ("--tool-profile", flag, ToolProfileSource::Flag),
        ("KIN_MCP_TOOL_PROFILE", env, ToolProfileSource::Env),
    ] {
        let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
            continue;
        };
        let lowered = requested.to_ascii_lowercase();
        return match TOOL_PROFILE_TOKENS
            .iter()
            .find(|(token, _)| *token == lowered)
        {
            Some((_, profile)) => ResolvedToolProfile {
                profile: *profile,
                source,
            },
            None => ResolvedToolProfile {
                profile: McpToolProfile::AgentDefault,
                source: ToolProfileSource::Unrecognized {
                    origin,
                    value: requested.to_string(),
                },
            },
        };
    }
    ResolvedToolProfile {
        profile: McpToolProfile::AgentDefault,
        source: ToolProfileSource::Default,
    }
}

/// Whether registry mode should resolve a startup repository.
///
/// Only in registry mode, only when nothing bound already, and never when an
/// operator pinned a repository: substituting a registry entry for a pin that
/// failed to bind is the wrong-repository answer the workspace-roots binder
/// refuses, reached through the registry door instead.
pub(crate) fn registry_should_resolve(global: bool, bound: bool, pinned: bool) -> bool {
    global && !bound && !pinned
}

/// What the global registry can offer as a startup repository.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RegistryStartupChoice {
    /// No repository has ever been registered on this host.
    NoneRegistered,
    /// Exactly one registered repository, so there is nothing to guess.
    Single(PathBuf),
    /// Several registered repositories and no basis for choosing one.
    Ambiguous(Vec<String>),
}

/// Choose a startup repository from the registry's recorded entries.
///
/// One registered repository is an unambiguous answer. Several is not: picking
/// the first would make the server answer about whichever repository happened
/// to sort or register first, which is precisely the wrong-repo failure the
/// roots binder exists to prevent. Ambiguity is reported so the caller can name
/// one, never resolved by guessing.
pub(crate) fn registry_startup_choice(
    registry: &kin_core::registry::KinRegistry,
) -> RegistryStartupChoice {
    match registry.repos.as_slice() {
        [] => RegistryStartupChoice::NoneRegistered,
        [only] => RegistryStartupChoice::Single(only.path.clone()),
        several => {
            let mut ids: Vec<String> = several.iter().map(|repo| repo.id.clone()).collect();
            ids.sort();
            RegistryStartupChoice::Ambiguous(ids)
        }
    }
}

/// Bind the startup repository from the global registry, reporting why when it
/// cannot. Returns the bound repository, or `None` when nothing bound.
async fn bind_from_registry(startup: &kin_mcp::StartupDaemonBinding) -> Option<kin_mcp::BoundRepo> {
    let registry = match kin_core::registry::KinRegistry::load() {
        Ok(registry) => registry,
        Err(error) => {
            eprintln!(
                "Kin MCP: registry mode could not read the Kin registry ({error}); tool calls \
                 will fail loud until a repository binds through --repo, KIN_MCP_REPO, or the \
                 client's workspace roots."
            );
            return None;
        }
    };

    match registry_startup_choice(&registry) {
        RegistryStartupChoice::NoneRegistered => {
            eprintln!(
                "Kin MCP: registry mode found no registered repositories, and no shipped command \
                 writes a registry entry. Pass --repo <path> (or set KIN_MCP_REPO=<path>) to \
                 serve a repository directly."
            );
            None
        }
        RegistryStartupChoice::Ambiguous(ids) => {
            eprintln!(
                "Kin MCP: registry mode found {} registered repositories and will not choose one \
                 for you ({}). Kin binds whichever the client advertises as a workspace root; to \
                 pin one now, pass --repo <path> or set KIN_MCP_REPO=<path>.",
                ids.len(),
                ids.join(", ")
            );
            None
        }
        RegistryStartupChoice::Single(path) => {
            // Retarget the still-starting report at the registry repository:
            // this is the daemon whose startup the report now describes.
            if let Some(layout) = kin_core::KinLayout::discover(&path) {
                let kin_root = layout.root().to_path_buf();
                startup.set_phase_probe(Box::new(move || {
                    crate::daemon_client::daemon_startup_phase(&kin_root)
                }));
            }
            match bind_daemon_when_asked(&path, startup).await {
                Ok(daemon_url) => {
                    // Match the roots path: the daemon delegate reads the
                    // per-install loopback token from <root>/.kin/daemon.token
                    // relative to the process working directory.
                    if let Err(err) = std::env::set_current_dir(&path) {
                        eprintln!(
                            "Kin MCP: bound {daemon_url} but could not switch cwd to {} ({err}); \
                             tool auth will fall back to KIN_DAEMON_AUTH_TOKEN if set.",
                            path.display()
                        );
                    }
                    eprintln!("{}", session_authority_notice());
                    eprintln!(
                        "Kin MCP: registry mode bound the only registered repository at {} (daemon \
                         {daemon_url})",
                        path.display()
                    );
                    Some(kin_mcp::BoundRepo {
                        root: canonical_path(&path),
                        daemon_url,
                    })
                }
                Err(reason) => {
                    eprintln!(
                        "Kin MCP: registry mode could not bind the only registered repository at {} \
                         ({reason}); tool calls will fail loud until one binds.",
                        path.display()
                    );
                    None
                }
            }
        }
    }
}

/// Bind — or re-bind — the repo daemon for the first workspace root that is a
/// Kin repository. Returns the bound repository and its daemon URL (and sets
/// `KIN_DAEMON_URL`), or `None` when none of the client's workspace roots is a
/// Kin repository whose daemon can be resolved.
///
/// Re-binding is the point as much as binding: an editor that moves its window
/// to another folder reports new roots, and a process that keeps its original
/// binding answers every later tool call from a repository the user has left.
/// When the roots still contain the bound repository this is a no-op that keeps
/// the running daemon; when they name a different one it repoints the process at
/// it; when the repositories they name cannot be served it reports
/// `OtherRepository`, which the stdio server turns into an explicit refusal.
///
/// Roots that resolve to no Kin repository at all are reported as
/// `Unresolvable`, which is a different fact and gets different treatment. This
/// process may be reached through `docker exec` or over a remote boundary, where
/// the client's roots are host paths that do not exist in this namespace: they
/// are not evidence that the client left the repository this server serves, and
/// a server that has one of its own keeps it.
///
/// `pinned_by_operator` marks a binding that came from an explicit
/// `--repo`/`KIN_MCP_REPO`. That pin is never repointed by the client — it is a
/// deliberate choice about which repository this server serves — so a workspace
/// that names a different repository fails loud instead of following the client
/// or, worse, answering from the pinned repository anyway.
async fn bind_first_kin_repo(
    roots: Vec<PathBuf>,
    pinned_by_operator: bool,
    mode: DaemonBindMode,
) -> kin_mcp::WorkspaceBinding {
    bind_first_kin_repo_against(roots, bound_repo_working_dir(), pinned_by_operator, mode).await
}

/// Core of [`bind_first_kin_repo`] with the currently bound repository as an
/// explicit input rather than a read of the process working directory, so the
/// same-repo/different-repo branch is testable without moving the cwd out from
/// under every other test in this binary.
async fn bind_first_kin_repo_against(
    roots: Vec<PathBuf>,
    bound_repo: Option<PathBuf>,
    pinned_by_operator: bool,
    mode: DaemonBindMode,
) -> kin_mcp::WorkspaceBinding {
    // `KinLayout::discover` is filesystem-rooted: it walks up from each root and
    // finds a `.kin/` or nothing, regardless of which daemon this process is
    // pinned to. A root that resolves to no layout is a root this server cannot
    // see, which is the distinction the two failure verdicts below rest on.
    let candidates: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| kin_core::KinLayout::discover(root))
        .map(|layout| canonical_path(layout.working_dir()))
        .collect();

    if candidates.is_empty() {
        // Nothing the client named resolves to a Kin repository this process can
        // see. That is what a host path looks like from inside a container, and
        // what a remote registration looks like from the server side, so it says
        // nothing about which repository this server should serve. The stdio
        // server decides whether its current binding has authority of its own.
        return kin_mcp::WorkspaceBinding::Unresolvable;
    }

    let bound_repo_still_open = bound_repo.as_deref().is_some_and(|bound| {
        candidates
            .iter()
            .any(|candidate| candidate.as_path() == bound)
    });

    if bound_repo_still_open {
        // The client still has the bound repository open — anywhere in its
        // workspace, not merely first. Keep the running daemon rather than
        // churning it because another folder happens to sort ahead of it.
        return match bound_repo.zip(current_daemon_url()) {
            Some((root, daemon_url)) => {
                kin_mcp::WorkspaceBinding::Bound(kin_mcp::BoundRepo { root, daemon_url })
            }
            // The bound repository is derived from the pinned daemon URL, so
            // losing the URL here means this process serves nothing the client
            // named after all.
            None => kin_mcp::WorkspaceBinding::OtherRepository(candidates),
        };
    }

    if pinned_by_operator {
        // An explicit --repo/KIN_MCP_REPO names a repository the client is not
        // looking at. Following the client would overrule a deliberate operator
        // choice; serving the pinned repository anyway would answer about a
        // codebase the client left. Report neither, and let the server refuse.
        eprintln!(
            "Kin MCP: the repository pinned by --repo/KIN_MCP_REPO is not among the client's \
             workspace roots; refusing tool calls until the workspace and the pin agree."
        );
        return kin_mcp::WorkspaceBinding::OtherRepository(candidates);
    }

    if bound_repo.is_some() {
        // The workspace moved off the bound repository. Drop the pin so daemon
        // resolution binds the new one instead of returning the one being left.
        // Deliberately not restored if binding fails below: falling back to the
        // previous repository is exactly the wrong-repo answer this path
        // prevents, so failure must leave the process unbound and failing loud.
        std::env::remove_var("KIN_DAEMON_URL");
    }

    for working_dir in candidates.iter() {
        // `mode` is the whole of this loop's part in FIR-3099. This binder runs
        // inline in the stdio loop, on the client's `roots/list` answer, which
        // arrives before the client has asked Kin anything. Attaching to a
        // daemon that is already serving is free; starting one is not, so
        // before the first `tools/call` a candidate with no running daemon is
        // skipped and reported as `OtherRepository`, which the server keeps and
        // puts through this binder again on that first call.
        let Ok(url) = bind_daemon_for_repo_dir(working_dir, mode).await else {
            continue;
        };
        // Point the process at the bound repo so the daemon delegate resolves
        // the per-install loopback auth token from <root>/.kin/daemon.token,
        // exactly as the --repo startup path does (it set_current_dir's first).
        // Without this, tool-call forwarding sends no bearer token and the
        // daemon replies 401 even though the repo bound correctly.
        if let Err(err) = std::env::set_current_dir(working_dir) {
            eprintln!(
                "Kin MCP: bound {url} but could not switch cwd to {} ({err}); \
                 tool auth will fall back to KIN_DAEMON_AUTH_TOKEN if set.",
                working_dir.display()
            );
        }
        eprintln!("{}", session_authority_notice());
        eprintln!(
            "Kin MCP: bound repo daemon at {url} from workspace root {}",
            working_dir.display()
        );
        return kin_mcp::WorkspaceBinding::Bound(kin_mcp::BoundRepo {
            root: working_dir.clone(),
            daemon_url: url,
        });
    }
    // The client named Kin repositories this process can see and none of their
    // daemons could be resolved. That is still a repository disagreement rather
    // than an invisible namespace, so the server refuses instead of serving the
    // repository the client left.
    kin_mcp::WorkspaceBinding::OtherRepository(candidates)
}

/// The repository this process is bound to, or `None` when it is not bound.
///
/// A binding exists only while a daemon URL is pinned, and the repository it
/// serves is the one containing the process working directory: every bind path
/// (`--repo`, `KIN_MCP_REPO`, the launch cwd, workspace roots) leaves the cwd
/// inside the bound repository. A `KIN_DAEMON_URL` pinned from outside while the
/// cwd is in no repository stays an explicit override — nothing to compare
/// roots against, so roots never repoint it.
fn bound_repo_working_dir() -> Option<PathBuf> {
    current_daemon_url()?;
    let cwd = std::env::current_dir().ok()?;
    kin_core::KinLayout::discover(&cwd).map(|layout| canonical_path(layout.working_dir()))
}

fn current_daemon_url() -> Option<String> {
    std::env::var("KIN_DAEMON_URL")
        .ok()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
}

/// Resolve symlinks so a client-supplied root and the process working directory
/// compare equal when they name the same repository (`/tmp` vs `/private/tmp`
/// on macOS, for one). Falls back to the path as given when it cannot be
/// canonicalized.
pub(crate) fn canonical_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// How this server's answers spell a `kin` command: `kin` when one is on the
/// PATH this server runs with, the `npx` form of this release when none is.
pub(crate) fn command_spelling() -> kin_mcp::first_contact::Spelling {
    if which::which("kin").is_ok() {
        kin_mcp::first_contact::Spelling::Kin
    } else {
        kin_mcp::first_contact::Spelling::Npx
    }
}

/// What `kin_init` runs: the checks an agent-driven setup needs, then `kin
/// init` itself. See [`crate::commands::init::initialize_for_mcp`].
fn repo_initializer() -> kin_mcp::RepoInitializer {
    std::sync::Arc::new(|dir: PathBuf| {
        Box::pin(crate::commands::init::initialize_for_mcp(dir))
            as Pin<Box<dyn Future<Output = kin_mcp::InitOutcome> + Send>>
    })
}

fn session_authority_notice() -> &'static str {
    "Kin daemon detected: MCP graph and session authority are daemon-centered; local fallback is disabled for this run."
}

fn build_mcp_start_config() -> kin_mcp::McpServerConfig {
    kin_mcp::McpServerConfig {
        session_authority_mode: kin_mcp::SessionAuthorityMode::DaemonRequired,
        snapshot_path: None,
        ..Default::default()
    }
}

/// The config `kin mcp start` serves `profile` under before a client
/// connects: the profile's tools, whether it is the agent belt, its routed
/// surface, whether it numbers entity lines, and whether it is citable.
///
/// `kin call` answers under the same config, so a shell's call is served
/// exactly as that profile's MCP client is.
pub(crate) fn served_config(profile: McpToolProfile) -> kin_mcp::McpServerConfig {
    let mut config = build_mcp_start_config();
    if let Some(names) = profile.allowed_tool_names() {
        config.allowed_tools = Some(
            names
                .iter()
                .map(|name| (*name).to_string())
                .collect::<HashSet<_>>(),
        );
    }
    config.agent_belt = profile.is_agent_belt();
    config.routed = profile.routed_surface();
    config.number_entity_lines = profile.numbers_entity_lines();
    config.citable = profile.is_citable();
    config
}

/// Resolve an explicit repository override for MCP startup: an explicit
/// `--repo` flag wins, then `KIN_MCP_REPO`. Returns `None` when neither is
/// set, in which case MCP binds whatever repository (if any) contains the
/// launching process's working directory — the pre-existing behavior for a
/// per-repo MCP entry.
///
/// This is the fix-shape the agent-global wiring case needs: a global agent
/// CLI MCP entry always launches with cwd at the session's project directory,
/// which is frequently not a Kin repository at all (an umbrella workspace
/// root, brownfield code before `kin init`, etc). Pointing that entry at
/// --repo/KIN_MCP_REPO lets it bind a specific repository regardless of cwd.
fn resolve_repo_override(repo_arg: Option<PathBuf>) -> Option<PathBuf> {
    repo_arg.or_else(|| std::env::var_os("KIN_MCP_REPO").map(PathBuf::from))
}

/// Resolve (autostarting if needed) the repo daemon for `dir` and pin
/// `KIN_DAEMON_URL` so the stdio server's per-call tool forwarding routes to
/// it. Returns a human-readable reason on failure instead of propagating a
/// hard error: `kin mcp start` must always reach the stdio loop so
/// `initialize`/`tools/list` succeed even when no repository is bound yet,
/// with individual `tools/call` requests failing loud instead.
async fn bind_daemon_for_repo_dir(
    dir: &Path,
    mode: DaemonBindMode,
) -> std::result::Result<String, BindRefusal> {
    if let Ok(url) = std::env::var("KIN_DAEMON_URL") {
        if !url.trim().is_empty() {
            return Ok(url);
        }
    }
    let layout = crate::commands::require_repository_layout_at(dir)
        .map_err(|refusal| BindRefusal::Reason(format!("{refusal:#}")))?;
    if mode == DaemonBindMode::AttachOnly {
        // Deliberately the resolver `kin doctor` reads from, not a second
        // opinion: it answers for a daemon that is already serving and starts
        // nothing. `None` here is not a failure, it is "a repository is here and
        // nobody is serving it yet", which is the state a session that has asked
        // for nothing is supposed to be left in.
        return match crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await {
            Some(url) => {
                std::env::set_var("KIN_DAEMON_URL", &url);
                Ok(url)
            }
            None => Err(BindRefusal::SpawnNotAdmitted),
        };
    }
    let url = crate::daemon_client::resolve_daemon_url_for_mcp(&layout)
        .await
        .map_err(|e| BindRefusal::Reason(format!("{e:#}")))?
        .ok_or_else(|| {
            BindRefusal::Reason(
                crate::daemon_client::daemon_required_error("MCP startup", &layout).to_string(),
            )
        })?;
    std::env::set_var("KIN_DAEMON_URL", &url);
    Ok(url)
}

/// Whether a bind may START a repo daemon or may only attach to one that is
/// already serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonBindMode {
    /// Bind a daemon already serving this repository. Start none.
    AttachOnly,
    /// Start a daemon when none is serving.
    SpawnIfNeeded,
}

impl DaemonBindMode {
    /// The mode a bind runs in, from whether a `tools/call` has admitted a
    /// spawn. Pure, so the rule is readable without a server.
    pub(crate) fn for_admission(spawn_admitted: bool) -> Self {
        if spawn_admitted {
            Self::SpawnIfNeeded
        } else {
            Self::AttachOnly
        }
    }
}

/// Why a bind produced no daemon URL.
///
/// The two are kept apart because they mean opposite things to a caller. A
/// reason is final for this bind's inputs and is what the operator is told. A
/// spawn that was not admitted is a state, not a failure: the repository is
/// there, nothing is serving it, and the same bind will succeed the moment
/// somebody asks Kin a question.
#[derive(Debug)]
pub(crate) enum BindRefusal {
    /// No daemon, and none can be had here. Carries the sentence to report.
    Reason(String),
    /// A Kin repository is here with no daemon serving it, and no caller has
    /// asked for a graph answer yet.
    SpawnNotAdmitted,
}

impl BindRefusal {
    /// The sentence a caller reports for this refusal.
    pub(crate) fn reason(self) -> String {
        match self {
            Self::Reason(reason) => reason,
            Self::SpawnNotAdmitted => {
                "no daemon is serving this repository yet and no tool call has asked for one"
                    .to_string()
            }
        }
    }
}

/// Bind the daemon for `dir`, attaching to a running one now and starting one
/// only once a `tools/call` has asked for a graph answer.
///
/// For the launcher's background binding task, which is the one place that has
/// somewhere to wait: the stdio loop keeps serving `initialize` and
/// `tools/list` the whole time this is parked. The workspace-roots binder runs
/// inside that loop and so cannot wait here; it asks the admission instead and
/// leaves its roots for the first tool call to retry.
async fn bind_daemon_when_asked(
    dir: &Path,
    startup: &kin_mcp::StartupDaemonBinding,
) -> std::result::Result<String, String> {
    match bind_daemon_for_repo_dir(dir, DaemonBindMode::AttachOnly).await {
        Ok(url) => return Ok(url),
        // Not a repository, or a repository whose daemon this process cannot
        // reach for a reason of its own. Neither improves by waiting.
        Err(BindRefusal::Reason(reason)) => return Err(reason),
        Err(BindRefusal::SpawnNotAdmitted) => {}
    }
    if crate::daemon_client::daemon_spawns_are_disabled() {
        // The probe contract. No tool call will ever start a daemon here, so
        // waiting for one to ask would leave this binding pending forever and
        // every call answered "the daemon is still starting" about a daemon
        // nothing will start. Settle now and let each call fail loud instead.
        return Err(
            "KIN_NO_DAEMON is set (or --no-spawn was passed) and no daemon is already \
             serving this repository, so this server binds none"
                .to_string(),
        );
    }
    startup.await_daemon_spawn_admission().await;
    bind_daemon_for_repo_dir(dir, DaemonBindMode::SpawnIfNeeded)
        .await
        .map_err(BindRefusal::reason)
}

#[cfg(test)]
mod tests {
    use super::{
        bind_daemon_for_repo_dir, bind_first_kin_repo_against, build_mcp_start_config,
        registry_should_resolve, registry_startup_choice, resolve_repo_override,
        resolve_tool_profile, session_authority_notice, BindRefusal, DaemonBindMode,
        McpToolProfile, RegistryStartupChoice, ToolProfileSource, TOOL_PROFILE_TOKENS,
    };
    use kin_core::registry::{KinRegistry, RegisteredRepo};
    use kin_core::test_env::EnvVarGuard;
    use serial_test::serial;
    use std::path::PathBuf;

    fn registered(id: &str, path: &str) -> RegisteredRepo {
        RegisteredRepo {
            id: id.to_string(),
            path: PathBuf::from(path),
            entities: 0,
            last_commit: "2026-01-01T00:00:00Z".to_string(),
            dependencies: Vec::new(),
            dependencies_recorded_by: None,
        }
    }

    fn registry(repos: Vec<RegisteredRepo>) -> KinRegistry {
        let mut registry = KinRegistry::default();
        registry.repos = repos;
        registry
    }

    #[test]
    fn daemon_available_notice_mentions_daemon_authority() {
        let message = session_authority_notice();
        assert!(message.contains("daemon-centered"));
        assert!(message.contains("disabled"));
    }

    /// Both sides. An unconfigured server serves the curated belt, and the
    /// whole surface is reachable only by asking for it.
    ///
    /// The counts are asserted against the profile lists themselves rather than
    /// against literals, so this stays true as tools are added; what it pins is
    /// the relationship, which is the thing that regressed: the default must be
    /// the small surface and `full` must be strictly larger.
    #[test]
    fn an_unconfigured_server_serves_the_curated_belt_and_full_is_the_opt_in() {
        let unconfigured = resolve_tool_profile(None, None);
        assert_eq!(unconfigured.profile, McpToolProfile::AgentDefault);
        assert_eq!(unconfigured.source, ToolProfileSource::Default);
        let served = unconfigured
            .profile
            .allowed_tool_names()
            .expect("the default profile must filter the surface");
        assert_eq!(served.len(), kin_mcp::agent_default_tool_names().len());

        let opted_in = resolve_tool_profile(None, Some("full"));
        assert_eq!(opted_in.profile, McpToolProfile::Full);
        assert_eq!(
            opted_in.profile.allowed_tool_names(),
            None,
            "the full surface must apply no allowlist at all"
        );
        assert!(
            kin_mcp::tool_definitions().tools.len() > served.len(),
            "the opt-in surface must be strictly larger than the default, or the default \
             is not saving anyone anything"
        );
    }

    /// "What breaks if I change this" is the product's flagship question, and
    /// the tool whose name says exactly that must be in the profile every agent
    /// receives.
    #[test]
    fn the_default_profile_carries_impact_analysis() {
        let served = resolve_tool_profile(None, None)
            .profile
            .allowed_tool_names()
            .expect("the default profile must filter the surface");
        assert!(
            served.contains(&"impact_analysis"),
            "impact_analysis must be in the profile an unconfigured agent gets: {served:?}"
        );
        // The tool has to exist to be servable; a profile naming a tool the
        // crate does not define would filter it away silently.
        let definitions = kin_mcp::tool_definitions();
        let defined: std::collections::HashSet<&str> = definitions
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        for name in served {
            assert!(
                defined.contains(name),
                "profile names undefined tool {name}"
            );
        }
    }

    #[test]
    fn an_explicit_flag_outranks_the_environment() {
        let resolved = resolve_tool_profile(Some("full"), Some("agent-default"));
        assert_eq!(resolved.profile, McpToolProfile::Full);
        assert_eq!(resolved.source, ToolProfileSource::Flag);
    }

    #[test]
    fn every_named_profile_resolves_to_its_own_surface() {
        let rows = [
            ("agent-default", McpToolProfile::AgentDefault),
            ("agent-query", McpToolProfile::AgentQuery),
            ("agent-search", McpToolProfile::AgentSearch),
            ("agent-routed", McpToolProfile::AgentRouted),
            ("agent-routed-query", McpToolProfile::AgentRoutedQuery),
            ("benchmark", McpToolProfile::Benchmark),
            ("context-bench", McpToolProfile::ContextBench),
            ("full", McpToolProfile::Full),
        ];
        // Written out AND counted. Without the count a profile added to
        // `TOOL_PROFILE_TOKENS` would ride in unnamed, and this loop would
        // report every token it happened to list.
        assert_eq!(
            rows.len(),
            TOOL_PROFILE_TOKENS.len(),
            "a profile joined the token table without a row here"
        );
        for (token, expected) in rows {
            let resolved = resolve_tool_profile(None, Some(token));
            assert_eq!(resolved.profile, expected, "for token {token}");
            assert_eq!(resolved.source, ToolProfileSource::Env);
            assert_eq!(resolved.profile.token(), token);
        }
        // Case and surrounding whitespace are a client config's business, not a
        // reason to serve a different surface than the one named.
        assert_eq!(
            resolve_tool_profile(None, Some("  Full ")).profile,
            McpToolProfile::Full
        );
        // An empty value is nobody naming anything, not a request.
        assert_eq!(
            resolve_tool_profile(None, Some("   ")).source,
            ToolProfileSource::Default
        );
    }

    /// A typo must not silently become the heavy surface — that was the old
    /// default's failure shape. It falls back to the curated belt and the
    /// notice quotes back what was asked for.
    #[test]
    fn an_unrecognized_profile_falls_back_loudly_rather_than_serving_everything() {
        let resolved = resolve_tool_profile(None, Some("agent_default"));
        assert_eq!(resolved.profile, McpToolProfile::AgentDefault);
        assert_eq!(
            resolved.source,
            ToolProfileSource::Unrecognized {
                origin: "KIN_MCP_TOOL_PROFILE",
                value: "agent_default".to_string(),
            }
        );
        let notice = resolved.startup_notice();
        assert!(notice.contains("agent_default"), "notice: {notice}");
        assert!(notice.contains("not a profile"), "notice: {notice}");
        assert!(
            notice.contains("full"),
            "notice must name the opt-in: {notice}"
        );
    }

    /// The startup line is the only channel this change has, since stdout
    /// belongs to the protocol, so an unconfigured server must announce what it
    /// is serving and both ways to ask for something else.
    #[test]
    fn the_default_startup_notice_names_the_surface_and_the_opt_ins() {
        let notice = resolve_tool_profile(None, None).startup_notice();
        assert!(notice.contains("agent-default"), "notice: {notice}");
        assert!(
            notice.contains("KIN_MCP_TOOL_PROFILE=full"),
            "notice: {notice}"
        );
        // The lighter surface is the one a query-only client wants and the one
        // nobody would guess exists. The default profile was invisible until
        // this line said so, and a second profile nobody is told about is the
        // same defect one profile along.
        assert!(
            notice.contains("KIN_MCP_TOOL_PROFILE=agent-query"),
            "notice must name the query-only surface: {notice}"
        );
        assert!(
            notice.contains(&kin_mcp::agent_default_tool_names().len().to_string()),
            "notice must state the served count: {notice}"
        );
        assert!(
            notice.contains(&format!(
                "({} tools)",
                kin_mcp::agent_query_tool_names().len()
            )),
            "notice must state what the query surface costs: {notice}"
        );
        // And the smallest surface, for the same reason: a profile nobody is
        // told about is the invisible default one profile along.
        assert!(
            notice.contains("KIN_MCP_TOOL_PROFILE=agent-search"),
            "notice must name the always-on surface: {notice}"
        );
        assert!(
            notice.contains(&format!(
                "({} tools)",
                kin_mcp::agent_search_tool_names().len()
            )),
            "notice must state what the search surface costs: {notice}"
        );
        assert!(
            notice.contains("KIN_MCP_TOOL_PROFILE=agent-routed"),
            "notice must name the routed surface: {notice}"
        );
    }

    /// The config `kin mcp start` builds for a resolved profile.
    fn config_for(profile: McpToolProfile) -> kin_mcp::McpServerConfig {
        let mut config = build_mcp_start_config();
        config.allowed_tools = profile.allowed_tool_names().map(kin_mcp::tool_name_set);
        config.agent_belt = profile.is_agent_belt();
        config.routed = profile.routed_surface();
        config.number_entity_lines = profile.numbers_entity_lines();
        config.citable = profile.is_citable();
        config
    }

    /// Both routed profiles serve the one routed tool, on the agent belt, so
    /// their commands get the belt's defaults and the procedure worded for
    /// them; `agent-routed` carries the writes and `agent-routed-query` does
    /// not.
    #[test]
    fn the_routed_profiles_serve_one_routed_tool_on_the_belt() {
        for (token, writes) in [("agent-routed", true), ("agent-routed-query", false)] {
            let resolved = resolve_tool_profile(Some(token), None);
            let profile = resolved.profile;
            assert_eq!(profile.token(), token);
            assert_eq!(
                profile.allowed_tool_names(),
                Some(&[kin_mcp::routed::TOOL_NAME][..])
            );
            assert!(profile.is_agent_belt());
            assert_eq!(profile.tool_count(), 1);
            assert_eq!(
                profile.routed_surface().map(|surface| surface.writes),
                Some(writes)
            );
            assert_eq!(profile.writes(), writes);
            let served = kin_mcp::server::served_tools_for(&config_for(profile));
            assert_eq!(served.tools.len(), 1);
            assert_eq!(served.tools[0].name, kin_mcp::routed::TOOL_NAME);
            assert_eq!(served.tools[0].annotations.read_only_hint, !writes);
            assert!(resolved.startup_notice().contains(&format!("'{token}'")));
        }
    }

    /// Numbering is a presentation for a client with no Kin write path: every
    /// profile that numbers serves no write, every profile that writes is
    /// served exact bodies, and only the citable profiles are citable.
    #[test]
    fn only_a_profile_without_a_write_path_numbers_entity_bodies() {
        for (_, profile) in TOOL_PROFILE_TOKENS {
            let profile = *profile;
            if profile.numbers_entity_lines() {
                assert!(
                    !profile.writes(),
                    "{} numbers bodies and writes",
                    profile.token()
                );
            }
            if profile.writes() {
                assert!(!profile.numbers_entity_lines(), "{}", profile.token());
            }
            let config = config_for(profile);
            assert_eq!(
                config.routed.is_some_and(|surface| surface.numbered),
                profile.routed_surface().is_some() && profile.numbers_entity_lines(),
                "{}: the routed surface and the connection disagree on numbering",
                profile.token()
            );
        }
        let numbered: Vec<&str> = TOOL_PROFILE_TOKENS
            .iter()
            .filter(|(_, profile)| profile.numbers_entity_lines())
            .map(|(token, _)| *token)
            .collect();
        assert_eq!(
            numbered,
            vec!["agent-query", "agent-search", "agent-routed-query"]
        );
        let citable: Vec<&str> = TOOL_PROFILE_TOKENS
            .iter()
            .filter(|(_, profile)| profile.is_citable())
            .map(|(token, _)| *token)
            .collect();
        assert_eq!(citable, vec!["benchmark", "context-bench"]);
    }

    /// The npm wrapper words its launch notice from its own copy of three facts
    /// this module owns: every profile `kin mcp start` accepts, the one it serves
    /// when none is named or the name is not a profile, and the profiles whose
    /// connection serves `kin_init`. A copy that drifted would have the notice
    /// send a user's agent to a tool the server does not list, or keep quiet
    /// about one it does, so the copies are read out of the wrapper's source and
    /// held to the registry here.
    #[test]
    fn the_npm_wrapper_agrees_on_which_profiles_serve_kin_init() {
        let wrapper = include_str!("../../../../packages/kin-mcp/src/index.js");
        let accepted: std::collections::BTreeSet<&str> = TOOL_PROFILE_TOKENS
            .iter()
            .map(|(token, _)| *token)
            .collect();
        let serving_init: std::collections::BTreeSet<&str> = TOOL_PROFILE_TOKENS
            .iter()
            .filter(|(_, profile)| config_for(*profile).serves_init())
            .map(|(token, _)| *token)
            .collect();
        // The rule is not vacuous: a profile that writes serves it and a
        // read-only one does not.
        assert!(serving_init.contains("agent-default"), "{serving_init:?}");
        assert!(
            !serving_init.contains("agent-routed-query"),
            "{serving_init:?}"
        );

        assert_eq!(
            wrapper_string_set(wrapper, "TOOL_PROFILES"),
            accepted,
            "packages/kin-mcp/src/index.js TOOL_PROFILES must list every profile `kin mcp \
             start` accepts"
        );
        assert_eq!(
            wrapper_string_set(wrapper, "PROFILES_SERVING_INIT"),
            serving_init,
            "packages/kin-mcp/src/index.js PROFILES_SERVING_INIT must list exactly the profiles \
             whose connection serves kin_init"
        );
        assert_eq!(
            wrapper_string_const(wrapper, "DEFAULT_TOOL_PROFILE"),
            resolve_tool_profile(None, None).profile.token(),
            "packages/kin-mcp/src/index.js DEFAULT_TOOL_PROFILE must be the profile `kin mcp \
             start` serves when none is named"
        );
    }

    /// The single-quoted strings inside `const <name> = new Set([ ... ]);` in the
    /// wrapper's source.
    fn wrapper_string_set<'a>(source: &'a str, name: &str) -> std::collections::BTreeSet<&'a str> {
        let opening = format!("const {name} = new Set([");
        let start = source
            .find(&opening)
            .unwrap_or_else(|| panic!("the wrapper declares no `{opening}`"))
            + opening.len();
        let body = &source[start..];
        let end = body
            .find("]);")
            .unwrap_or_else(|| panic!("the wrapper's {name} is never closed"));
        let values: std::collections::BTreeSet<&str> =
            body[..end].split('\'').skip(1).step_by(2).collect();
        assert!(!values.is_empty(), "the wrapper's {name} names nothing");
        values
    }

    /// The single-quoted string in `const <name> = '...';` in the wrapper's
    /// source.
    fn wrapper_string_const<'a>(source: &'a str, name: &str) -> &'a str {
        let opening = format!("const {name} = '");
        let start = source
            .find(&opening)
            .unwrap_or_else(|| panic!("the wrapper declares no `{opening}`"))
            + opening.len();
        let rest = &source[start..];
        &rest[..rest
            .find('\'')
            .unwrap_or_else(|| panic!("the wrapper's {name} is never closed"))]
    }

    /// A first launch of the npm wrapper answers `initialize` before `kin mcp
    /// start` exists, from the wrapper's own copy of the instructions each
    /// profile is served, and a client keeps the instructions it was first
    /// given for the whole session. So the copy is read out of the wrapper and
    /// held, profile by profile, to what this server answers `initialize` with
    /// on the config `kin mcp start` builds for that profile. The wrapper used
    /// to carry one string, the one only `benchmark` and `context-bench` are
    /// served, and hand it to every first launch.
    #[tokio::test]
    async fn a_first_launch_is_handed_the_instructions_its_profile_is_served() {
        let copy: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../packages/kin-mcp/src/server-instructions.json"
        ))
        .expect("the wrapper's instructions file is JSON");
        let texts = copy["instructions"]
            .as_object()
            .expect("the wrapper's instructions file carries its texts by name");
        let profiles = copy["profiles"]
            .as_object()
            .expect("the wrapper's instructions file names a text for each profile");
        let accepted: std::collections::BTreeSet<&str> = TOOL_PROFILE_TOKENS
            .iter()
            .map(|(token, _)| *token)
            .collect();
        assert_eq!(
            profiles
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            accepted,
            "packages/kin-mcp/src/server-instructions.json must name the instructions of every \
             profile `kin mcp start` accepts, and of no other"
        );

        let initialize = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "first-launch-pin", "version": "1" }
            }
        })
        .to_string();
        let mut handed_out = std::collections::BTreeSet::new();
        for (token, profile) in TOOL_PROFILE_TOKENS {
            let answer = kin_mcp::process_daemon_message(&initialize, &config_for(*profile))
                .await
                .expect("initialize is answered");
            let served = answer
                .result
                .as_ref()
                .and_then(|result| result.get("instructions"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| {
                    panic!("{token}: `kin mcp start` answered with no instructions")
                });
            let name = profiles[*token]
                .as_str()
                .unwrap_or_else(|| panic!("{token}: the wrapper names no text for it"));
            let copied = texts
                .get(name)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| {
                    panic!("{token}: the wrapper names {name} and carries no such text")
                });
            assert_eq!(
                copied, served,
                "{token}: a first launch hands out the wrapper's {name}, and `kin mcp start` \
                 answers this profile with other instructions; update \
                 packages/kin-mcp/src/server-instructions.json"
            );
            handed_out.insert(name);
        }
        // The pin is not vacuous: profiles are served different texts, and the
        // wrapper carries none that no profile is served.
        assert!(handed_out.len() > 1, "{handed_out:?}");
        assert_eq!(
            texts
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            handed_out,
            "the wrapper carries a text no profile is served"
        );
    }

    #[test]
    fn daemon_required_disables_local_snapshot_bootstrap() {
        let config = build_mcp_start_config();
        assert_eq!(
            config.session_authority_mode,
            kin_mcp::SessionAuthorityMode::DaemonRequired
        );
        assert!(config.snapshot_path.is_none());
    }

    /// Registry resolution is reached only in registry mode, only when nothing
    /// bound, and never over an operator pin. The pin row is the one that
    /// matters: rescuing a failed pin from the registry would serve a
    /// repository nobody named.
    #[test]
    fn registry_resolution_never_substitutes_for_an_operator_pin() {
        assert!(registry_should_resolve(true, false, false));
        assert!(
            !registry_should_resolve(true, false, true),
            "a pinned repository that did not bind must not be replaced from the registry"
        );
        assert!(!registry_should_resolve(true, true, false));
        assert!(!registry_should_resolve(false, false, false));
    }

    /// One registered repository is an unambiguous startup answer, which is
    /// what makes registry mode useful from a non-repository launch directory.
    #[test]
    fn registry_mode_binds_the_only_registered_repository() {
        assert_eq!(
            registry_startup_choice(&registry(vec![registered("kin", "/registered/kin")])),
            RegistryStartupChoice::Single(PathBuf::from("/registered/kin"))
        );
    }

    /// The wrong-repo failure the roots binder exists to prevent, reached
    /// through the registry instead. Several registered repositories must not
    /// collapse into "serve the first one".
    #[test]
    fn registry_mode_refuses_to_choose_between_registered_repositories() {
        let choice = registry_startup_choice(&registry(vec![
            registered("kin-vfs", "/registered/kin-vfs"),
            registered("kin", "/registered/kin"),
            registered("kin-db", "/registered/kin-db"),
        ]));

        assert_eq!(
            choice,
            RegistryStartupChoice::Ambiguous(vec![
                "kin".to_string(),
                "kin-db".to_string(),
                "kin-vfs".to_string(),
            ]),
            "ambiguity must be reported with every candidate named, in a stable order"
        );
    }

    /// An empty registry is its own case: nothing to bind and nothing to
    /// disambiguate, so the message must name registration as the remedy
    /// rather than pinning.
    #[test]
    fn registry_mode_reports_an_empty_registry_distinctly() {
        assert_eq!(
            registry_startup_choice(&registry(Vec::new())),
            RegistryStartupChoice::NoneRegistered
        );
    }

    #[test]
    #[serial]
    fn repo_override_prefers_explicit_flag_over_env() {
        let _guard = EnvVarGuard::set("KIN_MCP_REPO", "/env/path");
        let resolved = resolve_repo_override(Some(PathBuf::from("/flag/path")));
        assert_eq!(resolved, Some(PathBuf::from("/flag/path")));
    }

    #[test]
    #[serial]
    fn repo_override_falls_back_to_env_var() {
        let _guard = EnvVarGuard::set("KIN_MCP_REPO", "/env/path");
        let resolved = resolve_repo_override(None);
        assert_eq!(resolved, Some(PathBuf::from("/env/path")));
    }

    #[test]
    #[serial]
    fn repo_override_none_when_neither_flag_nor_env_set() {
        let _guard = EnvVarGuard::unset("KIN_MCP_REPO");
        assert_eq!(resolve_repo_override(None), None);
    }

    // Serialized against every other test that mutates the process-global
    // `KIN_DAEMON_URL` (its sibling below, and the init bootstrap test) so a
    // concurrent set/remove from another test can never be observed mid-body.
    #[tokio::test]
    #[serial]
    async fn bind_daemon_reports_missing_repo_without_hard_error() {
        // A directory with no .kin/ must produce an `Err` reason string for
        // the caller to log, never a panic or a process-killing error
        // propagated out of `start`.
        let _daemon_guard = EnvVarGuard::unset("KIN_DAEMON_URL");
        let tmp = tempfile::tempdir().unwrap();
        let reason = bind_daemon_for_repo_dir(tmp.path(), DaemonBindMode::SpawnIfNeeded)
            .await
            .expect_err("a directory with no .kin/ must not resolve a daemon")
            .reason();
        assert!(
            reason.contains("not a Kin repository"),
            "unexpected reason: {reason}"
        );
        assert!(
            reason.contains("kin init"),
            "the reason must name the remedy: {reason}"
        );
    }

    /// A directory that passes `KinLayout` discovery: a `.kin/` and nothing
    /// else, so nothing here can resolve a repo id or a running daemon.
    fn kin_repo_fixture() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".kin")).unwrap();
        tmp
    }

    fn expect_bound(binding: kin_mcp::WorkspaceBinding, context: &str) -> kin_mcp::BoundRepo {
        match binding {
            kin_mcp::WorkspaceBinding::Bound(bound) => bound,
            other => panic!("{context}, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn roots_naming_the_bound_repo_keep_the_running_daemon() {
        // A redundant roots change (same folder still open) must not tear down
        // or re-resolve the binding.
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let repo = kin_repo_fixture();
        let repo_dir = std::fs::canonicalize(repo.path()).unwrap();

        let bound = expect_bound(
            bind_first_kin_repo_against(
                vec![repo.path().to_path_buf()],
                Some(repo_dir.clone()),
                false,
                DaemonBindMode::SpawnIfNeeded,
            )
            .await,
            "the bound repository still being open must stay bound",
        );

        assert_eq!(bound.root, repo_dir);
        assert_eq!(bound.daemon_url, "http://127.0.0.1:4242");
        assert_eq!(
            std::env::var("KIN_DAEMON_URL").ok().as_deref(),
            Some("http://127.0.0.1:4242"),
            "a no-op roots change must leave the pinned daemon alone"
        );
    }

    #[tokio::test]
    #[serial]
    async fn switching_to_an_unresolvable_repo_never_falls_back_to_the_old_one() {
        // The wrong-repo failure mode in miniature: the client moved to another
        // repository whose daemon cannot be resolved. Binding must end up
        // unbound and report failure, never silently keep serving the previous
        // repository's daemon.
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        // No autostart: this test must never spawn a daemon process.
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let previous = kin_repo_fixture();
        let switched_to = kin_repo_fixture();

        let bound = bind_first_kin_repo_against(
            vec![switched_to.path().to_path_buf()],
            Some(std::fs::canonicalize(previous.path()).unwrap()),
            false,
            DaemonBindMode::SpawnIfNeeded,
        )
        .await;

        assert!(
            matches!(bound, kin_mcp::WorkspaceBinding::OtherRepository(_)),
            "a real repository whose daemon will not resolve is another repository, \
             not an unseeable root: {bound:?}"
        );
        assert_eq!(
            std::env::var("KIN_DAEMON_URL").ok().as_deref(),
            None,
            "the previous repository's daemon must not survive the switch"
        );
    }

    #[tokio::test]
    #[serial]
    async fn the_bound_repo_wins_wherever_it_sits_among_the_roots() {
        // A second folder opened alongside the bound one is not a switch. Root
        // order must not move a working binding.
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let other = kin_repo_fixture();
        let bound = kin_repo_fixture();
        let bound_dir = std::fs::canonicalize(bound.path()).unwrap();

        let result = expect_bound(
            bind_first_kin_repo_against(
                vec![other.path().to_path_buf(), bound.path().to_path_buf()],
                Some(bound_dir.clone()),
                false,
                DaemonBindMode::SpawnIfNeeded,
            )
            .await,
            "the bound repository being open anywhere must keep the binding",
        );

        assert_eq!(result.root, bound_dir);
        assert_eq!(result.daemon_url, "http://127.0.0.1:4242");
    }

    #[tokio::test]
    #[serial]
    async fn an_operator_pin_is_never_repointed_by_workspace_roots() {
        // --repo/KIN_MCP_REPO is a deliberate choice about which repository this
        // server serves. A roots change naming a different repository must
        // neither follow the client nor keep answering from the pin: it reports
        // failure so the stdio server refuses.
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let pinned = kin_repo_fixture();
        let other = kin_repo_fixture();

        let bound = bind_first_kin_repo_against(
            vec![other.path().to_path_buf()],
            Some(std::fs::canonicalize(pinned.path()).unwrap()),
            true,
            DaemonBindMode::SpawnIfNeeded,
        )
        .await;

        assert!(
            matches!(bound, kin_mcp::WorkspaceBinding::OtherRepository(_)),
            "a pinned server must report the workspace it does not serve as another \
             repository: {bound:?}"
        );
        assert_eq!(
            std::env::var("KIN_DAEMON_URL").ok().as_deref(),
            Some("http://127.0.0.1:4242"),
            "the operator's pin must survive a roots change it does not match"
        );
    }

    #[tokio::test]
    #[serial]
    async fn an_operator_pin_still_binds_when_the_roots_name_it() {
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let pinned = kin_repo_fixture();
        let pinned_dir = std::fs::canonicalize(pinned.path()).unwrap();

        let bound = expect_bound(
            bind_first_kin_repo_against(
                vec![pinned.path().to_path_buf()],
                Some(pinned_dir.clone()),
                true,
                DaemonBindMode::SpawnIfNeeded,
            )
            .await,
            "roots naming the pinned repository must stay bound",
        );

        assert_eq!(bound.root, pinned_dir);
        assert_eq!(bound.daemon_url, "http://127.0.0.1:4242");
    }

    #[tokio::test]
    #[serial]
    async fn roots_with_no_kin_repository_bind_nothing() {
        let _daemon_guard = EnvVarGuard::unset("KIN_DAEMON_URL");
        // No autostart: this test must never spawn a daemon process.
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let plain = tempfile::tempdir().unwrap();
        assert_eq!(
            bind_first_kin_repo_against(
                vec![plain.path().to_path_buf()],
                None,
                false,
                DaemonBindMode::SpawnIfNeeded,
            )
            .await,
            kin_mcp::WorkspaceBinding::Unresolvable,
        );
    }

    /// FIR-2405. A server registered as `docker exec -i -w /work/express ... kin
    /// mcp start` serves a container path while the client announces a host path
    /// that never exists in this namespace. Reporting that as a repository
    /// switch is what made every call after the first refuse: the root can never
    /// become bindable, so the refusal was permanent for the life of a process
    /// the client owns.
    #[tokio::test]
    #[serial]
    async fn a_root_this_server_cannot_see_is_unresolvable_not_another_repository() {
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        // No autostart: this test must never spawn a daemon process.
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let served = kin_repo_fixture();
        let served_dir = std::fs::canonicalize(served.path()).unwrap();
        // A path that exists on no filesystem this process can reach, standing
        // in for the client's host path.
        let host_namespace = tempfile::tempdir().unwrap();
        let host_only = host_namespace.path().join("private/tmp/brown/work");
        assert!(
            !host_only.exists(),
            "the stand-in host path must really be absent"
        );

        assert_eq!(
            bind_first_kin_repo_against(
                vec![host_only],
                Some(served_dir.clone()),
                false,
                DaemonBindMode::SpawnIfNeeded,
            )
            .await,
            kin_mcp::WorkspaceBinding::Unresolvable,
            "a root that resolves to no Kin repository here must not be reported as a switch"
        );

        // Falsification: the same call with a root this server CAN see, holding
        // a repository it does not serve, reports the switch it really is. The
        // verdict tracks what the filesystem says rather than always answering
        // `Unresolvable`.
        let other = kin_repo_fixture();
        let moved = bind_first_kin_repo_against(
            vec![other.path().to_path_buf()],
            Some(served_dir),
            false,
            DaemonBindMode::SpawnIfNeeded,
        )
        .await;
        assert!(
            matches!(moved, kin_mcp::WorkspaceBinding::OtherRepository(_)),
            "a visible second repository must be reported as another repository: {moved:?}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bind_daemon_short_circuits_on_explicit_daemon_url() {
        // When KIN_DAEMON_URL is already set (e.g. by a supervising session),
        // binding must trust it directly rather than requiring a local .kin/
        // — this is the existing multi-process pinning contract and must
        // survive the lazy-binding rework unchanged.
        let _guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let tmp = tempfile::tempdir().unwrap();
        let url = bind_daemon_for_repo_dir(tmp.path(), DaemonBindMode::SpawnIfNeeded)
            .await
            .expect("an explicit KIN_DAEMON_URL must be trusted without repo discovery");
        assert_eq!(url, "http://127.0.0.1:4242");
    }

    /// FIR-3099, at the seam that decides it. Whether a bind may start a daemon
    /// is a function of one thing: whether a caller has asked for a graph
    /// answer. Both directions, because a mode that is always `SpawnIfNeeded`
    /// would pass a test that only checked the admitted case.
    #[test]
    fn only_an_admitted_spawn_lets_a_bind_start_a_daemon() {
        assert_eq!(
            DaemonBindMode::for_admission(false),
            DaemonBindMode::AttachOnly,
            "before a tool call a bind must attach to a running daemon and start none"
        );
        assert_eq!(
            DaemonBindMode::for_admission(true),
            DaemonBindMode::SpawnIfNeeded,
            "once a caller has asked for a graph answer the bind must be able to start one"
        );
    }

    /// A repository with no daemon yet is a state, not a failure, and the two
    /// must not collapse into one message. The operator-facing sentence belongs
    /// to a bind that genuinely cannot produce a daemon.
    #[tokio::test]
    #[serial]
    async fn an_unadmitted_spawn_refuses_without_claiming_the_repository_is_broken() {
        let _daemon_guard = EnvVarGuard::unset("KIN_DAEMON_URL");
        let repo = kin_repo_fixture();
        let refusal = bind_daemon_for_repo_dir(repo.path(), DaemonBindMode::AttachOnly)
            .await
            .expect_err("no daemon is running for a fresh fixture, and none may be started");
        assert!(
            matches!(refusal, BindRefusal::SpawnNotAdmitted),
            "an attach-only bind over a real repository with no daemon must report the \
             unadmitted spawn, not a reason: {refusal:?}"
        );
        assert!(
            std::env::var("KIN_DAEMON_URL")
                .map(|url| url.trim().is_empty())
                .unwrap_or(true),
            "an attach-only bind that found no daemon must not pin a daemon URL"
        );
    }
}
