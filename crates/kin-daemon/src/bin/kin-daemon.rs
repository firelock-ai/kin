// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashSet;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
use std::env;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use kin_core::KinLayout;
use kin_daemon::{acquire_daemon_authority, DaemonConfig, DaemonState};
use tracing_subscriber::EnvFilter;

kin_buildinfo::embed_update_build_identity!(
    KIN_UPDATE_BUILD_IDENTITY,
    env!("CARGO_PKG_VERSION"),
    kin_db::GraphSnapshot::CURRENT_VERSION
);

/// Storage mode for graph snapshots.
#[derive(Debug, Clone, PartialEq)]
enum StorageMode {
    /// Local filesystem (default for developer machines).
    Local,
    /// GCS object storage (for cloud deployment).
    /// Requires KIN_GCS_BUCKET env var.
    #[cfg(feature = "gcs")]
    Gcs,
}

struct Args {
    repo: PathBuf,
    port: u16,
    storage: StorageMode,
    /// Repo identifier for StorageBackend (defaults to the manifest repo_id).
    repo_id: Option<String>,
    /// Run the central local supervisor instead of a repo graph daemon.
    supervisor: bool,
    /// Print daemon/graph compatibility metadata and exit.
    compat_json: bool,
}

fn usage(program: &str) {
    eprintln!(
        "Usage:\n  {program} [--repo <path>] [--port <port>] [--storage local|gcs] [--repo-id <id>]\n  {program} --supervisor [--port <port>]\n  {program} --compat-json\n\n\
         Defaults:\n  --repo     current working directory\n  --port     4219\n  --storage  local (or KIN_STORAGE env var)\n  --repo-id  repo_id from --repo/.kin/manifest.json"
    );
    eprintln!(
        "\nEnvironment:\n  KIN_DAEMON_BIND_HOST   daemon bind address (default 127.0.0.1)\n  KIN_DAEMON_AUTH_TOKEN  bearer token required for non-public daemon routes\n  KIN_REPO_ID            explicit repo_id override for tests/bench flows"
    );
    eprintln!("  KIN_DAEMON_IDLE_TIMEOUT_SECS  optional idle shutdown timeout; 0 disables");
    eprintln!(
        "  KIN_SUPERVISOR_IDLE_TIMEOUT_SECS  optional supervisor idle shutdown timeout; 0 disables"
    );
}

fn parse_args() -> Result<Args, String> {
    let mut repo = env::current_dir().map_err(|error| error.to_string())?;
    let mut port = 4219_u16;
    let mut storage_str: Option<String> = None;
    let mut repo_id: Option<String> = None;
    let mut supervisor = false;
    let mut compat_json = false;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--supervisor" | "--central" => {
                supervisor = true;
            }
            "--compat-json" => {
                compat_json = true;
            }
            "--repo" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--repo requires a path".to_string())?;
                repo = PathBuf::from(value);
            }
            "--port" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--port requires a value".to_string())?;
                port = value
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port: {value}"))?;
            }
            "--storage" => {
                storage_str = Some(
                    args.next()
                        .ok_or_else(|| "--storage requires a value (local or gcs)".to_string())?,
                );
            }
            "--repo-id" => {
                repo_id = Some(
                    args.next()
                        .ok_or_else(|| "--repo-id requires a value".to_string())?,
                );
            }
            "--version" | "-V" => {
                println!("{}", kin_buildinfo::version_line("kin-daemon"));
                process::exit(0);
            }
            "--help" | "-h" => {
                usage(
                    &env::args()
                        .next()
                        .unwrap_or_else(|| "kin-daemon".to_string()),
                );
                process::exit(0);
            }
            other => {
                return Err(format!("unrecognized argument: {other}"));
            }
        }
    }

    // Resolve storage mode: CLI flag > env var > default (local)
    let storage_val = storage_str
        .or_else(|| env::var("KIN_STORAGE").ok())
        .unwrap_or_else(|| "local".to_string());

    let storage = match storage_val.as_str() {
        "local" => StorageMode::Local,
        #[cfg(feature = "gcs")]
        "gcs" => StorageMode::Gcs,
        #[cfg(not(feature = "gcs"))]
        "gcs" => {
            return Err(
                "GCS storage requires the 'gcs' feature. Rebuild with --features gcs".to_string(),
            );
        }
        other => {
            return Err(format!(
                "unknown storage mode: {other} (expected local or gcs)"
            ));
        }
    };

    Ok(Args {
        repo,
        port,
        storage,
        repo_id,
        supervisor,
        compat_json,
    })
}

/// The `allowed_repo_ids` key space a storage mode hands `DaemonState`, refusing
/// any configuration whose key space excludes the repository being served.
///
/// The daemon takes its identity from two independent sources: the served
/// repo id (`--repo-id`, `KIN_REPO_ID`, or the manifest) and, in GCS mode, the
/// allowlist (`KIN_REPO_IDS`). Nothing reconciled them, and
/// `DaemonState::serves_repo_id` answers from the allowlist alone whenever one
/// is configured. An allowlist that omits the served id therefore produced a
/// daemon that advertised that id on `GET /health` and refused it on every
/// `/repos/{repo_id}` route: a live process whose two identity surfaces
/// contradict each other, with no request able to tell which one is right.
///
/// There is no reading of that configuration under which the daemon can serve
/// correctly, so it refuses to start rather than admitting the served id behind
/// the operator's back. Silently widening the allowlist would serve a
/// repository the operator explicitly did not list, which is the opposite
/// failure and a worse one in a hosted multi-tenant pod.
fn served_repo_key_space(
    storage: &StorageMode,
    repo_id: &str,
) -> std::result::Result<Option<HashSet<String>>, String> {
    let configured: Option<HashSet<String>> = match storage {
        // Local mode has no allowlist source: the served key space is the
        // repository authority the daemon opened, so the advertised id is
        // routable by construction.
        StorageMode::Local => None,
        #[cfg(feature = "gcs")]
        StorageMode::Gcs => parse_allowed_repo_ids(),
    };
    match configured {
        Some(allowed) if !allowed.contains(repo_id) => {
            let mut listed: Vec<&str> = allowed.iter().map(String::as_str).collect();
            listed.sort_unstable();
            Err(format!(
                "KIN_REPO_IDS does not list the repository this daemon serves. \
                 Serving repo_id {repo_id}; KIN_REPO_IDS allows [{}]. \
                 This daemon would advertise {repo_id} on GET /health and then refuse \
                 it on every /repos/{repo_id} route. Add {repo_id} to KIN_REPO_IDS, or \
                 unset KIN_REPO_IDS to serve every repository the backend holds.",
                listed.join(", ")
            ))
        }
        admitted => Ok(admitted),
    }
}

fn create_state(
    layout: KinLayout,
    storage: &StorageMode,
    repo_id: &str,
    #[cfg_attr(not(feature = "gcs"), allow(unused_variables))] allowed_repo_ids: Option<
        HashSet<String>,
    >,
) -> std::result::Result<DaemonState, Box<dyn std::error::Error>> {
    match storage {
        StorageMode::Local => Ok(DaemonState::open_with_repo_id(layout, Some(repo_id))?),
        #[cfg(feature = "gcs")]
        StorageMode::Gcs => {
            let bucket = env::var("KIN_GCS_BUCKET")
                .map_err(|_| "KIN_GCS_BUCKET env var required for --storage gcs")?;
            let prefix = env::var("KIN_GCS_PREFIX").unwrap_or_default();
            let backend = kin_db::GcsBackend::new(&bucket, prefix)?;
            Ok(DaemonState::open_with_backend(
                layout,
                Box::new(backend),
                repo_id,
                allowed_repo_ids,
            )?)
        }
    }
}

fn acquire_before_state<T>(
    kin_root: &Path,
    acquire: impl FnOnce(&Path) -> kin_daemon::Result<kin_daemon::lifecycle::DaemonLock>,
    create: impl FnOnce() -> std::result::Result<T, Box<dyn std::error::Error>>,
) -> std::result::Result<(T, kin_daemon::lifecycle::DaemonLock), Box<dyn std::error::Error>> {
    let authority =
        acquire(kin_root).map_err(|error| Box::new(error) as Box<dyn std::error::Error>)?;
    let state = create()?;
    Ok((state, authority))
}

#[cfg(feature = "gcs")]
fn parse_repo_id_list() -> Vec<String> {
    env::var("KIN_REPO_IDS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(feature = "gcs")]
fn parse_allowed_repo_ids() -> Option<HashSet<String>> {
    let values: HashSet<String> = parse_repo_id_list().into_iter().collect();
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn resolve_layout(path: &Path) -> Option<KinLayout> {
    if path.file_name().and_then(|name| name.to_str()) == Some(".kin") && path.is_dir() {
        return Some(KinLayout::new(path.to_path_buf()));
    }
    KinLayout::discover(path)
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

fn idle_timeout_from_env() -> Result<Option<Duration>, String> {
    let Some(raw) = env::var("KIN_DAEMON_IDLE_TIMEOUT_SECS").ok() else {
        return Ok(Some(Duration::from_secs(3600))); // Default to 1 hour auto-cleanup
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return Ok(None);
    }
    let seconds = trimmed
        .parse::<u64>()
        .map_err(|_| format!("invalid KIN_DAEMON_IDLE_TIMEOUT_SECS: {trimmed}"))?;
    Ok(Some(Duration::from_secs(seconds)))
}

fn supervisor_idle_timeout_from_env() -> Result<Option<Duration>, String> {
    let Some(raw) = env::var("KIN_SUPERVISOR_IDLE_TIMEOUT_SECS").ok() else {
        return Ok(Some(Duration::from_secs(3600))); // Default to 1 hour auto-cleanup
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return Ok(None);
    }
    let seconds = trimmed
        .parse::<u64>()
        .map_err(|_| format!("invalid KIN_SUPERVISOR_IDLE_TIMEOUT_SECS: {trimmed}"))?;
    Ok(Some(Duration::from_secs(seconds)))
}

fn embed_batch_size_from_env() -> Result<Option<usize>, String> {
    let Some(raw) = env::var("KIN_DAEMON_EMBED_BATCH_SIZE").ok() else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let size = trimmed
        .parse::<usize>()
        .map_err(|_| format!("invalid KIN_DAEMON_EMBED_BATCH_SIZE: {trimmed}"))?;
    if size == 0 {
        return Err("invalid KIN_DAEMON_EMBED_BATCH_SIZE: must be > 0".to_string());
    }
    Ok(Some(size))
}

fn main() {
    match kin_daemon_spawn::run_process_group_guardian_if_requested() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("kin-daemon: process-group guardian failed: {error}");
            process::exit(1);
        }
    }

    kin_buildinfo::retain_update_build_identity(&KIN_UPDATE_BUILD_IDENTITY);
    // Build the async runtime explicitly (rather than via `#[tokio::main]`) so
    // we own its teardown. The embedding worker dispatches batches onto the
    // blocking pool doing synchronous GPU compute that cannot observe the
    // shutdown signal; a plain runtime drop would wait for an in-flight batch
    // *indefinitely*, leaving a headless, SIGTERM-immune CPU zombie still
    // racing kvec writes. Bounding teardown here is what lets the process exit.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("kin-daemon: failed to build async runtime: {error}");
            process::exit(1);
        }
    };

    let exit_code = runtime.block_on(async_main());

    // `block_on` has returned (graceful shutdown released the lock + endpoint
    // files), but a blocking embed batch may still be running. `shutdown_timeout`
    // waits a bounded grace period for the blocking pool to drain, then abandons
    // anything still running so we don't hang here…
    runtime.shutdown_timeout(kin_daemon::daemon::runtime_shutdown_grace());
    // …and we exit explicitly to terminate the whole process — including any
    // blocking thread that was abandoned above. SIGTERM always ends in real
    // termination; no zombie survives.
    process::exit(exit_code);
}

/// Exact test-harness entrypoint for the shared process-group guardian.
#[cfg(all(test, unix))]
#[test]
fn kin_process_group_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = kin_daemon_spawn::run_process_group_guardian_if_requested()
        .expect("run daemon binary process-group guardian worker");
    assert_eq!(dispatched, requested);
}

/// Default tracing directive when `RUST_LOG` is unset.
///
/// `info` so first-run daemon and supervisor lifecycle logs actually land in the
/// daemon/supervisor log files. A bare `tracing_subscriber::fmt::init()` derives
/// its default from `RUST_LOG` and admits no info-level events when it is unset,
/// which left the log files empty and first-run failures undiagnosable.
const DEFAULT_LOG_DIRECTIVE: &str = "info";

/// Tracing filter for the daemon/supervisor process: honor `RUST_LOG` when set,
/// otherwise fall back to [`DEFAULT_LOG_DIRECTIVE`].
fn daemon_env_filter() -> EnvFilter {
    if env::var_os("RUST_LOG").is_some() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(DEFAULT_LOG_DIRECTIVE)
    }
}

fn init_tracing() {
    // Logs go to stderr: stdout is a protocol surface (`--compat-json` emits
    // machine-read JSON there), and any log line on stdout corrupts it —
    // an env-registry override warning printed before the compat payload
    // makes the CLI's compat probe report the daemon binary as stale.
    tracing_subscriber::fmt()
        .with_env_filter(daemon_env_filter())
        .with_writer(std::io::stderr)
        .init();
}

async fn async_main() -> i32 {
    let program = env::args()
        .next()
        .unwrap_or_else(|| "kin-daemon".to_string());
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("kin-daemon: {error}");
            usage(&program);
            process::exit(1);
        }
    };

    // The CLI's daemon-compat probe runs `kin-daemon --compat-json` and parses
    // this process's stdout as JSON. Emit that payload before installing the
    // tracing subscriber (whose default writer is stdout) or running startup env
    // validation, so no log line — e.g. a KIN_* override warning — can precede
    // the JSON and be misread as a stale/incompatible daemon. A compat probe is
    // a pure metadata query needing neither logging nor env enforcement.
    if args.compat_json {
        let build = kin_buildinfo::get();
        println!(
            "{}",
            serde_json::json!({
                "schema": "kin.daemon.compat.v2",
                "version": env!("CARGO_PKG_VERSION"),
                "graph_snapshot_version": kin_db::GraphSnapshot::CURRENT_VERSION,
                "supervisor_startup_protocol": 2,
                "supervisor_startup_capabilities": [
                    "generation-adoption-ack-v2",
                    "legacy-directory-sentinel-v1",
                    "bounded-legacy-rollback-v1",
                ],
                "build": {
                    "sha": build.sha,
                    "dirty": build.dirty,
                    "source_known": build.source_known,
                    "dependency_provenance": build.dependency_provenance,
                    "branch": build.branch,
                    "built_at": build.built_at,
                },
            })
        );
        return 0;
    }

    init_tracing();

    // Validate the KIN_* environment surface at startup: unknown names and
    // out-of-range values are surfaced loudly; an invalid correctness-relevant
    // value refuses to boot. Governed by KIN_ENV_VALIDATION (off/warn/strict).
    if let Err(err) = kin_core::env_registry::enforce_startup_env() {
        eprintln!("kin-daemon: {err}");
        return 2;
    }

    // Resident serving daemon: profile-driven retrieval defaults that assume
    // model residency (cross-encoder rerank) may apply in this process.
    kin_cli::retrieval_profile::mark_daemon_serving();

    if args.supervisor {
        let idle_timeout = match supervisor_idle_timeout_from_env() {
            Ok(timeout) => timeout,
            Err(error) => {
                eprintln!("kin-daemon: {error}");
                process::exit(1);
            }
        };
        if let Err(error) = kin_daemon::supervisor::run_supervisor(args.port, idle_timeout).await {
            eprintln!("kin-daemon supervisor: {error}");
            return 1;
        }
        return 0;
    }

    let layout = match resolve_layout(&args.repo) {
        Some(layout) => layout,
        None => {
            eprintln!(
                "kin-daemon: no .kin directory found from {}",
                args.repo.display()
            );
            process::exit(1);
        }
    };

    let explicit_repo_id = args.repo_id.or_else(|| env::var("KIN_REPO_ID").ok());
    let repo_id = match kin_core::manifest::resolve_repo_id(&layout, explicit_repo_id.as_deref()) {
        Ok(repo_id) => repo_id,
        Err(error) => {
            eprintln!("kin-daemon: failed to resolve repo id: {error}");
            process::exit(1);
        }
    };

    // Reconcile the served identity with the configured key space before taking
    // the repository singleton lock. A daemon that cannot serve the id it will
    // advertise has nothing to contend for, and refusing here keeps the operator
    // message about the misconfiguration itself rather than wrapping it in a
    // failure to open state.
    // Exit 2, the same code `enforce_startup_env` uses: this is one more
    // correctness-relevant KIN_* value refusing to boot, not a runtime failure.
    let allowed_repo_ids = match served_repo_key_space(&args.storage, &repo_id) {
        Ok(allowed_repo_ids) => allowed_repo_ids,
        Err(error) => {
            eprintln!("kin-daemon: {error}");
            return 2;
        }
    };

    let kin_root = layout.root().to_path_buf();
    // Bind, publish, and start answering BEFORE opening state.
    //
    // Opening state reads and re-verifies the whole durable publication, which
    // is proportional to repository size. Binding after it meant every client
    // arriving during that window got a connection refusal and no endpoint file
    // to find, so first contact on a large repository looked like a dead daemon.
    // Binding first turns that into an answered "not ready yet".
    //
    // It runs INSIDE `acquire_before_state`'s create step, so singleton
    // authority is already held: a daemon that lost the race must never bind the
    // port it would then have to give up.
    //
    // The ENDPOINT is deliberately still published later, after state opens.
    // Publishing it here is what would let a client find and use this daemon
    // during the open window, and the client does not gate its commands on
    // `/readiness` yet — it gates only its spawn-wait — so it would send a real
    // command and take the readiness refusal as a failed command rather than as
    // "not yet". Moving publication earlier belongs with the client half; until
    // then this closes the refusal window for anyone who already knows the port
    // without advertising a daemon that cannot answer commands.
    let bind_port = args.port;
    let bind_layout = layout.clone();
    let storage = args.storage.clone();
    let runtime = tokio::runtime::Handle::current();
    let opened = tokio::task::spawn_blocking(move || {
        acquire_before_state(&kin_root, acquire_daemon_authority, move || {
            let (warming_listener, api_listener, bound_port) =
                kin_daemon::api::bind_api_listener_pair(&bind_layout, bind_port)?;
            let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
            // The readiness surface runs on the async runtime while this thread
            // blocks in the open. That split is the whole mechanism: a warming
            // answer is only possible because the load is not on the reactor.
            runtime.spawn(kin_daemon::api::serve_warming_until(
                warming_listener,
                ready_rx,
            ));
            // A failed open drops both handles here, which closes the socket. No
            // endpoint was published for it, so nothing outlives the failure.
            let state = create_state(bind_layout, &storage, &repo_id, allowed_repo_ids)?;
            Ok((state, api_listener, bound_port, ready_tx))
        })
        // The boxed startup error is not `Send`, and this result crosses back
        // off the blocking thread. Its text is the whole of what the caller
        // does with it.
        .map_err(|error| error.to_string())
    })
    .await;
    let opened = opened
        .map_err(|error| format!("daemon startup task failed: {error}"))
        .and_then(|inner| {
            inner.map_err(|error| {
                format!("failed to acquire daemon authority or open state: {error}")
            })
        });
    let ((state, api_listener, bound_port, ready_tx), authority) = match opened {
        Ok(opened) => opened,
        Err(message) => {
            eprintln!("kin-daemon: {message}");
            process::exit(1);
        }
    };

    let embed_batch_size = match embed_batch_size_from_env() {
        Ok(explicit) => {
            let resource_profile = env::var("KIN_RESOURCE_PROFILE").ok();
            kin_cli::commands::resources::resolve_embed_batch_size(
                explicit,
                resource_profile.as_deref(),
                DaemonConfig::default().embed_batch_size,
                kin_cli::commands::resources::throughput_embed_batch_size,
            )
        }
        Err(error) => {
            eprintln!("kin-daemon: {error}");
            process::exit(1);
        }
    };

    let embed_pipeline_overlap = kin_cli::commands::resources::embed_pipeline_overlap_default(
        env::var("KIN_RESOURCE_PROFILE").ok().as_deref(),
    );

    let config = DaemonConfig {
        api_port: args.port,
        lsp_enabled: !env_flag("KIN_DAEMON_DISABLE_LSP"),
        idle_timeout: match idle_timeout_from_env() {
            Ok(timeout) => timeout,
            Err(error) => {
                eprintln!("kin-daemon: {error}");
                process::exit(1);
            }
        },
        embed_batch_size,
        embed_pipeline_overlap,
        ..DaemonConfig::default()
    };

    if let Err(error) = kin_daemon::daemon::run_with_authority_on(
        state,
        config,
        authority,
        Some(kin_daemon::daemon::PreboundApi {
            listener: api_listener,
            port: bound_port,
            ready_tx,
        }),
    )
    .await
    {
        eprintln!("kin-daemon: {error}");
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::fmt::MakeWriter;

    /// A `MakeWriter` that appends everything the subscriber emits into a shared
    /// buffer — stands in for the daemon/supervisor log file the spawn code wires
    /// the process's stdout/stderr to.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    #[test]
    fn singleton_authority_is_acquired_before_state_construction() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let first = kin_daemon::lifecycle::acquire_singleton_lock(root)
            .expect("first lock IO")
            .expect("first starter must own the repo");
        let state_constructor_called = AtomicBool::new(false);

        let opened = acquire_before_state(
            root,
            |root| kin_daemon::daemon::acquire_daemon_authority_within(root, Duration::ZERO),
            || {
                state_constructor_called.store(true, Ordering::SeqCst);
                Ok::<_, Box<dyn std::error::Error>>(())
            },
        );

        assert!(opened.is_err(), "the contending starter must be refused");
        assert!(
            !state_constructor_called.load(Ordering::SeqCst),
            "state construction must not run before singleton authority is acquired"
        );
        drop(first);
    }

    /// Every storage mode the daemon can boot in, so the routability assertion
    /// below cannot silently stop covering a mode that is added later. The
    /// `match` in `served_repo_key_space` is what forces a new variant to be
    /// handled; this list is what forces it to be exercised.
    fn every_storage_mode() -> Vec<StorageMode> {
        #[allow(unused_mut)]
        let mut modes = vec![StorageMode::Local];
        #[cfg(feature = "gcs")]
        modes.push(StorageMode::Gcs);
        modes
    }

    fn with_repo_ids<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let mut allowlist = kin_core::test_env::EnvVarGuard::new();
        allowlist.apply("KIN_REPO_IDS", value);
        body()
    }

    /// The identity a daemon advertises must be one it will route, in every
    /// storage mode and under every allowlist that mode can be handed, not only
    /// the default configuration that has nothing to disagree with.
    ///
    /// `DaemonState::serves_repo_id` answers from `allowed_repo_ids` alone
    /// whenever a key space is configured, so this is the exact predicate every
    /// `/repos/{repo_id}` route resolves against. Startup therefore has two
    /// admissible outcomes and no third: it either yields a key space that
    /// admits the advertised id, or it refuses to boot. A daemon that runs
    /// while contradicting its own `/health` is the state this forbids.
    #[test]
    #[serial_test::serial]
    fn every_storage_mode_admits_the_repo_id_it_advertises_or_refuses_to_boot() {
        let repo_id = "advertised-repo";
        for storage in every_storage_mode() {
            for allowlist in [
                None,
                Some(repo_id),
                Some("advertised-repo,sibling-repo"),
                Some("other-repo,third-repo"),
            ] {
                let outcome = with_repo_ids(allowlist, || served_repo_key_space(&storage, repo_id));
                let Ok(key_space) = outcome else {
                    continue;
                };
                assert!(
                    key_space
                        .as_ref()
                        .is_none_or(|allowed| allowed.contains(repo_id)),
                    "{storage:?} booted with a key space that refuses the id it advertises \
                     (KIN_REPO_IDS={allowlist:?}): {key_space:?}"
                );
            }
        }
    }

    /// The misconfiguration itself: an allowlist that omits the served id. It
    /// must refuse to boot, and the refusal must name both values so the
    /// operator can see which one to change.
    #[cfg(feature = "gcs")]
    #[test]
    #[serial_test::serial]
    fn a_gcs_allowlist_excluding_the_served_repo_refuses_startup() {
        let refusal = with_repo_ids(Some("other-repo, third-repo"), || {
            served_repo_key_space(&StorageMode::Gcs, "advertised-repo")
                .expect_err("an allowlist without the served id must refuse startup")
        });

        assert!(
            refusal.contains("advertised-repo"),
            "the refusal must name the served repo id: {refusal}"
        );
        assert!(
            refusal.contains("other-repo") && refusal.contains("third-repo"),
            "the refusal must name the configured allowlist: {refusal}"
        );
        assert!(
            refusal.contains("KIN_REPO_IDS"),
            "the refusal must name the setting to change: {refusal}"
        );
    }

    /// A consistent allowlist is still honored in full: admission reconciles the
    /// served id with the key space, it does not discard the operator's list or
    /// widen it to every repository in the bucket.
    #[cfg(feature = "gcs")]
    #[test]
    #[serial_test::serial]
    fn a_gcs_allowlist_containing_the_served_repo_is_admitted_unchanged() {
        let admitted = with_repo_ids(Some("advertised-repo,sibling-repo"), || {
            served_repo_key_space(&StorageMode::Gcs, "advertised-repo")
                .expect("an allowlist naming the served id must be admitted")
        })
        .expect("a configured allowlist must survive admission");

        assert!(admitted.contains("advertised-repo"));
        assert!(admitted.contains("sibling-repo"));
        assert_eq!(admitted.len(), 2, "admission must not widen the key space");
    }

    /// No allowlist means no key-space constraint, which is how a single-repo
    /// hosted pod runs. Admission must not invent one.
    #[cfg(feature = "gcs")]
    #[test]
    #[serial_test::serial]
    fn gcs_without_an_allowlist_keeps_an_unconstrained_key_space() {
        let admitted = with_repo_ids(None, || {
            served_repo_key_space(&StorageMode::Gcs, "advertised-repo")
                .expect("an unset allowlist must be admitted")
        });
        assert!(admitted.is_none(), "got {admitted:?}");
    }

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn default_directive_admits_info() {
        // The regression: a bare `fmt::init()` starves info-level logs when
        // RUST_LOG is unset. The daemon default must admit info.
        let filter = EnvFilter::new(DEFAULT_LOG_DIRECTIVE);
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::INFO));
    }

    #[test]
    fn bare_fmt_init_default_drops_info() {
        // Root-cause proof. `tracing_subscriber::fmt::init()` filters through
        // `EnvFilter::from_default_env()`, whose builder default directive is
        // ERROR; with RUST_LOG unset it admits only ERROR, so every info-level
        // lifecycle log is dropped — the reason supervisor.log / daemon.log
        // stayed empty on a fresh install. Reproduce that filter deterministically
        // (explicit empty RUST_LOG) and confirm it excludes info, unlike the
        // daemon's explicit `info` default.
        let bare = EnvFilter::builder()
            .with_default_directive(LevelFilter::ERROR.into())
            .parse_lossy("");
        assert_eq!(bare.max_level_hint(), Some(LevelFilter::ERROR));
        assert_eq!(
            EnvFilter::new(DEFAULT_LOG_DIRECTIVE).max_level_hint(),
            Some(LevelFilter::INFO)
        );
    }

    #[test]
    fn info_events_reach_the_log_writer_under_default_filter() {
        // Build the subscriber exactly as the daemon does for the RUST_LOG-unset
        // case and confirm a lifecycle info event actually lands in the writer —
        // i.e. the log file receives content on startup.
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(DEFAULT_LOG_DIRECTIVE))
            .with_writer(SharedBuf(Arc::clone(&buf)))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(port = 4219, "daemon is up and ready");
        });

        let logged = String::from_utf8(buf.lock().expect("log buffer poisoned").clone())
            .expect("log output is valid UTF-8");
        assert!(
            logged.contains("daemon is up and ready"),
            "expected info lifecycle log in the writer, got: {logged:?}"
        );
    }
}
