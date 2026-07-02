// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(feature = "gcs")]
use std::collections::HashSet;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
use std::env;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use kin_core::KinLayout;
use kin_daemon::{run, DaemonConfig, DaemonState};
use tracing_subscriber::EnvFilter;

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

fn create_state(
    layout: KinLayout,
    storage: &StorageMode,
    repo_id: &str,
) -> std::result::Result<DaemonState, Box<dyn std::error::Error>> {
    match storage {
        StorageMode::Local => {
            let _ = repo_id;
            Ok(DaemonState::open(layout)?)
        }
        #[cfg(feature = "gcs")]
        StorageMode::Gcs => {
            let allowed_repo_ids = parse_allowed_repo_ids();
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
    tracing_subscriber::fmt()
        .with_env_filter(daemon_env_filter())
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
        println!(
            "{}",
            serde_json::json!({
                "schema": "kin.daemon.compat.v1",
                "version": env!("CARGO_PKG_VERSION"),
                "graph_snapshot_version": kin_db::GraphSnapshot::CURRENT_VERSION,
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

    let state = match create_state(layout, &args.storage, &repo_id) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("kin-daemon: failed to open daemon state: {error}");
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

    if let Err(error) = run(state, config).await {
        eprintln!("kin-daemon: {error}");
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::fmt::MakeWriter;

    /// A `MakeWriter` that appends everything the subscriber emits into a shared
    /// buffer — stands in for the daemon/supervisor log file the spawn code wires
    /// the process's stdout/stderr to.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

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
