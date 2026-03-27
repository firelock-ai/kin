// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::env;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process;

use kin_core::KinLayout;
use kin_daemon::{run, DaemonConfig, DaemonState};

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
    /// Repo identifier for StorageBackend (defaults to directory name).
    repo_id: Option<String>,
}

fn usage(program: &str) {
    eprintln!(
        "Usage:\n  {program} [--repo <path>] [--port <port>] [--storage local|gcs] [--repo-id <id>]\n\n\
         Defaults:\n  --repo     current working directory\n  --port     4219\n  --storage  local (or KIN_STORAGE env var)\n  --repo-id  directory name of --repo"
    );
}

fn parse_args() -> Result<Args, String> {
    let mut repo = env::current_dir().map_err(|error| error.to_string())?;
    let mut port = 4219_u16;
    let mut storage_str: Option<String> = None;
    let mut repo_id: Option<String> = None;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
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
            return Err(format!("unknown storage mode: {other} (expected local or gcs)"));
        }
    };

    Ok(Args {
        repo,
        port,
        storage,
        repo_id,
    })
}

fn create_state(
    layout: KinLayout,
    storage: &StorageMode,
    _repo_id: &str,
) -> std::result::Result<DaemonState, Box<dyn std::error::Error>> {
    match storage {
        StorageMode::Local => Ok(DaemonState::open(layout)?),
        #[cfg(feature = "gcs")]
        StorageMode::Gcs => {
            let allowed_repo_ids = parse_allowed_repo_ids();
            let bucket = env::var("KIN_GCS_BUCKET").map_err(|_| {
                "KIN_GCS_BUCKET env var required for --storage gcs"
            })?;
            let prefix = env::var("KIN_GCS_PREFIX").unwrap_or_default();
            let backend = kin_db::GcsBackend::new(&bucket, prefix)?;
            Ok(DaemonState::open_with_backend(
                layout,
                Box::new(backend),
                _repo_id,
                allowed_repo_ids,
            )?)
        }
    }
}

#[cfg(feature = "gcs")]
fn parse_allowed_repo_ids() -> Option<HashSet<String>> {
    let raw = env::var("KIN_REPO_IDS").ok()?;
    let values: HashSet<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect();
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

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

    // Derive repo_id from --repo-id flag or directory name
    let repo_id = args.repo_id.unwrap_or_else(|| {
        args.repo
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("default")
            .to_string()
    });

    let state = match create_state(layout, &args.storage, &repo_id) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("kin-daemon: failed to open daemon state: {error}");
            process::exit(1);
        }
    };

    let config = DaemonConfig {
        api_port: args.port,
        ..DaemonConfig::default()
    };

    if let Err(error) = run(state, config).await {
        eprintln!("kin-daemon: {error}");
        process::exit(1);
    }
}
