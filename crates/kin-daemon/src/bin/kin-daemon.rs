// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::env;
use std::path::{Path, PathBuf};
use std::process;

use kin_core::KinLayout;
use kin_daemon::{run, DaemonConfig, DaemonState};

struct Args {
    repo: PathBuf,
    port: u16,
}

fn usage(program: &str) {
    eprintln!(
        "Usage:\n  {program} [--repo <path>] [--port <port>]\n\nDefaults:\n  --repo  current working directory\n  --port  4219"
    );
}

fn parse_args() -> Result<Args, String> {
    let mut repo = env::current_dir().map_err(|error| error.to_string())?;
    let mut port = 4219_u16;
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

    Ok(Args { repo, port })
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

    let state = match DaemonState::open(layout) {
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
