// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Print, as JSON, the configuration Kin starts one language server with for
//! one repository: the command, the initialization options, the settings the
//! server asks for, the environment, the fallback and the files no build
//! compiles, and beside them the project model and environment the adapter
//! chose them from.
//!
//! ```text
//! cargo run -p kin-lsp --example launch_config -- <rust|python|typescript|go|c|java> <repository>
//! ```
//!
//! It reads the repository and writes nothing into it. For TypeScript it
//! installs the workspace-source plugin under Kin's cache, as a start would.
//!
//! With `--provision` after the repository, it first runs the adapter's
//! network step, as a server start does: an analysis environment the launch
//! has pending is fetched into Kin's cache, and the report of what was
//! fetched, reused, skipped and refused, and which processes started, is
//! printed as `provision` beside the launch chosen afterwards.

use std::path::PathBuf;

use kin_lsp::adapters::{
    clangd, go, java, python, rust_analyzer, typescript, LspAdapter, ServerLaunch,
};

fn describe(launch: &ServerLaunch) -> serde_json::Value {
    serde_json::json!({
        "label": launch.label,
        "initializationOptions": launch.initialization_options,
        "settings": launch.settings,
        "env": launch.env,
        "loadCheck": launch.load_check.map(|check| format!("{check:?}")),
        "fallbackTrigger": launch.fallback_trigger,
        "fallback": launch.fallback.as_deref().map(describe),
        "unbuiltSources": launch
            .resolution
            .as_ref()
            .map(|resolution| resolution.not_in_any_build.clone())
            .unwrap_or_default(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(language), Some(root)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: launch_config <rust|python|typescript|go|c|java> <repository>");
        std::process::exit(2);
    };
    let root = PathBuf::from(root)
        .canonicalize()
        .unwrap_or_else(|error| panic!("{root}: {error}"));
    let adapter: Box<dyn LspAdapter> = match language.as_str() {
        "rust" => Box::new(rust_analyzer::RustAnalyzerAdapter),
        "python" => Box::new(python::PyrightAdapter),
        "typescript" | "javascript" => Box::new(typescript::TypeScriptAdapter),
        "go" => Box::new(go::GoplsAdapter),
        "c" | "cpp" => Box::new(clangd::ClangdAdapter),
        "java" => Box::new(java::JdtlsAdapter),
        other => {
            eprintln!("no adapter for {other}");
            std::process::exit(2);
        }
    };
    let report = (args.get(3).map(String::as_str) == Some("--provision"))
        .then(|| adapter.provision(&root))
        .flatten();
    let launch = adapter.launch(&root);
    let mut described = describe(&launch);
    if let Some(report) = &report {
        described["provision"] = serde_json::json!(report);
    }
    if let Some(resolution) = &launch.resolution {
        described["status"] = serde_json::json!(resolution.status_lines());
        described["environment"] = serde_json::json!(resolution.environment);
    }
    described["projectModel"] = serde_json::json!(adapter.project_model(&root));
    described["command"] = serde_json::json!(adapter.server_command());
    described["args"] = serde_json::json!(adapter.server_args());
    described["root"] = serde_json::json!(root);
    println!("{}", serde_json::to_string_pretty(&described).unwrap());
}
