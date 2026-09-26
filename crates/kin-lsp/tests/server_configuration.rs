// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exercises each adapter's launch against the installed server it configures,
//! on fixtures where the configuration decides whether a call has an answer.
//! Run explicitly with
//! `cargo test -p kin-lsp --test server_configuration -- --ignored --nocapture`.
//! Nothing is installed or downloaded; each test needs its server on `PATH`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use kin_lsp::adapters::{python, rust_analyzer, typescript, LspAdapter, ServerLaunch};
use kin_lsp::lifecycle::LspServer;
use kin_lsp::protocol;
use serde_json::{json, Value};

fn fixture(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kin-server-configuration-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.canonicalize().unwrap()
}

fn write(root: &Path, relative: &str, text: &str) -> PathBuf {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    path
}

async fn start(adapter: &dyn LspAdapter, root: &Path, launch: &ServerLaunch) -> LspServer {
    let command = which::which(adapter.server_command())
        .unwrap_or_else(|_| panic!("{} is not installed", adapter.server_command()));
    let args = adapter.server_args();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    LspServer::launch_settled(&command.to_string_lossy(), &args, root, launch, None)
        .await
        .expect("the server starts")
}

async fn open(server: &LspServer, path: &Path, language: &str) {
    server
        .client
        .notify(
            "textDocument/didOpen",
            json!({"textDocument": {
                "uri": protocol::path_to_uri(path), "languageId": language,
                "version": 1, "text": std::fs::read_to_string(path).unwrap(),
            }}),
        )
        .await
        .unwrap();
}

/// The files the definition at `line:character` lands in, asked until one
/// lands outside the asking file or the deadline passes. A server still
/// loading answers from the open file alone, which is not its final answer.
async fn definition_files(
    server: &LspServer,
    path: &Path,
    line: u32,
    character: u32,
) -> Vec<PathBuf> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let reply = server
            .client
            .request(
                "textDocument/definition",
                json!({"textDocument": {"uri": protocol::path_to_uri(path)},
                       "position": {"line": line, "character": character}}),
            )
            .await
            .unwrap_or(Value::Null);
        let files: Vec<PathBuf> = reply
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|location| {
                let uri = location
                    .get("uri")
                    .or_else(|| location.get("targetUri"))?
                    .as_str()?;
                protocol::uri_to_path(uri)
            })
            .collect();
        if files.iter().any(|file| file != path) || tokio::time::Instant::now() > deadline {
            eprintln!("definition {}:{line}:{character}: {reply}", path.display());
            return files;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// pyright types a third-party call only from an environment that has the
/// package, and takes that environment only as `python.pythonPath` through
/// `workspace/configuration`. The fixture's `.venv` holds a package no other
/// Python on the host has; with the adapter's launch the call lands in it.
#[tokio::test]
#[ignore = "requires pyright-langserver and python3; runs offline when explicitly selected"]
async fn pyright_takes_the_project_environment_from_its_settings() {
    let root = fixture("pyright-env");
    let venv = root.join(".venv");
    let made = std::process::Command::new("python3")
        .args(["-m", "venv", "--without-pip"])
        .arg(&venv)
        .status()
        .expect("python3 makes a virtual environment");
    assert!(made.success());
    let version = std::process::Command::new(venv.join("bin/python3"))
        .args([
            "-c",
            "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')",
        ])
        .output()
        .unwrap();
    let version = String::from_utf8(version.stdout)
        .unwrap()
        .trim()
        .to_string();
    let site = format!(".venv/lib/python{version}/site-packages");
    write(
        &root,
        &format!("{site}/kin_only_in_venv/__init__.py"),
        "class Client:\n    def get(self, url):\n        return url\n",
    );
    write(&root, "pyproject.toml", "[project]\nname = \"demo\"\n");
    let test = write(
        &root,
        "tests/test_client.py",
        "from kin_only_in_venv import Client\n\nclient = Client()\nclient.get('/')\n",
    );

    let launch = python::PyrightAdapter.launch(&root);
    assert!(
        launch.label.contains("ProjectVenv"),
        "the adapter finds the fixture's environment: {}",
        launch.label
    );
    let server = start(&python::PyrightAdapter, &root, &launch).await;
    open(&server, &test, "python").await;
    let files = definition_files(&server, &test, 3, 7).await;
    assert!(
        files
            .iter()
            .any(|file| file.starts_with(&venv) && file.ends_with("kin_only_in_venv/__init__.py")),
        "client.get resolves into the project environment: {files:?}"
    );
    server.shutdown().await.unwrap();

    // The same server with the settings withheld has no environment with the
    // package, which is what Kin sent before: nothing reached pyright.
    let bare = ServerLaunch::default();
    let server = start(&python::PyrightAdapter, &root, &bare).await;
    open(&server, &test, "python").await;
    let files = definition_files(&server, &test, 3, 7).await;
    assert!(
        !files.iter().any(|file| file.starts_with(&venv)),
        "without the settings pyright cannot see the environment: {files:?}"
    );
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

/// drizzle-orm's shape: `app` depends on `lib` through `lib/dist`, which no
/// build has written, and `lib`'s source imports through its own path alias.
/// With the adapter's plugin the call lands in `lib`'s source; without it the
/// import resolves to nothing.
#[tokio::test]
#[ignore = "requires typescript-language-server with a TypeScript it can find; runs offline"]
async fn typescript_resolves_an_unbuilt_workspace_package_from_source() {
    let root = fixture("ts-workspace");
    write(
        &root,
        "pnpm-workspace.yaml",
        "packages:\n  - lib\n  - app\n",
    );
    write(
        &root,
        "package.json",
        "{\"name\": \"root\", \"private\": true}",
    );
    write(
        &root,
        "lib/package.json",
        "{\"name\": \"lib\", \"main\": \"./index.js\", \"types\": \"./index.d.ts\"}",
    );
    write(
        &root,
        "lib/tsconfig.json",
        r#"{"compilerOptions": {"baseUrl": ".", "paths": {"~/*": ["src/*"]}, "module": "esnext", "moduleResolution": "bundler", "strict": true}, "include": ["src"]}"#,
    );
    write(
        &root,
        "lib/src/index.ts",
        "export { greet } from '~/greet';\n",
    );
    let greet = write(
        &root,
        "lib/src/greet.ts",
        "export function greet(name: string): string {\n  return name;\n}\n",
    );
    write(
        &root,
        "app/package.json",
        "{\"name\": \"app\", \"dependencies\": {\"lib\": \"workspace:../lib/dist\"}}",
    );
    write(
        &root,
        "app/tsconfig.json",
        r#"{"compilerOptions": {"module": "esnext", "moduleResolution": "bundler", "strict": true}, "include": ["src"]}"#,
    );
    std::fs::create_dir_all(root.join("app/node_modules")).unwrap();
    std::os::unix::fs::symlink("../../lib/dist", root.join("app/node_modules/lib")).unwrap();
    let main = write(
        &root,
        "app/src/main.ts",
        "import { greet } from 'lib';\n\nexport function run(): string {\n  return greet('x');\n}\n",
    );

    let cache = root.join(".kin-cache");
    let launch = typescript::launch_with(&root, &cache);
    assert!(
        launch.label.contains("2 workspace package"),
        "{}",
        launch.label
    );
    let server = start(&typescript::TypeScriptAdapter, &root, &launch).await;
    open(&server, &main, "typescript").await;
    let files = definition_files(&server, &main, 3, 9).await;
    assert!(
        files.contains(&greet),
        "greet resolves to lib's source through lib's own alias: {files:?}"
    );
    server.shutdown().await.unwrap();

    let bare = ServerLaunch::with_initialization_options(
        typescript::TypeScriptAdapter.initialization_options(&root),
    );
    let server = start(&typescript::TypeScriptAdapter, &root, &bare).await;
    open(&server, &main, "typescript").await;
    let files = definition_files(&server, &main, 3, 9).await;
    assert!(
        !files.contains(&greet),
        "without the plugin the unbuilt package resolves to nothing: {files:?}"
    );
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

/// axum's shape: a second Cargo workspace in `examples/` that the root
/// workspace does not include. rust-analyzer loads it only when linked.
#[tokio::test]
#[ignore = "requires rust-analyzer; runs offline when explicitly selected"]
async fn rust_analyzer_loads_a_nested_workspace_it_is_linked_to() {
    let root = fixture("ra-nested");
    write(
        &root,
        "Cargo.toml",
        "[workspace]\nmembers = [\"core\"]\nresolver = \"2\"\n",
    );
    write(
        &root,
        "core/Cargo.toml",
        "[package]\nname = \"core_lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    let lib = write(
        &root,
        "core/src/lib.rs",
        "pub fn shared() -> u32 {\n    1\n}\n",
    );
    write(
        &root,
        "deeper/examples/Cargo.toml",
        "[workspace]\nmembers = [\"hello\"]\nresolver = \"2\"\n",
    );
    write(
        &root,
        "deeper/examples/hello/Cargo.toml",
        "[package]\nname = \"hello\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncore_lib = { path = \"../../../core\" }\n",
    );
    let example = write(
        &root,
        "deeper/examples/hello/src/main.rs",
        "fn main() {\n    core_lib::shared();\n}\n",
    );
    for dir in [root.clone(), root.join("deeper/examples")] {
        let status = std::process::Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(status.success());
    }

    let launch = rust_analyzer::RustAnalyzerAdapter.launch(&root);
    assert!(
        launch.label.contains("2 linked project"),
        "{}",
        launch.label
    );
    let server = start(&rust_analyzer::RustAnalyzerAdapter, &root, &launch).await;
    assert_eq!(server.configuration(), launch.label);
    open(&server, &example, "rust").await;
    let files = definition_files(&server, &example, 1, 15).await;
    assert!(
        files.contains(&lib),
        "the example's call reaches the root workspace's crate: {files:?}"
    );
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&root);
}
