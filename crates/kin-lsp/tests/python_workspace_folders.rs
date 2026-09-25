// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exercises the production initialize handshake against an installed pyright.
//! Run explicitly with `cargo test -p kin-lsp --test python_workspace_folders
//! -- --ignored --nocapture`. No packages are installed or downloaded.

#![cfg(unix)]

use kin_lsp::enrichment::{EntityIndex, EntityRef};
use kin_lsp::file_enrichment::enrich_file_definitions;
use kin_lsp::lifecycle::LspServer;
use kin_lsp::protocol;
use kin_model::{EntityId, EntityKind, GraphNodeId};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn quoted(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
}

fn entity(name: &str, path: &str, start: u32, end: u32) -> EntityRef {
    EntityRef {
        id: EntityId::new(),
        name: name.into(),
        file_path: path.into(),
        start_line: start,
        start_col: 0,
        end_line: end,
        name_line: start,
        name_col: 4,
        declares_name: true,
        kind: EntityKind::Function,
    }
}

async fn open(server: &LspServer, path: &Path, text: &str) {
    server
        .client
        .notify(
            "textDocument/didOpen",
            json!({"textDocument": {
                "uri": protocol::path_to_uri(path), "languageId": "python",
                "version": 1, "text": text
            }}),
        )
        .await
        .unwrap();
}

async fn definition(server: &LspServer, path: &Path, line: u32, character: u32) -> Value {
    let reply = tokio::time::timeout(
        Duration::from_secs(30),
        server.client.request(
            "textDocument/definition",
            json!({"textDocument": {"uri": protocol::path_to_uri(path)},
                   "position": {"line": line, "character": character}}),
        ),
    )
    .await
    .expect("definition deadline")
    .expect("definition response");
    eprintln!("definition {}:{line}:{character}: {reply}", path.display());
    assert_eq!(reply.as_array().map(Vec::len), Some(1), "{reply}");
    reply[0].clone()
}

fn location_path(location: &Value) -> PathBuf {
    protocol::uri_to_path(location["uri"].as_str().unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires installed pyright-langserver and Python; runs offline when explicitly selected"]
async fn src_workspace_wins_over_outside_pth_without_admitting_foreign_definitions() {
    let pyright = which::which("pyright-langserver").expect("installed pyright-langserver");
    let python = which::which("python3").expect("installed Python");
    let fixture = std::env::temp_dir().join(format!("kin-python-workspace-{}", EntityId::new()));
    std::fs::create_dir(&fixture).unwrap();
    let fixture = fixture.canonicalize().unwrap();
    eprintln!("fixture (retained on failure): {}", fixture.display());
    let root = fixture.join("repo");
    let outside = fixture.join("outside-copy");
    let dependencies = fixture.join("dependencies");
    let local_source = "def signal(value):\n    return value\n";
    let foreign_source = "def signal(value):\n    return 'foreign'\n";
    let external_source = "def harmless(value):\n    return value\n";
    let local_use = "from pkg import signal\n\ndef use_local():\n    return signal(1)\n";
    let external_use =
        "from external_dependency import harmless\n\ndef use_external():\n    return harmless(1)\n";
    write(
        &root,
        "pyproject.toml",
        "[tool.pyright]\ninclude = [\"src\"]\n",
    );
    write(
        &root,
        "src/pkg/__init__.py",
        "from .signals import signal\n",
    );
    write(&root, "src/pkg/signals.py", local_source);
    write(&root, "tests/use_local.py", local_use);
    write(&root, "tests/use_external.py", external_use);
    write(
        &outside,
        "src/pkg/__init__.py",
        "from .signals import signal\n",
    );
    write(&outside, "src/pkg/signals.py", foreign_source);
    write(&dependencies, "external_dependency.py", external_source);

    let venv = fixture.join("venv");
    let created = Command::new(&python)
        .args(["-m", "venv", "--without-pip"])
        .arg(&venv)
        .output()
        .unwrap();
    assert!(created.status.success(), "{created:?}");
    let interpreter = venv.join("bin/python3");
    let purelib = Command::new(&interpreter)
        .args([
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ])
        .output()
        .unwrap();
    assert!(purelib.status.success(), "{purelib:?}");
    let purelib = PathBuf::from(String::from_utf8(purelib.stdout).unwrap().trim());
    std::fs::write(
        purelib.join("workspace_fixture.pth"),
        format!(
            "{}\n{}\n",
            outside.join("src").display(),
            dependencies.display()
        ),
    )
    .unwrap();
    let imported = Command::new(&interpreter)
        .args(["-c", "import pkg; print(pkg.signal.__code__.co_filename)"])
        .output()
        .unwrap();
    assert!(imported.status.success(), "{imported:?}");
    assert_eq!(
        String::from_utf8(imported.stdout).unwrap().trim(),
        outside.join("src/pkg/signals.py").to_str().unwrap(),
        "the Python environment must actually point outside the repository"
    );

    // Change only this owned child's PATH. Concurrent tests keep their environment.
    let launcher = fixture.join("server.sh");
    std::fs::write(
        &launcher,
        format!(
            "#!/bin/sh\nPATH={}:\"$PATH\"\nexport PATH\nexec {} \"$@\"\n",
            quoted(&venv.join("bin")),
            quoted(&pyright)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
    let server = LspServer::start(
        "/bin/sh",
        &[launcher.to_str().unwrap(), "--stdio"],
        &root,
        Some(json!({"diagnosticMode": "off", "pythonPath": "python3"})),
        None,
    )
    .await
    .expect("actual pyright initializes through the production lifecycle");

    open(&server, &root.join("tests/use_local.py"), local_use).await;
    let local = definition(&server, &root.join("tests/use_local.py"), 3, 12).await;
    assert_eq!(location_path(&local), root.join("src/pkg/signals.py"));
    let target = entity("signal", "src/pkg/signals.py", 0, 1);
    let caller = entity("use_local", "tests/use_local.py", 2, 3);
    let external_caller = entity("use_external", "tests/use_external.py", 2, 3);
    let index = EntityIndex::new(vec![target.clone(), caller.clone(), external_caller], &root);
    assert_eq!(
        index
            .find_at(local["uri"].as_str().unwrap(), 0)
            .map(|e| e.id),
        Some(target.id)
    );

    // Same function name, same tail and line, but a different repository.
    let foreign_path = outside.join("src/pkg/signals.py");
    open(&server, &foreign_path, foreign_source).await;
    let foreign = definition(&server, &foreign_path, 0, 5).await;
    assert_eq!(location_path(&foreign), foreign_path);
    assert!(index.find_at(foreign["uri"].as_str().unwrap(), 0).is_none());

    open(&server, &root.join("tests/use_external.py"), external_use).await;
    let external = definition(&server, &root.join("tests/use_external.py"), 3, 12).await;
    assert_eq!(
        location_path(&external),
        dependencies.join("external_dependency.py")
    );
    assert!(index
        .find_at(external["uri"].as_str().unwrap(), 0)
        .is_none());

    let documents = HashMap::from([
        ("src/pkg/signals.py", local_source),
        ("tests/use_local.py", local_use),
        ("tests/use_external.py", external_use),
    ]);
    let provider = |path: &str| documents.get(path).map(|source| (*source).to_owned());
    let local_pass = enrich_file_definitions(
        &server,
        &root.join("tests/use_local.py"),
        local_use,
        &index,
        &root,
        Some(&provider),
    )
    .await
    .unwrap();
    assert_eq!(local_pass.failed_queries, 0, "{local_pass:?}");
    assert!(
        local_pass
            .relations
            .iter()
            .any(|edge| edge.src == GraphNodeId::Entity(caller.id)
                && edge.dst == GraphNodeId::Entity(target.id)),
        "{local_pass:?}"
    );
    let external_pass = enrich_file_definitions(
        &server,
        &root.join("tests/use_external.py"),
        external_use,
        &index,
        &root,
        Some(&provider),
    )
    .await
    .unwrap();
    assert_eq!(external_pass.failed_queries, 0, "{external_pass:?}");
    assert!(external_pass.relations.is_empty(), "{external_pass:?}");
    eprintln!("local pass: {local_pass:?}\nexternal pass: {external_pass:?}");
    server.shutdown().await.unwrap();
    std::fs::remove_dir_all(fixture).unwrap();
}
