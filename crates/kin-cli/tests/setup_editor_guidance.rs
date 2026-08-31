// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin setup --intent editor` describes the extension state consistently.
//!
//! The public installer can enter setup with kin-editor already installed.
//! This drives the whole captured command because the contradictory guidance
//! used to span two independently correct sections: the plan recommended an
//! install before the follow-up and health checklist reported it installed.

use std::path::Path;
use std::time::Duration;

mod common;

const SETUP_TIMEOUT: Duration = Duration::from_secs(120);

fn run_editor_setup(home: &Path, cwd: &Path) -> String {
    let output = common::Command::new(env!("CARGO_BIN_EXE_kin"))
        .args([
            "setup",
            "--intent",
            "editor",
            "--no-interactive",
            "--skip-mcp-check",
        ])
        .current_dir(cwd)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("KIN_HOME", home.join(".kin"))
        .env("KIN_VFS_DISABLE", "1")
        .env("KIN_NO_DAEMON", "1")
        .env("KIN_REGISTRY_PATH", home.join("registry.toml"))
        .env_remove("KIN_DIR")
        .env_remove("KIN_DAEMON_URL")
        .output_within(SETUP_TIMEOUT)
        .expect("run kin setup --intent editor");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "editor setup failed: stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

#[test]
fn full_setup_output_recommends_install_only_when_the_editor_extension_is_missing() {
    let installed_root = tempfile::tempdir().expect("installed setup root");
    let installed_home = installed_root.path().join("home");
    let installed_cwd = installed_root.path().join("outside-repository");
    let installed_extension = installed_home
        .join(".vscode")
        .join("extensions")
        .join("firelock.kin-editor-test");
    std::fs::create_dir_all(&installed_extension)
        .expect("seed version-neutral extension directory");
    std::fs::write(
        installed_extension.join("package.json"),
        r#"{"publisher":"firelock","name":"kin-editor","version":"0.0.0-test"}"#,
    )
    .expect("seed official extension manifest");
    std::fs::create_dir_all(&installed_cwd).expect("create installed cwd");

    let installed = run_editor_setup(&installed_home, &installed_cwd);
    let installed_lower = installed.to_lowercase();
    assert!(
        installed_lower.contains("kin-editor extension already installed")
            && installed_lower.contains("kin-editor is already installed"),
        "the full setup output did not acknowledge the detected extension:\n{installed}"
    );
    assert!(
        !installed_lower.contains("install the kin-editor"),
        "the full setup output recommended an extension that is already installed:\n{installed}"
    );

    let missing_root = tempfile::tempdir().expect("missing setup root");
    let missing_home = missing_root.path().join("home");
    let missing_cwd = missing_root.path().join("outside-repository");
    std::fs::create_dir_all(&missing_home).expect("create missing home");
    std::fs::create_dir_all(&missing_cwd).expect("create missing cwd");

    let missing = run_editor_setup(&missing_home, &missing_cwd);
    let missing_lower = missing.to_lowercase();
    assert!(
        missing_lower.contains("plan: editor (vs code + kin-editor)")
            && missing_lower.contains("plus how to install the kin-editor extension"),
        "the missing-extension plan stopped describing its install path:\n{missing}"
    );
    let editor_followup = missing
        .split_once("Editor extension:")
        .map(|(_, after_heading)| after_heading)
        .and_then(|after_heading| after_heading.split_once("=== Health checklist ==="))
        .map(|(section, _)| section)
        .unwrap_or_else(|| panic!("setup printed no bounded editor follow-up section:\n{missing}"));
    assert!(
        editor_followup.contains("Install the kin-editor VS Code extension for the entity explorer,")
            && editor_followup
                .contains("semantic search, and trace surfaces. See the kin-editor README."),
        "the missing-extension editor follow-up lost its actionable install guidance:\n{editor_followup}"
    );
}
