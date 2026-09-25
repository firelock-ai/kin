// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which changes a session workspace may hand back to repository authority.
//!
//! A session runs a command over a copy of graph truth, and whatever the
//! command leaves behind is observed at the reconcile boundary. Two policies
//! decide what of that is admitted:
//!
//! * [`SessionWriteBack::ExceptBuildOutputs`] is what a person's session
//!   admits: every change the command made, except new build outputs. A new
//!   executable or object file, and a new file under a directory the
//!   repository never admits new files from by default, is reported and left
//!   out. `kin exec -- go build ./...` used to admit the compiled binary as a
//!   repository artifact.
//! * [`SessionWriteBack::ToolchainManifests`] is what an agent's toolchain run
//!   admits: the manifests and lockfiles a toolchain owns, and nothing else.
//!   An agent writes code through entity operations, so a source file a
//!   command created, changed or removed is refused and reported, and so is
//!   any other file. Build outputs are never admitted.
//!
//! Everything here is a pure decision over a path and the bytes the reconcile
//! boundary already read. Nothing in this module touches the filesystem.

use kin_model::RepoPath;
use serde::{Deserialize, Serialize};

use crate::commands::reconcile::{ReconcileChangeKind, ReconcilePath};

/// What a session's observed changes may admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionWriteBack {
    /// Every observed change except new build outputs. `kin exec`, `kin
    /// shell`, `kin with`, `kin open` and `kin reconcile` admit this.
    #[default]
    ExceptBuildOutputs,
    /// Only the manifests and lockfiles any toolchain owns. An agent's run of
    /// a command the repository configured, which belongs to no one
    /// toolchain, admits this.
    ToolchainManifests,
    /// Only the manifests and lockfiles of the toolchain that ran. An agent's
    /// `go` command hands back `go.mod` and `go.sum`, never a `package.json`
    /// the program it built happened to write.
    ManifestsOf(Toolchain),
}

impl SessionWriteBack {
    /// Whether this is an agent's policy, which admits manifests and nothing
    /// else.
    pub fn manifests_only(self) -> bool {
        !matches!(self, Self::ExceptBuildOutputs)
    }

    /// The toolchain whose manifests this admits, `None` for every
    /// toolchain's.
    pub fn toolchain(self) -> Option<Toolchain> {
        match self {
            Self::ManifestsOf(toolchain) => Some(toolchain),
            _ => None,
        }
    }
}

/// A toolchain whose manifests an agent's run may hand back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Toolchain {
    Go,
    Node,
    Python,
    Rust,
}

impl Toolchain {
    pub const ALL: [Toolchain; 4] = [Self::Go, Self::Node, Self::Python, Self::Rust];

    /// The manifests and lockfiles this toolchain writes, by file name.
    pub fn manifests(self) -> &'static [&'static str] {
        match self {
            Self::Go => &["go.mod", "go.sum", "go.work", "go.work.sum"],
            Self::Node => &[
                "package.json",
                "package-lock.json",
                "npm-shrinkwrap.json",
                "yarn.lock",
                "pnpm-lock.yaml",
            ],
            Self::Rust => &["Cargo.toml", "Cargo.lock"],
            Self::Python => &[
                "pyproject.toml",
                "requirements.txt",
                "poetry.lock",
                "uv.lock",
                "Pipfile",
                "Pipfile.lock",
                "pdm.lock",
            ],
        }
    }
}

/// Why an observed change was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithheldReason {
    /// A new executable, object file or library, recognised by its first
    /// bytes or its extension.
    BuildOutput,
    /// A new file or directory under a name the repository never admits new
    /// files from by default, such as `node_modules` or `target`. A directory
    /// reported this way was not walked.
    Generated,
    /// Source code. An agent changes code through entity operations, never
    /// through a command's file writes.
    SourceUnit,
    /// Any other file an agent's toolchain run wrote. Only toolchain manifests
    /// and lockfiles are admitted from one.
    NotAToolchainManifest,
}

impl WithheldReason {
    /// One sentence saying what happened and what to do instead.
    pub fn sentence(self) -> &'static str {
        match self {
            Self::BuildOutput => "a build output, which Kin never admits into the repository",
            Self::Generated => {
                "generated or dependency output under a directory Kin never admits new files from"
            }
            Self::SourceUnit => {
                "source code, which is written through entity operations rather than by a command"
            }
            Self::NotAToolchainManifest => {
                "not a toolchain manifest or lockfile, the only files an agent's command may hand \
                 back"
            }
        }
    }
}

/// One observed change a session did not admit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithheldChange {
    pub kind: ReconcileChangeKind,
    pub path: ReconcilePath,
    pub reason: WithheldReason,
}

/// Every toolchain's manifests and lockfiles, by file name at any depth.
pub fn toolchain_manifests() -> impl Iterator<Item = &'static str> {
    Toolchain::ALL
        .into_iter()
        .flat_map(|toolchain| toolchain.manifests().iter().copied())
}

/// Extensions of files a compiler or linker produces. Content is checked as
/// well, by [`binary_output_kind`], so an extensionless executable is caught
/// too.
const BUILD_OUTPUT_EXTENSIONS: &[&str] = &[
    "o", "obj", "a", "lib", "so", "dylib", "dll", "exe", "rlib", "rmeta", "class", "pyc", "pyo",
    "wasm",
];

/// The last path component, as UTF-8 when it is.
fn file_name(path: &RepoPath) -> Option<&str> {
    let bytes = path.as_bytes();
    let leaf = bytes.rsplit(|byte| *byte == b'/').next()?;
    std::str::from_utf8(leaf).ok()
}

/// Whether `path` names a manifest or lockfile of `toolchain`, or of any
/// toolchain when `None`.
pub fn is_toolchain_manifest(path: &RepoPath, toolchain: Option<Toolchain>) -> bool {
    file_name(path).is_some_and(|name| match toolchain {
        Some(toolchain) => toolchain.manifests().contains(&name),
        None => toolchain_manifests().any(|manifest| manifest == name),
    })
}

/// Whether `path` is source code Kin extracts entities from.
pub fn is_source_unit(path: &RepoPath) -> bool {
    path.as_utf8().is_some_and(|path| {
        matches!(
            kin_index::FileClassifier::classify(std::path::Path::new(path)),
            kin_index::FileClassification::EntitySource
                | kin_index::FileClassification::ShallowSyntax { .. }
        )
    })
}

/// Whether one path component is a name the repository never admits new
/// files from by default. This is the repository's own default ignore list,
/// the names that are unambiguously generated in every ecosystem that uses
/// them; `build`, `out`, `bin` and `vendor` are not on it, because they
/// routinely hold hand-written source.
pub fn is_generated_name(component: &[u8]) -> bool {
    kin_index::repository::DEFAULT_IGNORED_NAMES
        .iter()
        .any(|name| name.as_bytes() == component)
}

/// Whether any component of `path` is a generated name.
pub fn under_generated_name(path: &RepoPath) -> bool {
    path.as_bytes()
        .split(|byte| *byte == b'/')
        .any(is_generated_name)
}

/// Whether the file name carries a compiler or linker output extension.
fn has_build_output_extension(path: &RepoPath) -> bool {
    file_name(path)
        .and_then(|name| name.rsplit_once('.'))
        .is_some_and(|(stem, extension)| {
            !stem.is_empty()
                && BUILD_OUTPUT_EXTENSIONS
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
}

/// What kind of compiled file `body` is, read from its first bytes, or `None`
/// for anything else.
pub fn binary_output_kind(body: &[u8]) -> Option<&'static str> {
    match body {
        [0x7f, b'E', b'L', b'F', ..] => Some("ELF"),
        [0xfe, 0xed, 0xfa, 0xce | 0xcf, ..] | [0xce | 0xcf, 0xfa, 0xed, 0xfe, ..] => Some("Mach-O"),
        // Both a universal Mach-O binary and a Java class file, and both are
        // build outputs.
        [0xca, 0xfe, 0xba, 0xbe, ..] => Some("Mach-O universal or Java class"),
        [0xca, 0xfe, 0xba, 0xbf, ..] => Some("Mach-O universal, 64-bit"),
        [0x00, b'a', b's', b'm', ..] => Some("WebAssembly"),
        [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n', ..] => Some("ar archive"),
        [b'M', b'Z', ..] if is_portable_executable(body) => Some("PE"),
        _ => None,
    }
}

/// A DOS header whose `e_lfanew` points at a `PE\0\0` signature. `MZ` alone
/// is two bytes a text file can start with.
fn is_portable_executable(body: &[u8]) -> bool {
    let Some(offset) = body.get(0x3c..0x40) else {
        return false;
    };
    let offset = u32::from_le_bytes([offset[0], offset[1], offset[2], offset[3]]) as usize;
    offset
        .checked_add(4)
        .and_then(|end| body.get(offset..end))
        .is_some_and(|signature| signature == b"PE\0\0")
}

/// Why a NEW file is not admitted by any session, or `None` when it may be.
///
/// Only new files: a file graph truth already holds is the repository's own,
/// and a person's session that rebuilds one is changing it on purpose.
pub fn new_file_withheld(path: &RepoPath, body: Option<&[u8]>) -> Option<WithheldReason> {
    if under_generated_name(path) {
        return Some(WithheldReason::Generated);
    }
    if has_build_output_extension(path) || body.and_then(binary_output_kind).is_some() {
        return Some(WithheldReason::BuildOutput);
    }
    None
}

/// Why an agent's toolchain run may not hand back a change to `path`, or
/// `None` when it may. `build_output` is what the scan concluded for a new
/// file.
pub fn agent_withheld(
    path: &RepoPath,
    build_output: Option<WithheldReason>,
    toolchain: Option<Toolchain>,
) -> Option<WithheldReason> {
    if let Some(reason) = build_output {
        return Some(reason);
    }
    if is_toolchain_manifest(path, toolchain) {
        return None;
    }
    if is_source_unit(path) {
        return Some(WithheldReason::SourceUnit);
    }
    Some(WithheldReason::NotAToolchainManifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> RepoPath {
        RepoPath::from_utf8(text).unwrap()
    }

    #[test]
    fn compiled_files_are_recognised_by_their_first_bytes() {
        assert_eq!(binary_output_kind(b"\x7fELF\x02\x01\x01"), Some("ELF"));
        assert_eq!(
            binary_output_kind(&[0xcf, 0xfa, 0xed, 0xfe, 0x0c]),
            Some("Mach-O")
        );
        assert_eq!(
            binary_output_kind(&[0xfe, 0xed, 0xfa, 0xce, 0x00]),
            Some("Mach-O")
        );
        assert!(binary_output_kind(&[0xca, 0xfe, 0xba, 0xbe]).is_some());
        assert_eq!(
            binary_output_kind(&[0xca, 0xfe, 0xba, 0xbf, 0x00]),
            Some("Mach-O universal, 64-bit")
        );
        assert_eq!(binary_output_kind(b"\0asm\x01\0\0\0"), Some("WebAssembly"));
        assert_eq!(binary_output_kind(b"!<arch>\nfoo"), Some("ar archive"));
        let mut pe = vec![0u8; 0x80];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(binary_output_kind(&pe), Some("PE"));
        // Text that happens to start with MZ, a script, and source are not.
        assert_eq!(binary_output_kind(b"MZ is a postcode prefix\n"), None);
        assert_eq!(binary_output_kind(b"#!/bin/sh\necho hi\n"), None);
        assert_eq!(binary_output_kind(b"package main\n"), None);
        assert_eq!(binary_output_kind(b""), None);
    }

    #[test]
    fn new_build_outputs_and_generated_files_are_withheld_from_every_session() {
        assert_eq!(
            new_file_withheld(&path("app"), Some(b"\x7fELF\x02")),
            Some(WithheldReason::BuildOutput)
        );
        for object in [
            "main.o",
            "lib/libx.a",
            "libx.so",
            "x.dylib",
            "a.exe",
            "A.CLASS",
        ] {
            assert_eq!(
                new_file_withheld(&path(object), Some(b"anything")),
                Some(WithheldReason::BuildOutput),
                "{object}"
            );
        }
        for generated in [
            "node_modules/left-pad/index.js",
            "target/debug/app",
            "pkg/__pycache__/m.cpython-312.pyc",
            "dist/bundle.js",
        ] {
            assert_eq!(
                new_file_withheld(&path(generated), Some(b"text")),
                Some(WithheldReason::Generated),
                "{generated}"
            );
        }
        // Ordinary new files, including ones under ambiguous directory names
        // that routinely hold hand-written source, are not.
        for kept in [
            "main.go",
            "build/gen.go",
            "vendor/x/y.go",
            "bin/tool.sh",
            ".o",
            "notes.txt",
        ] {
            assert_eq!(
                new_file_withheld(&path(kept), Some(b"text\n")),
                None,
                "{kept}"
            );
        }
    }

    #[test]
    fn an_agent_hands_back_toolchain_manifests_and_nothing_else() {
        for manifest in [
            "go.mod",
            "go.sum",
            "services/api/go.mod",
            "package.json",
            "package-lock.json",
            "Cargo.lock",
            "Cargo.toml",
            "pyproject.toml",
            "uv.lock",
        ] {
            assert_eq!(
                agent_withheld(&path(manifest), None, None),
                None,
                "{manifest}"
            );
        }
        for source in ["main.go", "src/lib.rs", "app/models.py", "index.ts"] {
            assert_eq!(
                agent_withheld(&path(source), None, None),
                Some(WithheldReason::SourceUnit),
                "{source}"
            );
        }
        for other in ["README.md", "coverage.out", "config.yaml", "go.mod.bak"] {
            assert_eq!(
                agent_withheld(&path(other), None, None),
                Some(WithheldReason::NotAToolchainManifest),
                "{other}"
            );
        }
        // A build output is a build output whatever it is named.
        assert_eq!(
            agent_withheld(&path("go.mod"), Some(WithheldReason::BuildOutput), None),
            Some(WithheldReason::BuildOutput)
        );
        // A toolchain's run hands back its own manifests only, so a Go
        // program that writes a package.json or a data file keeps neither.
        let go = Some(Toolchain::Go);
        assert_eq!(agent_withheld(&path("go.sum"), None, go), None);
        for other in ["package.json", "Cargo.lock", "tasks.json"] {
            assert_eq!(
                agent_withheld(&path(other), None, go),
                Some(WithheldReason::NotAToolchainManifest),
                "{other}"
            );
        }
        assert_eq!(
            agent_withheld(&path("Cargo.lock"), None, Some(Toolchain::Rust)),
            None
        );
    }
}
