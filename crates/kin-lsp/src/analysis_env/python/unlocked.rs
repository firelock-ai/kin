// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! An environment for a project that locks nothing.
//!
//! Many repositories declare their dependencies as ranges and lock no
//! versions. For those, Kin resolves the declared requirements itself with
//! uv, forbidding any build (`--no-build`), so versions come only from
//! published wheel metadata and no package code runs, for the pinned Python
//! on this platform, with a hash for every file. The result is kept in the
//! store, keyed by everything that went into it, so the environment stays the
//! same until the declarations change. It is recorded as resolved by Kin, not
//! locked: the repository chose the ranges, not these versions.
//!
//! The requirements are read statically: `[project]` dependencies and every
//! optional-dependency table, every `[dependency-groups]` group, uv's and
//! PDM's development dependencies, and the requirement lines of
//! `requirements*.txt` files. A `setup.py` is never run, so a project whose
//! dependencies exist only there declares none that Kin can read.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::adapters::contract::EnvironmentIdentity;

use super::index::IndexConfig;
use super::lockfile::normalize_name;
use super::plan::Target;

/// How long one resolution may take before it is abandoned.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(300);

/// The requirements a project declares, as PEP 508 strings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Declared {
    pub requirements: BTreeSet<String>,
    /// The files they were read from.
    pub sources: Vec<PathBuf>,
}

/// The distribution name a requirement string names.
fn requirement_name(requirement: &str) -> Option<String> {
    let name: String = requirement
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    (!name.is_empty()).then(|| normalize_name(&name))
}

fn strings(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The requirements of one `[dependency-groups]` group, following
/// `{ include-group = "..." }` entries.
fn group(groups: &toml::Table, name: &str, seen: &mut BTreeSet<String>) -> Vec<String> {
    if !seen.insert(name.to_string()) {
        return Vec::new();
    }
    let mut found = Vec::new();
    for item in groups
        .get(name)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(requirement) = item.as_str() {
            found.push(requirement.to_string());
        } else if let Some(included) = item.get("include-group").and_then(toml::Value::as_str) {
            found.extend(group(groups, included, seen));
        }
    }
    found
}

/// The requirement lines of a requirements file: options, local paths and
/// editable installs are left out; includes are followed.
fn requirement_lines(path: &Path, seen: &mut BTreeSet<PathBuf>) -> Vec<String> {
    if !seen.insert(path.to_path_buf()) {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let joined = text.replace("\\\n", " ");
    let mut found = Vec::new();
    for line in joined.lines() {
        let line = match line.find(" #") {
            Some(at) => &line[..at],
            None => line,
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(included) = line
            .strip_prefix("-r ")
            .or_else(|| line.strip_prefix("--requirement "))
        {
            if let Some(dir) = path.parent() {
                found.extend(requirement_lines(&dir.join(included.trim()), seen));
            }
            continue;
        }
        if line.starts_with('-') || line.starts_with('.') || line.starts_with('/') {
            continue;
        }
        let requirement = line.split(" --").next().unwrap_or(line);
        let requirement = requirement.split_whitespace().collect::<Vec<_>>().join(" ");
        if requirement_name(&requirement).is_some() {
            found.push(requirement);
        }
    }
    found
}

/// Everything the project at `root` declares, without the repository's own
/// packages, which resolve to source.
pub fn declared_requirements(root: &Path, own: &BTreeSet<String>) -> Declared {
    let mut declared = Declared::default();
    let add = |requirement: String, declared: &mut Declared| {
        if requirement_name(&requirement).is_some_and(|name| !own.contains(&name)) {
            declared.requirements.insert(requirement.trim().to_string());
        }
    };
    let pyproject = root.join("pyproject.toml");
    if let Some(table) = std::fs::read_to_string(&pyproject)
        .ok()
        .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
    {
        declared.sources.push(pyproject);
        let project = table.get("project");
        for requirement in strings(project.and_then(|p| p.get("dependencies"))) {
            add(requirement, &mut declared);
        }
        if let Some(extras) = project
            .and_then(|p| p.get("optional-dependencies"))
            .and_then(toml::Value::as_table)
        {
            for list in extras.values() {
                for requirement in strings(Some(list)) {
                    add(requirement, &mut declared);
                }
            }
        }
        if let Some(groups) = table
            .get("dependency-groups")
            .and_then(toml::Value::as_table)
        {
            let mut seen = BTreeSet::new();
            for name in groups.keys() {
                for requirement in group(groups, name, &mut seen) {
                    add(requirement, &mut declared);
                }
            }
        }
        let tool = table.get("tool");
        for requirement in strings(
            tool.and_then(|t| t.get("uv"))
                .and_then(|uv| uv.get("dev-dependencies")),
        ) {
            add(requirement, &mut declared);
        }
        if let Some(pdm) = tool
            .and_then(|t| t.get("pdm"))
            .and_then(|pdm| pdm.get("dev-dependencies"))
            .and_then(toml::Value::as_table)
        {
            for list in pdm.values() {
                for requirement in strings(Some(list)) {
                    add(requirement, &mut declared);
                }
            }
        }
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("requirements") && name.ends_with(".txt"))
        })
        .collect();
    files.extend(
        std::fs::read_dir(root.join("requirements"))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "txt")),
    );
    files.sort();
    let mut seen = BTreeSet::new();
    for file in files {
        let lines = requirement_lines(&file, &mut seen);
        if !lines.is_empty() {
            declared.sources.push(file);
        }
        for requirement in lines {
            add(requirement, &mut declared);
        }
    }
    declared
}

/// The name of a resolution in the store: a digest of what went into it.
pub fn resolution_key(declared: &Declared, target: &Target, index: &IndexConfig) -> String {
    let mut parts: Vec<String> = vec![
        "kin-python-resolution/1".to_string(),
        format!("3.{}", target.minor),
        target.platform.id(),
        index.index_url.clone(),
    ];
    parts.extend(index.extra_index_urls.iter().cloned());
    parts.extend(declared.requirements.iter().cloned());
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    EnvironmentIdentity::of(&parts).hex().to_string()
}

/// Where a resolution with this key is kept.
pub fn resolution_path(store: &Path, key: &str) -> PathBuf {
    store.join("resolutions").join(format!("{key}.txt"))
}

/// The command line that resolves `input` into `output`. uv is handed the
/// pinned CPython Kin fetched, so the only interpreter it queries is that
/// one, rather than every Python on the host.
#[allow(clippy::too_many_arguments)]
pub fn uv_command(
    uv: &Path,
    python: &Path,
    input: &Path,
    output: &Path,
    target: &Target,
    index: &IndexConfig,
    platform_triple: &str,
) -> Vec<String> {
    let mut args = vec![
        uv.display().to_string(),
        "pip".to_string(),
        "compile".to_string(),
        input.display().to_string(),
        "--no-build".to_string(),
        "--python".to_string(),
        python.display().to_string(),
        "--python-version".to_string(),
        format!("3.{}", target.minor),
        "--python-platform".to_string(),
        platform_triple.to_string(),
        "--generate-hashes".to_string(),
        "--no-header".to_string(),
        "--no-annotate".to_string(),
        "--quiet".to_string(),
        "--output-file".to_string(),
        output.display().to_string(),
    ];
    // uv reads its own configuration and variables; an index named only in
    // pip's configuration is passed on.
    if !index.is_pypi() && !index.source.starts_with("$UV") && !index.source.contains("uv.toml") {
        args.push("--default-index".to_string());
        args.push(index.index_url.clone());
        for extra in &index.extra_index_urls {
            args.push("--index".to_string());
            args.push(extra.clone());
        }
    }
    args
}

/// Resolve `declared` with uv into the store. Returns the command line run,
/// with the resolution's path or why it failed. The resolution is written
/// under a temporary name and renamed into place only when uv succeeds.
pub fn resolve_with_uv(
    uv: &Path,
    python: &Path,
    store: &Path,
    declared: &Declared,
    target: &Target,
    index: &IndexConfig,
    platform_triple: &str,
) -> (String, Result<PathBuf, String>) {
    let key = resolution_key(declared, target, index);
    let destination = resolution_path(store, &key);
    let dir = store.join("resolutions");
    let unique = super::store::unique_suffix();
    let input = dir.join(format!(".{key}.{unique}.in"));
    let output = dir.join(format!(".{key}.{unique}.out"));
    let command = uv_command(uv, python, &input, &output, target, index, platform_triple);
    let rendered = command
        .iter()
        .map(|arg| super::super::fetch::redact(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let text: String = declared
        .requirements
        .iter()
        .map(|requirement| format!("{requirement}\n"))
        .collect();
    if let Err(error) = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&input, text)) {
        return (rendered, Err(format!("{}: {error}", input.display())));
    }
    let result = (|| {
        let mut child = Command::new(&command[0])
            .args(&command[1..])
            .current_dir(&dir)
            .env("UV_CACHE_DIR", store.join("uv-cache"))
            .env("UV_NO_PROGRESS", "1")
            .env("UV_PYTHON_DOWNLOADS", "never")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("could not start {}: {error}", uv.display()))?;
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use std::io::Read;
                    let _ = pipe.read_to_string(&mut stderr);
                }
                if !status.success() {
                    let tail: String = stderr
                        .trim()
                        .lines()
                        .rev()
                        .take(6)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join(" ");
                    return Err(format!("uv could not resolve without building: {tail}"));
                }
                return Ok(());
            }
            if started.elapsed() > RESOLVE_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "uv did not resolve within {}s",
                    RESOLVE_TIMEOUT.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })();
    let _ = std::fs::remove_file(&input);
    let outcome = match result {
        Ok(()) => std::fs::rename(&output, &destination)
            .map(|()| destination.clone())
            .map_err(|error| format!("{}: {error}", destination.display())),
        Err(error) => {
            let _ = std::fs::remove_file(&output);
            Err(error)
        }
    };
    (rendered, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    /// requests' shape: runtime dependencies, extras, a dependency group that
    /// names the project itself with an extra, and a requirements file that
    /// installs the project editable. The project's own name never reaches
    /// the resolution.
    #[test]
    fn declared_requirements_are_read_without_running_anything() {
        let repo = Fixture::new("unlocked-declared");
        repo.write(
            "pyproject.toml",
            r#"
[project]
name = "requests"
dependencies = ["charset_normalizer>=2,<4", "idna>=2.5,<4"]
dynamic = ["version"]

[project.optional-dependencies]
socks = ["PySocks>=1.5.6, !=1.5.7"]
security = []

[dependency-groups]
test = ["requests[socks]", "pytest>=8", { include-group = "lint" }]
lint = ["ruff"]
"#,
        );
        repo.write(
            "requirements-dev.txt",
            "-e .[socks]\npytest>=2.8.0,<10\npytest-httpbin==2.1.0 \\\n  ; python_version >= '3.10'\n# comment\n",
        );
        repo.write("setup.py", "raise SystemExit('never run')\n");
        let own = BTreeSet::from(["requests".to_string()]);
        let declared = declared_requirements(&repo.root, &own);
        let listed: Vec<&str> = declared.requirements.iter().map(String::as_str).collect();
        assert_eq!(
            listed,
            vec![
                "PySocks>=1.5.6, !=1.5.7",
                "charset_normalizer>=2,<4",
                "idna>=2.5,<4",
                "pytest-httpbin==2.1.0 ; python_version >= '3.10'",
                "pytest>=2.8.0,<10",
                "pytest>=8",
                "ruff",
            ]
        );
        assert_eq!(declared.sources.len(), 2);
    }

    #[test]
    fn the_resolution_passes_no_build_and_the_target() {
        let target = Target {
            full_version: "3.14.7".to_string(),
            minor: 14,
            platform: crate::analysis_env::python::tags::Platform {
                os: crate::analysis_env::python::tags::Os::Mac(None),
                arch: "aarch64",
            },
        };
        let index = IndexConfig {
            index_url: "https://user:pw@mirror.example/simple".to_string(),
            extra_index_urls: Vec::new(),
            source: "/home/me/.config/pip/pip.conf".to_string(),
            network: Default::default(),
        };
        let command = uv_command(
            Path::new("/bin/uv"),
            Path::new("/kin/cpython/bin/python3.14"),
            Path::new("in"),
            Path::new("out"),
            &target,
            &index,
            "aarch64-apple-darwin",
        );
        let joined = command.join(" ");
        assert!(joined.contains("--no-build"), "{joined}");
        assert!(
            joined.contains("--python /kin/cpython/bin/python3.14"),
            "{joined}"
        );
        assert!(joined.contains("--python-version 3.14"), "{joined}");
        assert!(joined.contains("--python-platform aarch64-apple-darwin"));
        assert!(joined.contains("--generate-hashes"));
        assert!(joined.contains("--default-index https://user:pw@mirror.example/simple"));
    }
}
