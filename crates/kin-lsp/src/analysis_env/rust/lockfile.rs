// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `Cargo.lock`, read for the crates it pins and the digests it pins them by.

use std::path::{Path, PathBuf};

/// The source id crates.io's packages carry in every lock, whichever
/// protocol fetched them.
pub const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Where one locked package comes from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CrateSource {
    /// A path dependency: source in or beside the repository, no lock entry
    /// to fetch.
    Path,
    /// A registry, by the source id the lock records (`registry+<url>` or
    /// `sparse+<url>`).
    Registry(String),
    /// A git repository at a commit. `reference` is the query the manifest
    /// named it by (`rev=..`, `branch=..`, `tag=..`), or `None` for the
    /// default branch.
    Git {
        url: String,
        reference: Option<(String, String)>,
        commit: String,
    },
    /// Anything else, verbatim.
    Other(String),
}

impl CrateSource {
    /// Read a lock's `source` value.
    pub fn parse(source: Option<&str>) -> Self {
        let Some(source) = source else {
            return CrateSource::Path;
        };
        if source.starts_with("registry+") || source.starts_with("sparse+") {
            return CrateSource::Registry(source.to_string());
        }
        if let Some(rest) = source.strip_prefix("git+") {
            let (location, commit) = rest.split_once('#').unwrap_or((rest, ""));
            let (url, query) = location.split_once('?').unwrap_or((location, ""));
            let reference = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(key, _)| matches!(*key, "rev" | "branch" | "tag"))
                .map(|(key, value)| (key.to_string(), value.to_string()));
            return CrateSource::Git {
                url: url.to_string(),
                reference,
                commit: commit.to_string(),
            };
        }
        CrateSource::Other(source.to_string())
    }

    /// The source id as the lock writes it.
    pub fn id(&self) -> String {
        match self {
            CrateSource::Path => String::new(),
            CrateSource::Registry(id) | CrateSource::Other(id) => id.clone(),
            CrateSource::Git {
                url,
                reference,
                commit,
            } => match reference {
                Some((key, value)) => format!("git+{url}?{key}={value}#{commit}"),
                None => format!("git+{url}#{commit}"),
            },
        }
    }
}

/// One package a lock pins.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockedCrate {
    pub name: String,
    pub version: String,
    pub source: CrateSource,
    /// The sha256 of the `.crate` file, for a registry package.
    pub checksum: Option<String>,
    /// The lock's dependency entries: `name`, `name version`, or
    /// `name version (source)`.
    pub dependencies: Vec<String>,
}

impl LockedCrate {
    pub fn pin(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// One `Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoLock {
    pub path: PathBuf,
    pub packages: Vec<LockedCrate>,
}

/// Read one `Cargo.lock`: the `[[package]]` entries, with checksums inline
/// (lock version 3 and later) or in the `[metadata]` table (versions 1 and
/// 2).
pub fn parse(path: &Path, text: &str) -> Result<CargoLock, String> {
    let table: toml::Table =
        toml::from_str(text).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = table.get("metadata").and_then(toml::Value::as_table);
    let mut packages = Vec::new();
    for package in table
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let field = |key: &str| package.get(key).and_then(toml::Value::as_str);
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            continue;
        };
        let source = CrateSource::parse(field("source"));
        let checksum = field("checksum").map(str::to_string).or_else(|| {
            let key = format!("checksum {name} {version} ({})", source.id());
            metadata?
                .get(&key)?
                .as_str()
                .filter(|value| *value != "<none>")
                .map(str::to_string)
        });
        let dependencies = package
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        packages.push(LockedCrate {
            name: name.to_string(),
            version: version.to_string(),
            source,
            checksum: checksum.map(|sum| sum.to_ascii_lowercase()),
            dependencies,
        });
    }
    Ok(CargoLock {
        path: path.to_path_buf(),
        packages,
    })
}

/// The locks beside the manifests `manifests` names, read and merged, with
/// the files that could not be read named.
pub fn read_locks(manifests: &[PathBuf]) -> (Vec<CargoLock>, Vec<String>) {
    let mut locks = Vec::new();
    let mut problems = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for manifest in manifests {
        let Some(dir) = manifest.parent() else {
            continue;
        };
        let path = dir.join("Cargo.lock");
        if !seen.insert(path.clone()) || !path.is_file() {
            continue;
        }
        match std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))
            .and_then(|text| parse(&path, &text))
        {
            Ok(lock) => locks.push(lock),
            Err(reason) => problems.push(reason),
        }
    }
    (locks, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
 "patched",
]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "DDC6F9CC94D67C0E21AA311B1B1E97B7E1283FA1CE4B9A51E9D5B3B8C8E8A1B7"

[[package]]
name = "patched"
version = "0.3.0"
source = "git+https://github.com/example/patched?branch=main#0123456789abcdef0123456789abcdef01234567"
dependencies = [
 "serde 1.0.200 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "internal"
version = "2.0.0"
source = "sparse+https://registry.example/index/"
checksum = "aa"
"#;

    #[test]
    fn a_v4_lock_names_sources_checksums_and_edges() {
        let lock = parse(Path::new("Cargo.lock"), V4).unwrap();
        assert_eq!(lock.packages.len(), 4);
        assert_eq!(lock.packages[0].source, CrateSource::Path);
        assert_eq!(lock.packages[0].dependencies, vec!["serde", "patched"]);
        assert_eq!(
            lock.packages[1].source,
            CrateSource::Registry(CRATES_IO.to_string())
        );
        assert_eq!(
            lock.packages[1].checksum.as_deref(),
            Some("ddc6f9cc94d67c0e21aa311b1b1e97b7e1283fa1ce4b9a51e9d5b3b8c8e8a1b7")
        );
        let git = &lock.packages[2].source;
        assert_eq!(
            *git,
            CrateSource::Git {
                url: "https://github.com/example/patched".to_string(),
                reference: Some(("branch".to_string(), "main".to_string())),
                commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
            }
        );
        assert_eq!(
            git.id(),
            "git+https://github.com/example/patched?branch=main#0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(
            lock.packages[3].source,
            CrateSource::Registry("sparse+https://registry.example/index/".to_string())
        );
    }

    #[test]
    fn a_v1_lock_keeps_its_checksums_in_metadata() {
        let text = r#"
[[package]]
name = "libc"
version = "0.2.50"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
"checksum libc 0.2.50 (registry+https://github.com/rust-lang/crates.io-index)" = "0123"
"#;
        let lock = parse(Path::new("Cargo.lock"), text).unwrap();
        assert_eq!(lock.packages[0].checksum.as_deref(), Some("0123"));
    }

    #[test]
    fn an_unreadable_lock_is_named() {
        let dir = crate::adapters::repo_scan::Fixture::new("cargo-lock-bad");
        let manifest = dir.write("Cargo.toml", "[package]\nname = \"x\"\n");
        dir.write("Cargo.lock", "[[package\n");
        let (locks, problems) = read_locks(&[manifest]);
        assert!(locks.is_empty());
        assert_eq!(problems.len(), 1);
    }
}
