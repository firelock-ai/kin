// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Where a locked crate is downloaded from, read from the user's own Cargo
//! configuration, and the crate store.
//!
//! Cargo's configuration is read the way Cargo reads it: `.cargo/config.toml`
//! (or `.cargo/config`) in the repository and every directory above it, the
//! nearer file winning, then `$CARGO_HOME/config.toml`, then `CARGO_*`
//! variables over all of them. A `[source.crates-io] replace-with` that names
//! a sparse mirror sends every crates.io download there; one that names a
//! directory means the repository vendors its crates and nothing is fetched.
//! A registry's download URL comes from its `config.json`, and its token,
//! when it asks for one, from the same places Cargo finds it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::super::fetch::{download_verified, FetchError, Fetcher, NetworkConfig};
use super::super::{python::store as shared, unpack, write_atomically};
use super::lockfile::CRATES_IO;

/// crates.io's download base, the `dl` of its index's `config.json`.
pub const CRATES_IO_DL: &str = "https://static.crates.io/crates";

/// The largest `.crate` file fetched.
pub const MAX_CRATE_BYTES: u64 = 512 * 1024 * 1024;

/// Cargo's configuration, merged.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CargoConfig {
    table: toml::Table,
    vars: HashMap<String, String>,
    /// The user's `CARGO_HOME`.
    pub cargo_home: Option<PathBuf>,
    /// The files read, nearest first.
    pub files: Vec<PathBuf>,
}

fn merge(into: &mut toml::Table, from: toml::Table) {
    for (key, value) in from {
        match (into.get_mut(&key), value) {
            (Some(toml::Value::Table(existing)), toml::Value::Table(incoming)) => {
                merge(existing, incoming)
            }
            (Some(_), _) => {}
            (None, value) => {
                into.insert(key, value);
            }
        }
    }
}

impl CargoConfig {
    /// The configuration a Cargo command run in `root` reads, on a host with
    /// these variables and this home.
    pub fn read(root: &Path, vars: &HashMap<String, String>, home: Option<&Path>) -> Self {
        let cargo_home = vars
            .get("CARGO_HOME")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|home| home.join(".cargo")));
        let mut candidates = Vec::new();
        for dir in root.ancestors() {
            candidates.push(dir.join(".cargo/config.toml"));
            candidates.push(dir.join(".cargo/config"));
        }
        if let Some(cargo_home) = &cargo_home {
            candidates.push(cargo_home.join("config.toml"));
            candidates.push(cargo_home.join("config"));
        }
        let mut table = toml::Table::new();
        let mut files = Vec::new();
        let mut seen_dirs = std::collections::BTreeSet::new();
        for file in candidates {
            // `config.toml` wins over `config` in one directory.
            let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
            if seen_dirs.contains(&dir) {
                continue;
            }
            let Some(parsed) = std::fs::read_to_string(&file)
                .ok()
                .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
            else {
                continue;
            };
            seen_dirs.insert(dir);
            merge(&mut table, parsed);
            files.push(file);
        }
        Self {
            table,
            vars: vars.clone(),
            cargo_home,
            files,
        }
    }

    fn get(&self, path: &[&str]) -> Option<&toml::Value> {
        let mut node = self.table.get(path[0])?;
        for part in &path[1..] {
            node = node.get(part)?;
        }
        Some(node)
    }

    fn string(&self, path: &[&str]) -> Option<String> {
        let variable = format!(
            "CARGO_{}",
            path.join("_").replace('-', "_").to_ascii_uppercase()
        );
        self.vars
            .get(&variable)
            .filter(|value| !value.is_empty())
            .cloned()
            .or_else(|| self.get(path)?.as_str().map(str::to_string))
    }

    /// The proxy and certificate authorities `[http]` names.
    pub fn network(&self) -> NetworkConfig {
        NetworkConfig {
            proxy: self.string(&["http", "proxy"]),
            ca_bundles: self
                .string(&["http", "cainfo"])
                .map(PathBuf::from)
                .into_iter()
                .collect(),
        }
    }

    /// Follow `replace-with` from source `name` to the source that serves.
    fn replacement_of(&self, name: &str) -> Option<(String, toml::Table)> {
        let mut current = name.to_string();
        let mut hops = 0;
        let mut replaced = None;
        while let Some(next) = self.string(&["source", &current, "replace-with"]) {
            hops += 1;
            if hops > 8 {
                return None;
            }
            current = next;
            replaced = self
                .get(&["source", &current])
                .and_then(toml::Value::as_table)
                .cloned()
                .map(|table| (current.clone(), table));
        }
        replaced
    }

    /// The name of the source crates.io is replaced with, after following
    /// every `replace-with`.
    pub fn crates_io_replacement(&self) -> Option<String> {
        self.replacement_of("crates-io").map(|(name, _)| name)
    }

    /// The registry name whose index is `index` (without its `registry+` or
    /// `sparse+` protocol prefix compared loosely).
    fn registry_named(&self, index: &str) -> Option<String> {
        let wanted = strip_protocol(index);
        self.get(&["registries"])?
            .as_table()?
            .iter()
            .find(|(_, registry)| {
                registry
                    .get("index")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|url| strip_protocol(url) == wanted)
            })
            .map(|(name, _)| name.clone())
    }

    /// The token for registry `name`: `CARGO_REGISTRIES_<NAME>_TOKEN`, the
    /// configuration, or `credentials.toml`.
    pub fn token(&self, name: &str) -> Option<String> {
        if let Some(token) = self.string(&["registries", name, "token"]) {
            return Some(token);
        }
        let credentials = self.cargo_home.as_ref().and_then(|home| {
            ["credentials.toml", "credentials"].iter().find_map(|file| {
                std::fs::read_to_string(home.join(file))
                    .ok()
                    .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
            })
        })?;
        credentials
            .get("registries")?
            .get(name)?
            .get("token")?
            .as_str()
            .map(str::to_string)
    }

    /// Where the crates of the registry the lock calls `source` come from.
    pub fn origin(&self, source: &str) -> Origin {
        let replaced = if source == CRATES_IO {
            self.replacement_of("crates-io")
        } else {
            self.registry_named(source)
                .and_then(|name| self.replacement_of(&name))
        };
        let index = match replaced {
            Some((name, table)) => {
                let text = |key: &str| {
                    table
                        .get(key)
                        .and_then(toml::Value::as_str)
                        .map(str::to_string)
                };
                if let Some(dir) = text("directory") {
                    return Origin::Vendored {
                        name,
                        dir: PathBuf::from(dir),
                    };
                }
                if let Some(dir) = text("local-registry") {
                    return Origin::Vendored {
                        name,
                        dir: PathBuf::from(dir),
                    };
                }
                match text("registry") {
                    Some(index) => index,
                    None => {
                        return Origin::Unsupported(format!(
                            "the source `{name}` that replaces it names no registry or directory"
                        ))
                    }
                }
            }
            None if source == CRATES_IO => return Origin::CratesIo,
            None => source.to_string(),
        };
        let index = index
            .strip_prefix("registry+")
            .map(str::to_string)
            .unwrap_or(index);
        match index.strip_prefix("sparse+") {
            Some(url) => Origin::Sparse {
                index: url.trim_end_matches('/').to_string(),
                token: self
                    .registry_named(&index)
                    .and_then(|name| self.token(&name)),
            },
            None => Origin::Unsupported(format!(
                "its registry index {index} is a git repository, and Kin reads only sparse \
                 indexes, over HTTP"
            )),
        }
    }
}

fn strip_protocol(url: &str) -> &str {
    let url = url.strip_prefix("registry+").unwrap_or(url);
    url.strip_prefix("sparse+")
        .unwrap_or(url)
        .trim_end_matches('/')
}

/// Where one registry's crates are downloaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// crates.io itself.
    CratesIo,
    /// A sparse index, whose `config.json` names the download URL.
    Sparse {
        index: String,
        token: Option<String>,
    },
    /// A directory the configuration vendors the crates in; nothing is
    /// fetched.
    Vendored { name: String, dir: PathBuf },
    /// Kin cannot fetch from it, and why.
    Unsupported(String),
}

/// A registry's download template, from its `config.json`, and whether it
/// wants a token on downloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloads {
    pub dl: String,
    pub auth_required: bool,
}

impl Downloads {
    pub fn crates_io() -> Self {
        Self {
            dl: CRATES_IO_DL.to_string(),
            auth_required: false,
        }
    }

    /// Read a sparse index's `config.json`.
    pub fn fetch(fetcher: &dyn Fetcher, index: &str) -> Result<Self, String> {
        let url = format!("{index}/config.json");
        let (_, bytes) = fetcher
            .document(&url, "application/json")
            .map_err(|error| error.to_string())?;
        let config: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{url} is not JSON: {error}"))?;
        Ok(Self {
            dl: config
                .get("dl")
                .and_then(|dl| dl.as_str())
                .ok_or_else(|| format!("{url} names no `dl`"))?
                .to_string(),
            auth_required: config.get("auth-required").and_then(|v| v.as_bool()) == Some(true),
        })
    }

    /// The URL of one crate's `.crate` file.
    pub fn url(&self, name: &str, version: &str, checksum: &str) -> String {
        let markers = [
            "{crate}",
            "{version}",
            "{prefix}",
            "{lowerprefix}",
            "{sha256-checksum}",
        ];
        if !markers.iter().any(|marker| self.dl.contains(marker)) {
            return format!(
                "{}/{name}/{version}/download",
                self.dl.trim_end_matches('/')
            );
        }
        let prefix = index_prefix(name);
        self.dl
            .replace("{crate}", name)
            .replace("{version}", version)
            .replace("{lowerprefix}", &prefix.to_ascii_lowercase())
            .replace("{prefix}", &prefix)
            .replace("{sha256-checksum}", checksum)
    }
}

/// The directory a crate's index entry lives under, as Cargo computes it.
pub fn index_prefix(name: &str) -> String {
    match name.len() {
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", &name[..1]),
        _ => format!("{}/{}", &name[..2], &name[2..4]),
    }
}

/// The directory a verified crate unpacks to, named by its digest.
pub fn crate_dir(store: &Path, sha256: &str) -> PathBuf {
    store.join("crates").join(sha256.to_ascii_lowercase())
}

/// Put one crate in the store: its `.crate` fetched, checked against the
/// lock's sha256 before anything is unpacked, unpacked as data, and marked
/// with the checksum file a Cargo directory source reads. Returns the
/// directory and the bytes downloaded, zero when the store held it.
pub fn ensure_crate(
    fetcher: &dyn Fetcher,
    store: &Path,
    url: &str,
    name: &str,
    version: &str,
    sha256: &str,
) -> Result<(PathBuf, u64), FetchError> {
    let destination = crate_dir(store, sha256);
    if destination.join(".cargo-checksum.json").is_file() {
        return Ok((destination, 0));
    }
    let unique = shared::unique_suffix();
    let archive = store
        .join("downloads")
        .join(format!("{name}-{version}.{unique}.crate"));
    let downloaded = download_verified(fetcher, url, &archive, sha256, MAX_CRATE_BYTES)?;
    let staging = store
        .join("crates")
        .join(format!(".{}.{unique}.tmp", sha256.to_ascii_lowercase()));
    let outcome = (|| -> Result<(), String> {
        unpack::untar_gz(&archive, &staging, unpack::TarLayout::DATA)?;
        let top = staging.join(format!("{name}-{version}"));
        if !top.join("Cargo.toml").is_file() {
            return Err(format!("the .crate holds no {name}-{version}/Cargo.toml"));
        }
        write_atomically(
            &top.join(".cargo-checksum.json"),
            serde_json::json!({ "files": {}, "package": sha256.to_ascii_lowercase() })
                .to_string()
                .as_bytes(),
        )?;
        shared::publish_dir(&top, &destination)
    })();
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_dir_all(&staging);
    outcome.map_err(FetchError::Io)?;
    Ok((destination, downloaded.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    #[test]
    fn download_urls_follow_the_dl_template() {
        let plain = Downloads::crates_io();
        assert_eq!(
            plain.url("serde", "1.0.0", "ab"),
            "https://static.crates.io/crates/serde/1.0.0/download"
        );
        let templated = Downloads {
            dl: "https://mirror.example/{prefix}/{crate}/{crate}-{version}.crate?sum={sha256-checksum}"
                .to_string(),
            auth_required: false,
        };
        assert_eq!(
            templated.url("Serde", "1.0.0", "ab"),
            "https://mirror.example/Se/rd/Serde/Serde-1.0.0.crate?sum=ab"
        );
        assert_eq!(index_prefix("a"), "1");
        assert_eq!(index_prefix("ab"), "2");
        assert_eq!(index_prefix("abc"), "3/a");
    }

    /// A replacement of crates.io in the repository's config wins over the
    /// user's, a directory replacement is vendoring, and a git index is named
    /// as unsupported.
    #[test]
    fn source_replacement_is_read_nearest_first() {
        let repo = Fixture::new("cargo-config");
        let home = Fixture::new("cargo-config-home");
        home.write(
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"corp\"\n\
             [source.corp]\nregistry = \"sparse+https://corp.example/index/\"\n\
             [registries.corp]\nindex = \"sparse+https://corp.example/index/\"\n",
        );
        home.write(
            ".cargo/credentials.toml",
            "[registries.corp]\ntoken = \"secret\"\n",
        );
        let vars = HashMap::new();
        let config = CargoConfig::read(&repo.root, &vars, Some(&home.root));
        assert_eq!(
            config.origin(CRATES_IO),
            Origin::Sparse {
                index: "https://corp.example/index".to_string(),
                token: Some("secret".to_string()),
            }
        );
        repo.write(
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"vendored\"\n\
             [source.vendored]\ndirectory = \"vendor\"\n",
        );
        let config = CargoConfig::read(&repo.root, &vars, Some(&home.root));
        assert!(matches!(config.origin(CRATES_IO), Origin::Vendored { .. }));
        repo.write(
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"git-mirror\"\n\
             [source.git-mirror]\nregistry = \"https://git.example/index\"\n",
        );
        let config = CargoConfig::read(&repo.root, &vars, Some(&home.root));
        assert!(
            matches!(config.origin(CRATES_IO), Origin::Unsupported(reason) if reason.contains("git"))
        );
        let empty = Fixture::new("cargo-config-empty");
        let config = CargoConfig::read(&empty.root, &vars, Some(&empty.root));
        assert_eq!(config.origin(CRATES_IO), Origin::CratesIo);
    }

    #[test]
    fn a_crate_is_verified_unpacked_and_marked_for_a_directory_source() {
        use crate::analysis_env::fetch::testing::FixedFetcher;
        use crate::analysis_env::unpack::testing::write_tar_gz;
        use sha2::Digest;
        let store = Fixture::new("crate-store");
        let archive = store.root.join("x.crate");
        write_tar_gz(
            &archive,
            &[
                ("demo-0.1.0/Cargo.toml", b"[package]\nname = \"demo\"\n"),
                ("demo-0.1.0/src/lib.rs", b"pub fn f() {}\n"),
            ],
        );
        let bytes = std::fs::read(&archive).unwrap();
        let sha = crate::adapters::contract::hex(&sha2::Sha256::digest(&bytes));
        let mut fetcher = FixedFetcher::default();
        fetcher
            .files
            .insert("https://dl.example/demo".to_string(), bytes);
        let (dir, downloaded) = ensure_crate(
            &fetcher,
            &store.root,
            "https://dl.example/demo",
            "demo",
            "0.1.0",
            &sha,
        )
        .unwrap();
        assert!(downloaded > 0);
        assert!(dir.join("src/lib.rs").is_file());
        let checksum: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(".cargo-checksum.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(checksum["package"], sha);
        let error = ensure_crate(
            &fetcher,
            &store.root,
            "https://dl.example/demo",
            "demo",
            "0.1.0",
            &"0".repeat(64),
        )
        .unwrap_err();
        assert!(matches!(error, FetchError::Mismatch { .. }), "{error}");
    }
}
