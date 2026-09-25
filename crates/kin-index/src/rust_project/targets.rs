// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Versioned Cargo target discovery over a complete admitted path inventory.

use super::{join, parent, BuildError, CargoTarget};
use kin_model::{ArtifactId, TreeEntry};
use std::collections::{BTreeMap, BTreeSet};

type Entries = BTreeMap<String, (ArtifactId, TreeEntry)>;

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn flag(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    default: bool,
) -> Result<bool, String> {
    table.get(key).map_or(Ok(default), |v| {
        v.as_bool()
            .ok_or_else(|| format!("Cargo {key} is not boolean"))
    })
}

fn target_path(
    kind: &str,
    target_name: &str,
    package: &str,
    base: &str,
    entries: &Entries,
) -> Result<String, String> {
    if kind == "lib" {
        return join(base, "src/lib.rs");
    }
    let directory = match kind {
        "bin" => "src/bin",
        "example" => "examples",
        "test" => "tests",
        "bench" => "benches",
        _ => return Err("unsupported Cargo target kind".into()),
    };
    let mut candidates = vec![
        join(base, &format!("{directory}/{target_name}.rs"))?,
        join(base, &format!("{directory}/{target_name}/main.rs"))?,
    ];
    if kind == "bin" && target_name == package {
        candidates.push(join(base, "src/main.rs")?);
    }
    candidates.retain(|path| entries.contains_key(path));
    match candidates.as_slice() {
        [path] => Ok(path.clone()),
        _ => Err(format!(
            "Cargo {kind} {target_name} has missing/ambiguous inferred root"
        )),
    }
}

// Single-component Cargo member patterns. Unsupported recursive/bracket
// patterns refuse inheritance instead of approximating workspace membership.
fn component_matches(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let (mut i, mut j, mut star, mut retry) = (0, 0, None, 0);
    while j < v.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == v[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some(i);
            i += 1;
            retry = j;
        } else if let Some(s) = star {
            retry += 1;
            j = retry;
            i = s + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == b'*' {
        i += 1;
    }
    i == p.len()
}

fn member_matches(pattern: &str, member: &str) -> Result<bool, String> {
    if pattern.contains("**") || pattern.contains(['[', ']', '{', '}', '\\']) {
        return Err("unsupported Cargo workspace member pattern".into());
    }
    let p: Vec<_> = pattern.trim_end_matches('/').split('/').collect();
    let m: Vec<_> = member.split('/').collect();
    Ok(p.len() == m.len() && p.iter().zip(m).all(|(p, m)| component_matches(p, m)))
}

fn workspace_edition(
    manifest: &str,
    package: &toml::map::Map<String, toml::Value>,
    values: &BTreeMap<String, toml::Value>,
) -> Result<String, String> {
    let explicit = package
        .get("workspace")
        .map(|v| v.as_str().ok_or("Cargo package.workspace is not a string"))
        .transpose()?;
    let workspace = if let Some(path) = explicit {
        let directory = join(parent(manifest), path)?;
        join(&directory, "Cargo.toml")?
    } else {
        let mut directory = parent(manifest);
        loop {
            let candidate = if directory.is_empty() {
                "Cargo.toml".into()
            } else {
                format!("{directory}/Cargo.toml")
            };
            if values
                .get(&candidate)
                .is_some_and(|v| v.get("workspace").is_some())
            {
                break candidate;
            }
            if directory.is_empty() {
                return Err("Cargo inherited edition has no admitted workspace".into());
            }
            directory = parent(directory);
        }
    };
    let table = values
        .get(&workspace)
        .and_then(|v| v.get("workspace"))
        .and_then(toml::Value::as_table)
        .ok_or("Cargo workspace is missing/unproven")?;
    if workspace != manifest {
        let base = parent(&workspace);
        let dir = parent(manifest);
        let member = if base.is_empty() {
            dir
        } else {
            dir.strip_prefix(&format!("{base}/"))
                .ok_or("Cargo member is outside inherited workspace")?
        };
        let mut included = false;
        for key in ["members", "exclude"] {
            if let Some(patterns) = table.get(key) {
                let patterns = patterns
                    .as_array()
                    .ok_or("Cargo workspace member list is not an array")?;
                for pattern in patterns {
                    if member_matches(
                        pattern
                            .as_str()
                            .ok_or("Cargo workspace pattern is not a string")?,
                        member,
                    )? {
                        if key == "exclude" {
                            return Err("Cargo inherited package is excluded from workspace".into());
                        }
                        included = true;
                    }
                }
            }
        }
        if !included {
            return Err(
                "Cargo inherited member requires unsupported implicit path-dependency membership"
                    .into(),
            );
        }
    }
    table
        .get("package")
        .and_then(|v| v.get("edition"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "Cargo workspace package edition is missing".into())
}

fn edition(
    manifest: &str,
    package: &toml::map::Map<String, toml::Value>,
    values: &BTreeMap<String, toml::Value>,
) -> Result<String, String> {
    let result = match package.get("edition") {
        None => "2015".into(),
        Some(value) if value.as_str().is_some() => value.as_str().unwrap().to_owned(),
        Some(value)
            if value.as_table().is_some_and(|t| {
                t.len() == 1 && t.get("workspace").and_then(toml::Value::as_bool) == Some(true)
            }) =>
        {
            workspace_edition(manifest, package, values)?
        }
        _ => return Err("unsupported Cargo edition specification".into()),
    };
    if !matches!(result.as_str(), "2015" | "2018" | "2021" | "2024") {
        return Err("unsupported Cargo edition".into());
    }
    Ok(result)
}

pub(super) fn discover(
    values: &BTreeMap<String, toml::Value>,
    entries: &Entries,
    cap: usize,
) -> Result<Vec<CargoTarget>, BuildError> {
    let mut result = Vec::new();
    for (manifest, value) in values {
        if value.get("cargo-features").is_some() {
            return Err("unstable Cargo features are unproven".into());
        }
        let Some(package) = value.get("package") else {
            if value.get("workspace").is_some() {
                continue;
            }
            return Err(format!("{manifest} is not an admitted Cargo package/workspace").into());
        };
        let package = package.as_table().ok_or("Cargo package is not a table")?;
        let package_name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|s| name(s))
            .ok_or("unsupported Cargo package name")?;
        let edition = edition(manifest, package, values)?;
        let manual = ["lib", "bin", "example", "test", "bench"]
            .iter()
            .any(|k| value.get(*k).is_some());
        let default_auto = edition != "2015" || !manual;
        let base = parent(manifest);
        let mut selected: BTreeMap<(String, String), String> = BTreeMap::new();
        for kind in ["lib", "bin", "example", "test", "bench"] {
            if let Some(tables) = value.get(kind) {
                let tables: Vec<_> = if kind == "lib" {
                    vec![tables]
                } else {
                    tables
                        .as_array()
                        .ok_or("Cargo target list is not an array")?
                        .iter()
                        .collect()
                };
                for table in tables {
                    let table = table.as_table().ok_or("Cargo target is not a table")?;
                    if table
                        .get("required-features")
                        .is_some_and(|v| v.as_array().is_none_or(|v| !v.is_empty()))
                    {
                        return Err(
                            "Cargo target required features need configuration evidence".into()
                        );
                    }
                    let default_name = package_name.replace('-', "_");
                    let target_name = table
                        .get("name")
                        .and_then(toml::Value::as_str)
                        .or((kind == "lib").then_some(default_name.as_str()))
                        .filter(|s| name(s))
                        .ok_or("unsupported/missing Cargo target name")?;
                    if let Some(target_edition) = table.get("edition") {
                        if target_edition.as_str() != Some(edition.as_str()) {
                            return Err("per-target edition override is not proven".into());
                        }
                    }
                    let path = match table.get("path") {
                        Some(path) => join(
                            base,
                            path.as_str().ok_or("Cargo target path is not a string")?,
                        )?,
                        None => target_path(kind, target_name, package_name, base, entries)?,
                    };
                    if selected
                        .insert((kind.into(), target_name.into()), path)
                        .is_some()
                    {
                        return Err("duplicate Cargo target identity".into());
                    }
                }
            }
            let auto_key = match kind {
                "lib" => "autolib",
                "bin" => "autobins",
                "example" => "autoexamples",
                "test" => "autotests",
                _ => "autobenches",
            };
            if !flag(package, auto_key, default_auto)? {
                continue;
            }
            let mut inferred: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            let standard = match kind {
                "lib" => Some((package_name.replace('-', "_"), "src/lib.rs")),
                "bin" => Some((package_name.into(), "src/main.rs")),
                _ => None,
            };
            if let Some((name, path)) = standard {
                let path = join(base, path)?;
                if entries.contains_key(&path) {
                    inferred.entry(name).or_default().insert(path);
                }
            }
            if kind != "lib" {
                let directory = match kind {
                    "bin" => "src/bin",
                    "example" => "examples",
                    "test" => "tests",
                    _ => "benches",
                };
                let prefix = format!("{}/", join(base, directory)?);
                for path in entries.keys() {
                    let Some(rest) = path.strip_prefix(&prefix) else {
                        continue;
                    };
                    let candidate = if !rest.contains('/') {
                        rest.strip_suffix(".rs")
                    } else {
                        rest.strip_suffix("/main.rs")
                            .filter(|name| !name.contains('/'))
                    };
                    if let Some(candidate) = candidate {
                        if !name(candidate) {
                            return Err("unsupported inferred Cargo target name".into());
                        }
                        inferred
                            .entry(candidate.into())
                            .or_default()
                            .insert(path.clone());
                    }
                }
            }
            for (name, paths) in inferred {
                if selected.contains_key(&(kind.into(), name.clone()))
                    || (kind == "lib" && value.get("lib").is_some())
                {
                    continue;
                }
                if paths.len() != 1 {
                    return Err("competing automatic Cargo target roots".into());
                }
                selected.insert((kind.into(), name), paths.into_iter().next().unwrap());
            }
        }
        // The build script is a separate Rust executable crate too. Omitting
        // it could falsely certify agreement for a source included by both
        // a library and the build script under different crate roots.
        let default_build = join(base, "build.rs")?;
        let build = match package.get("build") {
            None => entries
                .contains_key(&default_build)
                .then_some(default_build),
            Some(toml::Value::Boolean(false)) => None,
            Some(toml::Value::Boolean(true)) => Some(default_build),
            Some(toml::Value::String(path)) => Some(join(base, path)?),
            _ => return Err("unsupported Cargo build-script setting".into()),
        };
        if let Some(root) = build {
            selected.insert(("build".into(), "build-script-build".into()), root);
        }
        for ((kind, name), root) in selected {
            if result.len() >= cap {
                return Err(BuildError::Refused(
                    "Cargo target count budget exceeded".into(),
                ));
            }
            if !matches!(
                entries.get(&root).map(|(_, entry)| entry),
                Some(TreeEntry::Blob { .. })
            ) {
                return Err(format!("Cargo root is not an admitted regular body: {root}").into());
            }
            result.push(CargoTarget {
                manifest: manifest.clone(),
                manifest_artifact: entries[manifest].0,
                kind,
                name,
                root,
                edition: edition.clone(),
            });
        }
    }
    Ok(result)
}
