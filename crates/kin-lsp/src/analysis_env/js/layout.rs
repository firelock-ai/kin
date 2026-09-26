// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Kin's `node_modules` layout for one lock, built outside the repository.
//!
//! ```text
//! <layout>/
//!   <importer>/node_modules/<alias>   -> a package below, or the workspace package's source
//!   .kin/<package>/node_modules/<name>/     the package's files, linked from the store
//!   .kin/<package>/node_modules/<dep>       -> the package each dependency resolved to
//!   .kin/node_modules/<name>                -> one version of every package, for packages
//!                                              that import what they never declared
//!   .complete
//! ```
//!
//! Every importer's directory (the root, and each workspace package) is
//! mirrored at its path relative to the repository, so resolving an import
//! as if from `<layout>/<the importing file's path>` finds exactly the
//! dependencies the lock gives that importer. Each package's files are hard
//! links to the store's verified copy, so resolution inside a package, which
//! follows real paths, finds that package's own dependencies beside it, the
//! way pnpm's virtual store works. No lifecycle script runs, no binary is
//! linked into `.bin`, and nothing is written into the repository; a link
//! from the layout to a workspace package's source only reads it.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use super::lockfile::{Dep, JsLock};

/// The directory name one package key gets under `.kin`.
pub fn store_name(key: &str, name: &str, version: &str) -> String {
    let digest = sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(
        key.as_bytes(),
    ));
    let safe_version: String = version
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    format!(
        "{}@{safe_version}_{}",
        name.replace('/', "+"),
        &crate::adapters::contract::hex(&digest)[..10]
    )
}

/// The path from directory `from` to `to`, both absolute.
pub fn relative_to(from: &Path, to: &Path) -> PathBuf {
    let from: Vec<Component> = from.components().collect();
    let to: Vec<Component> = to.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut path = PathBuf::new();
    for _ in common..from.len() {
        path.push("..");
    }
    for part in &to[common..] {
        path.push(part);
    }
    path
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "analysis environments link their packages, which needs a unix host",
    ))
}

/// Link `link` to `target` with a relative link, creating its directory.
fn link_relative(target: &Path, link: &Path) -> Result<(), String> {
    let parent = link
        .parent()
        .ok_or_else(|| format!("{} has no directory", link.display()))?;
    std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    if std::fs::symlink_metadata(link).is_ok() {
        return Ok(());
    }
    symlink(&relative_to(parent, target), link)
        .map_err(|error| format!("{}: {error}", link.display()))
}

/// Link `link` to the absolute `target`, creating its directory.
fn link_absolute(target: &Path, link: &Path) -> Result<(), String> {
    let parent = link
        .parent()
        .ok_or_else(|| format!("{} has no directory", link.display()))?;
    std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    if std::fs::symlink_metadata(link).is_ok() {
        return Ok(());
    }
    symlink(target, link).map_err(|error| format!("{}: {error}", link.display()))
}

/// Recreate the tree at `from` under `to`, each file a hard link to the
/// store's copy (a copy where the filesystem refuses the link).
fn link_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)?.filter_map(Result::ok) {
        let kind = entry.file_type()?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            link_tree(&entry.path(), &target)?;
        } else if kind.is_file() && std::fs::hard_link(entry.path(), &target).is_err() {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Where a linked directory really is: the path the lock names, or, when
/// that is build output not yet built (`drizzle-orm/dist`), the nearest
/// directory above it that holds a `package.json`: the package's source.
fn link_target(base: &Path, relative: &str, root: &Path) -> PathBuf {
    let target = base.join(relative);
    if target.is_dir() {
        return target;
    }
    target
        .ancestors()
        .skip(1)
        .take_while(|dir| dir.starts_with(root))
        .find(|dir| dir.join("package.json").is_file())
        .map(Path::to_path_buf)
        .unwrap_or(target)
}

/// Build the layout for `lock` at `dir`, from the packages in `stored` (key
/// to its directory in the store), replacing any layout there. `root` is
/// the repository the importers are mirrored from.
pub fn build(
    dir: &Path,
    root: &Path,
    lock: &JsLock,
    stored: &BTreeMap<String, PathBuf>,
) -> Result<(), String> {
    let staging = dir.with_file_name(format!(
        ".{}.{}.tmp",
        dir.file_name().unwrap_or_default().to_string_lossy(),
        super::super::python::store::unique_suffix()
    ));
    let built = build_into(&staging, dir, root, lock, stored);
    if let Err(reason) = built {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(reason);
    }
    if dir.exists() {
        let retired = dir.with_file_name(format!(
            ".{}.{}.old",
            dir.file_name().unwrap_or_default().to_string_lossy(),
            super::super::python::store::unique_suffix()
        ));
        let _ = std::fs::rename(dir, &retired);
        let _ = std::fs::remove_dir_all(&retired);
    }
    super::super::python::store::publish_dir(&staging, dir)
}

fn build_into(
    staging: &Path,
    dir: &Path,
    root: &Path,
    lock: &JsLock,
    stored: &BTreeMap<String, PathBuf>,
) -> Result<(), String> {
    let base = lock.file.parent().unwrap_or(root);
    let mirror = staging.join(base.strip_prefix(root).unwrap_or(Path::new("")));
    let virtual_store = staging.join(".kin");
    let package_dir = |key: &str| -> Option<PathBuf> {
        let package = lock.packages.get(key)?;
        stored.get(key)?;
        Some(
            virtual_store
                .join(store_name(key, &package.name, &package.version))
                .join("node_modules")
                .join(&package.name),
        )
    };
    // Each package's files.
    let keys: Vec<&String> = stored.keys().collect();
    let failures: Vec<String> = super::super::parallel_map(&keys, 16, |key| {
        let (Some(from), Some(to)) = (stored.get(*key), package_dir(key)) else {
            return None;
        };
        link_tree(from, &to)
            .err()
            .map(|error| format!("{}: {error}", to.display()))
    })
    .into_iter()
    .flatten()
    .collect();
    if let Some(failure) = failures.first() {
        return Err(failure.clone());
    }
    // Each package's dependencies, beside it.
    for key in stored.keys() {
        let Some(package) = lock.packages.get(key) else {
            continue;
        };
        let modules = virtual_store
            .join(store_name(key, &package.name, &package.version))
            .join("node_modules");
        for (alias, dep) in &package.dependencies {
            if *alias == package.name {
                continue;
            }
            let link = modules.join(alias);
            match dep {
                Dep::Package(target) => {
                    if let Some(target) = package_dir(target) {
                        link_relative(&target, &link)?;
                    }
                }
                Dep::Link(path) => link_absolute(&link_target(base, path, root), &link)?,
                Dep::Missing(_) => {}
            }
        }
    }
    // Every importer's direct dependencies, at its mirrored path.
    for (importer, manifest) in &lock.importers {
        let modules = mirror.join(importer).join("node_modules");
        for (alias, dep) in &manifest.dependencies {
            let link = modules.join(alias);
            match dep {
                Dep::Package(target) => {
                    if let Some(target) = package_dir(target) {
                        link_relative(&target, &link)?;
                    }
                }
                Dep::Link(path) => link_absolute(&link_target(base, path, root), &link)?,
                Dep::Missing(_) => {}
            }
        }
    }
    // One version of every package where a package's walk up reaches, for
    // an import it never declared.
    let hoisted = virtual_store.join("node_modules");
    let mut seen = std::collections::BTreeSet::new();
    for key in stored.keys() {
        let Some(package) = lock.packages.get(key) else {
            continue;
        };
        if seen.insert(package.name.clone()) {
            if let Some(target) = package_dir(key) {
                link_relative(&target, &hoisted.join(&package.name))?;
            }
        }
    }
    std::fs::write(
        staging.join(".complete"),
        format!("layout of {} for {}\n", lock.file.display(), dir.display()),
    )
    .map_err(|error| format!("{}: {error}", staging.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_climb_to_the_common_directory() {
        assert_eq!(
            relative_to(
                Path::new("/l/.kin/a/node_modules/@s"),
                Path::new("/l/.kin/b/node_modules/b")
            ),
            PathBuf::from("../../../b/node_modules/b")
        );
        assert_eq!(
            relative_to(
                Path::new("/l/x/node_modules"),
                Path::new("/l/.kin/p/node_modules/p")
            ),
            PathBuf::from("../../.kin/p/node_modules/p")
        );
    }

    #[test]
    fn store_names_are_filesystem_safe_and_distinct() {
        let a = store_name("@s/a@1.0.0(peer@2.0.0)", "@s/a", "1.0.0");
        let b = store_name("@s/a@1.0.0(peer@3.0.0)", "@s/a", "1.0.0");
        assert!(a.starts_with("@s+a@1.0.0_"), "{a}");
        assert_ne!(a, b);
        assert!(!a.contains('/'));
    }
}
