// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A bounded, read-only walk of a repository, for the choices adapters make
//! before a server starts: which Cargo workspaces exist, which packages a
//! JavaScript workspace declares, which Go build tags are in use.
//!
//! This is configuration IO at the server-startup boundary, never a query
//! path. It reads names and a few manifests, follows no symbolic link, and
//! stops after a fixed number of entries so a huge or pathological tree costs
//! a bounded amount of time.

use std::path::Path;

/// The most directory entries one walk reads before it stops.
pub(crate) const MAX_ENTRIES: usize = 200_000;

/// How deep a walk goes below the workspace root.
pub(crate) const MAX_DEPTH: usize = 16;

/// Whether a directory holds no source of the repository's own: version
/// control and tool state, dependency trees, caches and a virtual environment.
/// A Rust `target` directory is recognised by the `CACHEDIR.TAG` Cargo writes,
/// so a source directory that happens to be named `target` is still read.
pub(crate) fn is_generated_dir(dir: &Path, name: &str) -> bool {
    name.starts_with('.')
        || matches!(name, "node_modules" | "__pycache__" | "bower_components")
        || dir.join("CACHEDIR.TAG").is_file()
        || dir.join("pyvenv.cfg").is_file()
}

/// Visit every regular file under `root` in a stable order, depth first and
/// by name, calling `visit(path, file_name)`.
///
/// A directory is entered only when it is not [`is_generated_dir`] and
/// `enter(dir, name)` agrees. Symbolic links are neither followed nor visited.
/// The walk returns early, having visited a prefix of the tree, once it has
/// read [`MAX_ENTRIES`] entries; it returns `false` then and `true` when it
/// read the whole tree.
pub(crate) fn walk_files(
    root: &Path,
    enter: &dyn Fn(&Path, &str) -> bool,
    visit: &mut dyn FnMut(&Path, &str),
) -> bool {
    let mut budget = MAX_ENTRIES;
    walk_dir(root, 0, enter, visit, &mut budget)
}

fn walk_dir(
    dir: &Path,
    depth: usize,
    enter: &dyn Fn(&Path, &str) -> bool,
    visit: &mut dyn FnMut(&Path, &str),
    budget: &mut usize,
) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    if entries.len() > *budget {
        return false;
    }
    *budget -= entries.len();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let path = entry.path();
        if kind.is_file() {
            visit(&path, name);
        } else if kind.is_dir()
            && depth < MAX_DEPTH
            && !is_generated_dir(&path, name)
            && enter(&path, name)
            && !walk_dir(&path, depth + 1, enter, visit, budget)
        {
            return false;
        }
    }
    true
}

/// Every file named `file_name` under `root`, in walk order.
#[cfg(test)]
pub(crate) fn files_named(
    root: &Path,
    file_name: &str,
    enter: &dyn Fn(&Path, &str) -> bool,
) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    walk_files(root, enter, &mut |path, name| {
        if name == file_name {
            found.push(path.to_path_buf());
        }
    });
    found
}

/// A directory made for one test and removed with it.
#[cfg(test)]
pub(crate) struct Fixture {
    pub root: std::path::PathBuf,
}

#[cfg(test)]
impl Fixture {
    pub(crate) fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "kin-lsp-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        Self { root }
    }

    pub(crate) fn write(&self, relative: &str, text: &str) -> std::path::PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }
}

#[cfg(test)]
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_walk_skips_generated_trees_and_keeps_a_source_dir_named_target() {
        let fixture = Fixture::new("scan");
        fixture.write("a/Cargo.toml", "");
        fixture.write("node_modules/x/Cargo.toml", "");
        fixture.write(".git/Cargo.toml", "");
        fixture.write("build/target/CACHEDIR.TAG", "");
        fixture.write("build/target/debug/Cargo.toml", "");
        fixture.write("src/target/Cargo.toml", "");
        fixture.write("venv/pyvenv.cfg", "");
        fixture.write("venv/lib/Cargo.toml", "");
        let found = files_named(&fixture.root, "Cargo.toml", &|_, _| true);
        let relative: Vec<_> = found
            .iter()
            .map(|path| path.strip_prefix(&fixture.root).unwrap().to_path_buf())
            .collect();
        assert_eq!(
            relative,
            vec![
                std::path::PathBuf::from("a/Cargo.toml"),
                std::path::PathBuf::from("src/target/Cargo.toml"),
            ]
        );
    }

    #[test]
    fn a_missing_root_is_an_empty_walk() {
        let found = files_named(Path::new("/nonexistent-kin-root"), "Cargo.toml", &|_, _| {
            true
        });
        assert!(found.is_empty());
    }
}
