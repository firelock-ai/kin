// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the store costs on disk, next to the Git object store it was admitted
//! from.
//!
//! Kin admits complete reachable history and derives a semantic entity layer
//! over all of it, so `.kin/` is not a copy of the packfile and is not bounded
//! by it. Measured repositories land on both sides of their Git object store:
//! a short history can finish below it, and a long one can finish two orders of
//! magnitude above it.
//!
//! Until this module existed neither number was reported anywhere. A user
//! learned their store size from `du`, after the disk was already spent, and had
//! nothing to compare it against. That is the whole defect being closed here.
//!
//! This module MEASURES and REPORTS. It does not bound, warn, refuse, or advise.
//! A ratio is a fact about how much history a repository carries, not a defect,
//! and dressing a measurement as a warning would make every large repository
//! look broken. Equally, a partial walk is never rendered as a total: an
//! unreadable entry turns the number into a stated floor, because a wrong number
//! printed confidently is the failure this module exists to end, not a smaller
//! version of it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Bytes summed from one directory tree, and whether the walk saw all of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeBytes {
    pub bytes: u64,
    /// Entries the walk could not stat or descend into.
    ///
    /// A non-zero count makes `bytes` a floor rather than a total, and every
    /// render says so. Silently dropping an unreadable subtree would report a
    /// store as smaller than it is, which is the same class of quiet wrong
    /// answer as not reporting it at all.
    pub unreadable_entries: usize,
}

impl TreeBytes {
    fn complete(&self) -> bool {
        self.unreadable_entries == 0
    }

    fn render(&self) -> String {
        if self.complete() {
            format_bytes(self.bytes)
        } else {
            format!(
                "at least {} ({} entries unreadable)",
                format_bytes(self.bytes),
                self.unreadable_entries
            )
        }
    }
}

/// The store's size on disk and the Git object store it is measured against.
///
/// The ratio is deliberately NOT a field. It is exactly `store / git_objects`,
/// both of which are here, so storing it would be a second encoding of the same
/// fact that a reader could find disagreeing with the first. Keeping the payload
/// to integers also keeps this type totally ordered and comparable, which the
/// status report it embeds in requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreFootprint {
    /// Bytes under `.kin/`. `None` when the store directory could not be walked
    /// at all, which renders as "not measured" and never as zero.
    pub store: Option<TreeBytes>,
    /// Bytes under the Git object store this repository was admitted from.
    ///
    /// `None` for a Kin-native repository that has no Git object store. There
    /// is then no ratio to report, which is a different statement from a ratio
    /// of zero or of infinity, and it is rendered as its own case.
    pub git_objects: Option<TreeBytes>,
    /// Why the store could not be measured, present only when `store` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmeasured_reason: Option<String>,
}

impl StoreFootprint {
    /// Measure `.kin/` and the Git object store beside it.
    ///
    /// Deliberately infallible. This is disclosure attached to commands that
    /// have already succeeded, so a failure to stat a directory must degrade to
    /// "not measured, because <reason>" rather than turn a completed `kin init`
    /// into an error.
    pub fn measure(layout: &kin_core::KinLayout) -> Self {
        let (store, unmeasured_reason) = match measure_tree(layout.root()) {
            Ok(tree) => (Some(tree), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let git_objects = git_object_dir(layout.working_dir())
            .and_then(|objects| measure_tree(&objects).ok())
            .filter(|tree| tree.bytes > 0);
        Self {
            store,
            git_objects,
            unmeasured_reason,
        }
    }

    /// Store bytes over Git object bytes, when both are known and the
    /// denominator is non-zero.
    pub fn ratio_to_git_objects(&self) -> Option<f64> {
        let store = self.store.as_ref()?;
        let git = self.git_objects.as_ref()?;
        (git.bytes > 0).then(|| store.bytes as f64 / git.bytes as f64)
    }

    /// The value rendered after a `Store size:` label.
    ///
    /// One function so `kin init` and `kin status` cannot drift into describing
    /// the same measurement differently, which is how a reader ends up believing
    /// two surfaces disagree about their own store.
    pub fn render(&self) -> String {
        let Some(store) = self.store.as_ref() else {
            let reason = self
                .unmeasured_reason
                .as_deref()
                .unwrap_or("the store directory could not be read");
            return format!("not measured ({reason})");
        };
        match (self.git_objects.as_ref(), self.ratio_to_git_objects()) {
            (Some(git), Some(ratio)) => format!(
                "{} under .kin/, {} the {} Git object store",
                store.render(),
                render_ratio(ratio),
                git.render()
            ),
            _ => format!(
                "{} under .kin/ (no Git object store here to compare against)",
                store.render()
            ),
        }
    }
}

/// The sentence that turns a measured ratio into something a reader can act on.
///
/// The number alone invites exactly the wrong inference. A reader who sees
/// "40x" and knows only their checkout size concludes Kin wasted their disk,
/// and a reader who sees "0.6x" on a fresh repository concludes it will stay
/// there. Both are wrong for the same reason, so this states the mechanism once
/// and hands over where the measured range is recorded.
///
/// It deliberately asserts no band of its own. A number compiled into the binary
/// is a claim that ages against whatever the next measured repository does, and
/// a claim nobody re-measures is the thing this ticket is about.
pub fn store_size_notice() -> &'static str {
    "Store size grows with history depth rather than checkout size, so this ratio varies widely \
     between repositories; docs/store-size.md records what has been measured."
}

fn render_ratio(ratio: f64) -> String {
    if ratio >= 1.0 {
        format!("{ratio:.1}x")
    } else if ratio >= 0.01 {
        format!("{ratio:.2}x")
    } else {
        "<0.01x".to_string()
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0_usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Sum the file bytes under `root`, without following symlinks.
///
/// `Err` only when `root` itself cannot be opened, which is the one case that
/// must not be reported as a size. Everything deeper that fails is counted as
/// unreadable and surfaces in the render as a floor.
///
/// Symlinks are skipped rather than followed. A followed link either double
/// counts a subtree already inside `root` or charges the store for bytes that
/// live outside it, and both produce a number that does not describe the
/// directory it names.
fn measure_tree(root: &Path) -> std::io::Result<TreeBytes> {
    let mut bytes = 0_u64;
    let mut unreadable_entries = 0_usize;
    let mut pending = vec![root.to_path_buf()];
    let mut first = true;
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if first => return Err(error),
            Err(_) => {
                unreadable_entries += 1;
                continue;
            }
        };
        first = false;
        for entry in entries {
            let Ok(entry) = entry else {
                unreadable_entries += 1;
                continue;
            };
            let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
                unreadable_entries += 1;
                continue;
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                bytes = bytes.saturating_add(metadata.len());
            }
        }
    }
    Ok(TreeBytes {
        bytes,
        unreadable_entries,
    })
}

/// Resolve the Git object store for `working_dir`, however `.git` is spelled
/// there.
///
/// A plain clone has a `.git` directory. A linked worktree and a submodule have
/// a `.git` FILE pointing elsewhere, and a linked worktree's objects live in the
/// common directory rather than in its own gitdir. Kin is developed out of
/// linked worktrees, so the case that gets exercised first is the one a naive
/// `working_dir/.git/objects` join reports as absent.
fn git_object_dir(working_dir: &Path) -> Option<PathBuf> {
    let dot_git = working_dir.join(".git");
    let metadata = std::fs::symlink_metadata(&dot_git).ok()?;
    if metadata.file_type().is_dir() {
        return Some(dot_git.join("objects"));
    }
    let pointer = std::fs::read_to_string(&dot_git).ok()?;
    let target = pointer.lines().find_map(|line| {
        line.trim()
            .strip_prefix("gitdir:")
            .map(|target| target.trim().to_string())
    })?;
    let git_dir = resolve_against(working_dir, Path::new(&target));
    let common = std::fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .map(|common| resolve_against(&git_dir, Path::new(common.trim())))
        .unwrap_or(git_dir);
    Some(common.join("objects"))
}

fn resolve_against(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn footprint(store: u64, git: Option<u64>) -> StoreFootprint {
        let store = TreeBytes {
            bytes: store,
            unreadable_entries: 0,
        };
        let git_objects = git.map(|bytes| TreeBytes {
            bytes,
            unreadable_entries: 0,
        });
        StoreFootprint {
            store: Some(store),
            git_objects,
            unmeasured_reason: None,
        }
    }

    /// The reported case: a store far above the pack it came from must print
    /// both sizes and the multiple, because the multiple is the number the user
    /// could not get from `du` and the one the ticket is about.
    #[test]
    fn a_store_above_its_pack_reports_the_multiple() {
        // 936 MiB of store over a 5.7 MiB Git object store.
        let rendered = footprint(981_467_136, Some(5_976_883)).render();
        assert!(
            rendered.contains("164.2x"),
            "the multiple must be stated, not left to arithmetic: {rendered}"
        );
        assert!(
            rendered.contains("936.0 MiB") && rendered.contains("5.7 MiB"),
            "both measured sizes must appear so the ratio can be checked: {rendered}"
        );
    }

    /// The falsification. A store SMALLER than its Git object store must say so
    /// in the same shape, with a sub-1 multiple. A renderer that could only
    /// describe inflation would be reporting a conclusion rather than a
    /// measurement, and every short history would be misdescribed by it.
    #[test]
    fn a_store_below_its_pack_reports_a_fraction_not_inflation() {
        let rendered = footprint(151_552, Some(268_288)).render();
        assert!(
            rendered.contains("0.56x"),
            "a below-1x ratio must render at a precision that shows it: {rendered}"
        );
        assert!(
            !rendered.contains("1.0x") && !rendered.contains("0.0x"),
            "a fraction must not round into 1x or vanish into 0x: {rendered}"
        );
    }

    /// A tiny ratio must not round to `0.0x`, which reads as "the store is
    /// empty" rather than "the store is much smaller than the pack".
    #[test]
    fn a_vanishing_ratio_states_a_bound_rather_than_zero() {
        assert_eq!(render_ratio(0.004), "<0.01x");
        assert_eq!(render_ratio(0.5), "0.50x");
        assert_eq!(render_ratio(163.42), "163.4x");
    }

    /// A Kin-native repository has no Git object store. It must say there is
    /// nothing to compare against rather than print a ratio against zero.
    #[test]
    fn a_repository_with_no_git_object_store_reports_no_comparison() {
        let rendered = footprint(151_552, None).render();
        assert!(
            rendered.contains("no Git object store"),
            "absence of a comparison must be named: {rendered}"
        );
        assert!(
            !rendered.contains('x'),
            "no ratio may be printed when there is no denominator: {rendered}"
        );
    }

    /// An unreadable subtree makes the number a floor, and the render has to say
    /// so. A partial walk printed as a total is the quiet wrong answer this
    /// module exists to prevent.
    #[test]
    fn an_incomplete_walk_reports_a_floor_rather_than_a_total() {
        let rendered = TreeBytes {
            bytes: 4096,
            unreadable_entries: 3,
        }
        .render();
        assert!(
            rendered.contains("at least") && rendered.contains("3 entries unreadable"),
            "a partial walk must be stated as partial: {rendered}"
        );
    }

    /// A store that could not be walked at all must report that, never zero.
    #[test]
    fn an_unmeasurable_store_says_so_instead_of_reporting_zero() {
        let rendered = StoreFootprint {
            store: None,
            git_objects: None,
            unmeasured_reason: Some("permission denied".to_string()),
        }
        .render();
        assert!(rendered.starts_with("not measured"), "{rendered}");
        assert!(rendered.contains("permission denied"), "{rendered}");
    }

    /// The walk must sum real bytes off a real tree, including nested
    /// directories, or the whole disclosure is a formatter over a wrong number.
    #[test]
    fn the_walk_sums_nested_files() {
        let root = tempfile::tempdir().expect("temp root");
        let nested = root.path().join("kindb").join("text-index");
        std::fs::create_dir_all(&nested).expect("create nested");
        std::fs::write(root.path().join("manifest.json"), vec![0_u8; 100]).expect("write manifest");
        std::fs::write(nested.join("segment"), vec![0_u8; 2_000]).expect("write segment");
        let measured = measure_tree(root.path()).expect("walk the tree");
        assert_eq!(measured.bytes, 2_100);
        assert_eq!(measured.unreadable_entries, 0);
    }

    /// A root that does not exist is an error, not a size. Returning zero here
    /// would let a mistyped path render as an empty store.
    #[test]
    fn a_missing_root_is_an_error_rather_than_zero_bytes() {
        let root = tempfile::tempdir().expect("temp root");
        assert!(measure_tree(&root.path().join("absent")).is_err());
    }

    /// A gitlink file must resolve to the object store it points at. Kin is
    /// developed out of linked worktrees, where `.git` is a file, so this is the
    /// path a naive join reports as "no Git object store" on the maintainers'
    /// own machines.
    #[test]
    fn a_gitlink_worktree_resolves_to_the_common_object_store() {
        let root = tempfile::tempdir().expect("temp root");
        let common = root.path().join("main-repo").join(".git");
        let worktree_git = common.join("worktrees").join("lane");
        std::fs::create_dir_all(&worktree_git).expect("create worktree gitdir");
        std::fs::create_dir_all(common.join("objects")).expect("create objects");
        std::fs::write(worktree_git.join("commondir"), "../..\n").expect("write commondir");
        let checkout = root.path().join("checkout");
        std::fs::create_dir_all(&checkout).expect("create checkout");
        std::fs::write(
            checkout.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .expect("write gitlink");

        let resolved = git_object_dir(&checkout).expect("resolve a gitlink worktree");
        assert_eq!(
            std::fs::canonicalize(resolved).expect("canonicalize resolved"),
            std::fs::canonicalize(common.join("objects")).expect("canonicalize expected")
        );
    }

    /// A plain clone keeps the simple answer.
    #[test]
    fn a_plain_git_directory_resolves_to_its_own_object_store() {
        let root = tempfile::tempdir().expect("temp root");
        std::fs::create_dir_all(root.path().join(".git").join("objects")).expect("create objects");
        assert_eq!(
            git_object_dir(root.path()).expect("resolve a plain clone"),
            root.path().join(".git").join("objects")
        );
    }

    /// A directory with no Git at all yields no denominator, which is how a
    /// Kin-native repository reaches the "nothing to compare against" render.
    #[test]
    fn a_directory_without_git_has_no_object_store() {
        let root = tempfile::tempdir().expect("temp root");
        assert!(git_object_dir(root.path()).is_none());
    }
}
