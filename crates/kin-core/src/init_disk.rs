// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whether the filesystem a conversion stages on has room for it, read before
//! the conversion writes anything.
//!
//! A conversion stages beside the repository and publishes into it, so all of
//! its writes land on the filesystem that holds the repository's parent. Nothing
//! used to look at how much of that filesystem was free. A store can be two
//! orders of magnitude larger than the Git object store it was admitted from,
//! so a laptop with a few gigabytes free could spend twenty minutes converting
//! and then fail on a full disk, taking every other program writing to that
//! disk down with it.
//!
//! # What is refused, and what is only said
//!
//! Two numbers, held to different standards, as the memory forecast beside
//! this one is.
//!
//! The refusal is drawn at a floor the conversion's own mechanism guarantees.
//! It reads Git into a capture and copies every body into the store it writes,
//! and neither copy is compressed, so while the copy runs every file version
//! reachable from HEAD is on this filesystem twice. A filesystem with less free
//! than that cannot hold the conversion whatever the repository is like, so a
//! refusal there cannot turn away a conversion that would have finished.
//!
//! The larger number is only said. How big a store grows past that floor
//! depends on the history and the language, and the measured range is wide:
//! see [`SMALLEST_MEASURED_STORE_RATIO`] and [`LARGEST_MEASURED_STORE_RATIO`].
//! A repository of large binary files can land near its floor, well below what
//! the ratio forecasts, so a refusal drawn from the ratio would turn away work
//! that fits. A conversion whose free space is under the ratio's forecast is
//! told so in one line and carries on.

use std::path::{Path, PathBuf};

use crate::init_attempt::human_bytes;

/// Name an operator uses to tell a conversion how much free space it really
/// has, in bytes.
///
/// Two audiences, like the memory ceiling's lever. A filesystem that compresses
/// or deduplicates what it stores, such as ZFS or btrfs with compression on,
/// uses fewer bytes than the uncompressed bodies this check counts, and its
/// owner can say how much it will really take. And a test can pin the number
/// rather than fill a disk to prove the refusal.
pub const INIT_DISK_FREE_ENV: &str = "KIN_INIT_DISK_FREE_BYTES";

/// Copies of every reachable file version a conversion holds on disk at once.
///
/// One in the capture Git is read into and one in the store's source-blob
/// store, which the conversion fills by copying from the capture while the
/// capture still exists. Neither is compressed and neither is delta encoded.
const VERBATIM_COPIES: u64 = 2;

/// The smallest store-to-Git-object-store ratio measured on a real repository
/// on a current release: expressjs/express under kin 0.7.21, whose own closing
/// line read "513.7 MiB under .kin/, 48.5x the 10.6 MiB Git object store".
///
/// In tenths, because the measurement has one decimal and rounding it to a
/// whole number would state a range the measurements do not.
const SMALLEST_MEASURED_STORE_RATIO: StoreRatio = StoreRatio {
    tenths: 485,
    repository: "expressjs/express",
    release: "0.7.21",
};

/// The largest store-to-Git-object-store ratio measured on an init-only store
/// on a current release: BurntSushi/ripgrep under kin 0.7.2, 703.9 MiB over a
/// 5.7 MiB Git object store, recorded in `docs/store-size.md`.
///
/// Stores measured after an embedding pass run larger, because they carry a
/// vector index the conversion itself does not write, and are left out for
/// that reason, as `docs/store-size.md` leaves them out.
const LARGEST_MEASURED_STORE_RATIO: StoreRatio = StoreRatio {
    tenths: 1227,
    repository: "BurntSushi/ripgrep",
    release: "0.7.2",
};

/// How many directory entries the Git object store walk visits at most.
///
/// A packed repository holds a handful of files. One that has never been
/// packed can hold a file per object, and this check runs before any work, so
/// it stops counting rather than walk millions of loose objects. A walk that
/// stops early is a floor, and the forecast it feeds says so.
const OBJECT_WALK_ENTRY_LIMIT: usize = 200_000;

/// One measured store-to-object-store ratio and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoreRatio {
    tenths: u64,
    repository: &'static str,
    release: &'static str,
}

impl StoreRatio {
    fn of(&self, bytes: u64) -> u64 {
        bytes.saturating_mul(self.tenths) / 10
    }

    fn render(&self) -> String {
        format!("{}.{}x", self.tenths / 10, self.tenths % 10)
    }
}

/// The two sizes a conversion's disk need is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSurvey {
    /// Bytes of every distinct file version reachable from HEAD, uncompressed.
    pub history_bytes: u64,
    /// Bytes under the Git object store, packfiles and loose objects both.
    pub git_object_bytes: u64,
    /// Whether the object store walk stopped early or skipped an unreadable
    /// entry, which makes `git_object_bytes` a floor rather than a total.
    pub git_objects_partial: bool,
}

impl DiskSurvey {
    /// The least free space this conversion can run in, whatever the
    /// repository is like.
    pub fn floor_bytes(&self) -> u64 {
        self.history_bytes.saturating_mul(VERBATIM_COPIES)
    }

    /// What the store is forecast to take at the large end of what has been
    /// measured, with the capture beside it until the conversion ends.
    pub fn forecast_bytes(&self) -> u64 {
        LARGEST_MEASURED_STORE_RATIO
            .of(self.git_object_bytes)
            .saturating_add(self.history_bytes)
            .max(self.floor_bytes())
    }

    fn git_objects_rendered(&self) -> String {
        if self.git_objects_partial {
            format!("at least {}", human_bytes(self.git_object_bytes))
        } else {
            human_bytes(self.git_object_bytes)
        }
    }
}

/// Where the free-space figure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeSpaceSource {
    /// The filesystem reported it.
    Filesystem,
    /// The operator named it in [`INIT_DISK_FREE_ENV`].
    Operator,
}

/// What the ladder decided about this conversion's disk before running it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskVerdict {
    /// Nothing is claimed, and the conversion proceeds exactly as before.
    Unmeasured { reason: String },
    /// The operator named a free-space figure this cannot read, so nothing is
    /// judged and the conversion does not start.
    InvalidFreeOverride { raw: String },
    /// Free space clears the forecast. Nothing is printed.
    Fits { survey: DiskSurvey, free_bytes: u64 },
    /// Free space clears the floor and not the forecast. One line is printed
    /// and the conversion carries on.
    Tight {
        survey: DiskSurvey,
        free_bytes: u64,
        filesystem: PathBuf,
        source: FreeSpaceSource,
    },
    /// Free space is under the floor. The conversion refuses here.
    Exceeds {
        survey: DiskSurvey,
        free_bytes: u64,
        filesystem: PathBuf,
        source: FreeSpaceSource,
    },
}

impl DiskVerdict {
    /// Whether the conversion must not start.
    pub fn refuses(&self) -> bool {
        matches!(
            self,
            Self::Exceeds { .. } | Self::InvalidFreeOverride { .. }
        )
    }

    /// The one line a conversion with room for its floor and not for its
    /// forecast prints.
    pub fn advisory_line(&self) -> Option<String> {
        let Self::Tight {
            survey,
            free_bytes,
            filesystem,
            source,
        } = self
        else {
            return None;
        };
        Some(format!(
            "  this conversion may not fit on disk: {} {}, and stores measured on current releases \
             came to between {} and {} their Git object store, which next to this repository's {} \
             would be up to about {} with the capture it copies from beside it. It needs at least \
             {} whatever it turns out to be, and that fits, so it carries on. If the disk fills \
             first, the conversion fails partway; to be sure instead, free more than {} there first",
            free_phrase(*free_bytes, *source),
            where_phrase(filesystem, *source),
            SMALLEST_MEASURED_STORE_RATIO.render(),
            LARGEST_MEASURED_STORE_RATIO.render(),
            survey.git_objects_rendered(),
            human_bytes(survey.forecast_bytes()),
            human_bytes(survey.floor_bytes()),
            human_bytes(survey.forecast_bytes()),
        ))
    }

    /// The refusal, as the lines an operator reads.
    pub fn refusal_lines(&self) -> Vec<String> {
        if let Self::InvalidFreeOverride { raw } = self {
            return vec![
                format!(
                    "{INIT_DISK_FREE_ENV} is set to {raw:?}, which is not a positive whole number \
                     of bytes"
                ),
                "  that variable names the free disk space this conversion is judged against, so \
                 a value Kin cannot read would disarm the check that stops a conversion filling \
                 the disk partway through"
                    .to_string(),
                format!(
                    "  set it to a byte count, for example {INIT_DISK_FREE_ENV}=107374182400 for \
                     100 GiB, or unset it to let Kin ask the filesystem"
                ),
            ];
        }
        let Self::Exceeds {
            survey,
            free_bytes,
            filesystem,
            source,
        } = self
        else {
            return Vec::new();
        };
        vec![
            format!(
                "this conversion needs more free disk than it has: at least {}, and {} {}",
                human_bytes(survey.floor_bytes()),
                free_phrase(*free_bytes, *source),
                where_phrase(filesystem, *source),
            ),
            format!(
                "  every file version reachable from HEAD, {} in all, is held twice while the \
                 conversion runs, once in the capture it reads Git into and once in the store it \
                 copies them to, and neither copy is compressed, so that much is needed before the \
                 semantic history is written on top",
                human_bytes(survey.history_bytes),
            ),
            format!(
                "  the finished store is larger than that: stores measured on current releases \
                 came to between {} ({}, kin {}) and {} ({}, kin {}) their Git object store, which \
                 next to this repository's {} would be up to about {} with the capture beside it",
                SMALLEST_MEASURED_STORE_RATIO.render(),
                SMALLEST_MEASURED_STORE_RATIO.repository,
                SMALLEST_MEASURED_STORE_RATIO.release,
                LARGEST_MEASURED_STORE_RATIO.render(),
                LARGEST_MEASURED_STORE_RATIO.repository,
                LARGEST_MEASURED_STORE_RATIO.release,
                survey.git_objects_rendered(),
                human_bytes(survey.forecast_bytes()),
            ),
            format!(
                "  free more than {} on that filesystem, or move the repository to a disk that has \
                 it, then run `kin init` again",
                human_bytes(survey.forecast_bytes()),
            ),
            format!(
                "  if this filesystem compresses or deduplicates what it stores, so it will use \
                 less than these uncompressed figures, set {INIT_DISK_FREE_ENV} to the free space \
                 to judge this conversion against, in bytes, and run again"
            ),
            "  nothing was written: this refusal happens before any capture, so there is no \
             staging to reclaim and no partial store to clean up"
                .to_string(),
        ]
    }
}

fn free_phrase(free_bytes: u64, source: FreeSpaceSource) -> String {
    match source {
        FreeSpaceSource::Filesystem => format!("{} is free", human_bytes(free_bytes)),
        FreeSpaceSource::Operator => format!(
            "{INIT_DISK_FREE_ENV} says {} is free",
            human_bytes(free_bytes)
        ),
    }
}

fn where_phrase(filesystem: &Path, source: FreeSpaceSource) -> String {
    match source {
        FreeSpaceSource::Filesystem => format!(
            "on the filesystem holding {}, where it stages",
            filesystem.display()
        ),
        FreeSpaceSource::Operator => format!(
            "for the filesystem holding {}, where it stages",
            filesystem.display()
        ),
    }
}

/// The free space this conversion is judged against, or why there is none.
fn free_space(staging_parent: &Path) -> Result<(u64, FreeSpaceSource), DiskVerdict> {
    if let Ok(raw) = std::env::var(INIT_DISK_FREE_ENV) {
        let trimmed = raw.trim();
        return match trimmed.parse::<u64>() {
            Ok(bytes) if bytes > 0 => Ok((bytes, FreeSpaceSource::Operator)),
            _ => Err(DiskVerdict::InvalidFreeOverride {
                raw: trimmed.to_string(),
            }),
        };
    }
    fs2::available_space(staging_parent)
        .map(|bytes| (bytes, FreeSpaceSource::Filesystem))
        .map_err(|error| DiskVerdict::Unmeasured {
            reason: format!(
                "the free space on the filesystem holding {} could not be read: {error}",
                staging_parent.display()
            ),
        })
}

/// Sum the bytes under the Git object store, stopping at
/// [`OBJECT_WALK_ENTRY_LIMIT`] entries.
///
/// Symlinks are skipped rather than followed, and an entry that cannot be read
/// is skipped and marks the sum a floor, which is what a partial walk is.
fn git_object_bytes(objects: &Path) -> (u64, bool) {
    let mut bytes = 0_u64;
    let mut partial = false;
    let mut visited = 0_usize;
    let mut pending = vec![objects.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            partial = true;
            continue;
        };
        for entry in entries {
            visited += 1;
            if visited > OBJECT_WALK_ENTRY_LIMIT {
                return (bytes, true);
            }
            let Ok(entry) = entry else {
                partial = true;
                continue;
            };
            let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
                partial = true;
                continue;
            };
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
            }
        }
    }
    (bytes, partial)
}

/// The Git object store `source` reads from, following a linked worktree or a
/// submodule's gitlink to the common directory that holds it.
fn git_objects_dir(source: &Path) -> Result<PathBuf, String> {
    let options = gix::open::Options::isolated().strict_config(true);
    let repo = gix::open_opts(source, options)
        .map_err(|error| format!("open {}: {error}", source.display()))?;
    Ok(repo.common_dir().join("objects"))
}

/// Decide, before any capture, whether this conversion fits on disk.
///
/// `history_bytes` is the reachable history the memory forecast already
/// counted, passed in so the history is walked once. When that forecast could
/// not run, the history is surveyed here instead.
pub fn assess(source: &Path, staging_parent: &Path, history_bytes: Option<u64>) -> DiskVerdict {
    let (free_bytes, source_of_free) = match free_space(staging_parent) {
        Ok(free) => free,
        Err(verdict) => return verdict,
    };
    let history_bytes = match history_bytes {
        Some(bytes) => bytes,
        None => match crate::init_budget::survey_history(source) {
            Ok(survey) => survey.history_bytes,
            Err(reason) => return DiskVerdict::Unmeasured { reason },
        },
    };
    let (git_object_bytes, git_objects_partial) = match git_objects_dir(source) {
        Ok(objects) => git_object_bytes(&objects),
        Err(_) => (0, true),
    };
    verdict_for(
        DiskSurvey {
            history_bytes,
            git_object_bytes,
            git_objects_partial,
        },
        free_bytes,
        staging_parent,
        source_of_free,
    )
}

/// The decision itself, over numbers rather than over a repository.
pub fn verdict_for(
    survey: DiskSurvey,
    free_bytes: u64,
    filesystem: &Path,
    source: FreeSpaceSource,
) -> DiskVerdict {
    if free_bytes < survey.floor_bytes() {
        return DiskVerdict::Exceeds {
            survey,
            free_bytes,
            filesystem: filesystem.to_path_buf(),
            source,
        };
    }
    if free_bytes < survey.forecast_bytes() {
        return DiskVerdict::Tight {
            survey,
            free_bytes,
            filesystem: filesystem.to_path_buf(),
            source,
        };
    }
    DiskVerdict::Fits { survey, free_bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    /// psf/requests: 112,474,615 bytes of reachable history, the figure the
    /// memory forecast's frontier walk measured, over the 13.9 MiB Git object
    /// store kin 0.7.21 reported when it converted the repository into a
    /// 1.5 GiB store.
    fn requests() -> DiskSurvey {
        DiskSurvey {
            history_bytes: 112_474_615,
            git_object_bytes: 14_575_000,
            git_objects_partial: false,
        }
    }

    fn verdict(survey: DiskSurvey, free: u64) -> DiskVerdict {
        verdict_for(
            survey,
            free,
            Path::new("/workspaces"),
            FreeSpaceSource::Filesystem,
        )
    }

    /// The floor is the two uncompressed copies and nothing else, so a refusal
    /// drawn there cannot turn away a conversion that would have fitted.
    #[test]
    fn the_refusal_is_drawn_at_twice_the_reachable_history() {
        let survey = requests();
        assert_eq!(survey.floor_bytes(), 2 * 112_474_615);
        assert!(verdict(survey, survey.floor_bytes() - 1).refuses());
        assert!(!verdict(survey, survey.floor_bytes()).refuses());
    }

    /// The measured store came in under the forecast, so a disk with room for
    /// the forecast had room for the store that was really written.
    #[test]
    fn the_forecast_covers_the_store_requests_really_wrote() {
        let written = 1536 * MIB;
        let survey = requests();
        assert!(
            survey.forecast_bytes() >= written + survey.history_bytes,
            "the forecast of {} must cover the {} store plus its capture",
            human_bytes(survey.forecast_bytes()),
            human_bytes(written)
        );
    }

    /// Between the floor and the forecast the conversion is told and carries on.
    #[test]
    fn a_disk_between_floor_and_forecast_is_warned_about_and_not_refused() {
        let survey = requests();
        let check = verdict(survey, survey.floor_bytes() + MIB);
        assert!(!check.refuses());
        let line = check
            .advisory_line()
            .expect("a disk under the forecast owes the reader a line");
        assert!(line.contains("may not fit on disk"), "{line}");
        assert!(line.contains("/workspaces"), "{line}");
        assert!(line.contains("48.5x") && line.contains("122.7x"), "{line}");
        assert!(line.contains("carries on"), "{line}");
    }

    /// A disk with room for the forecast says nothing, because a line about
    /// disk on every conversion is a line nobody reads.
    #[test]
    fn a_roomy_disk_is_silent() {
        let check = verdict(requests(), 500 * GIB);
        assert!(matches!(check, DiskVerdict::Fits { .. }));
        assert!(check.advisory_line().is_none());
        assert!(check.refusal_lines().is_empty());
    }

    /// The refusal names the need, the free space, the place, the measured
    /// range, the remedy, the override and that nothing was written.
    #[test]
    fn the_refusal_says_what_it_needs_where_and_what_to_do() {
        let survey = requests();
        let lines = verdict(survey, 100 * MIB).refusal_lines().join("\n");
        assert!(lines.contains("needs more free disk"), "{lines}");
        assert!(
            lines.contains(&human_bytes(survey.floor_bytes())),
            "{lines}"
        );
        assert!(lines.contains("100.0 MiB is free"), "{lines}");
        assert!(lines.contains("/workspaces"), "{lines}");
        assert!(lines.contains("expressjs/express, kin 0.7.21"), "{lines}");
        assert!(lines.contains("BurntSushi/ripgrep, kin 0.7.2"), "{lines}");
        assert!(lines.contains(INIT_DISK_FREE_ENV), "{lines}");
        assert!(lines.contains("nothing was written"), "{lines}");
    }

    /// A repository of large binaries sits near its floor, far under what the
    /// ratio forecasts, so the ratio may warn and must never refuse.
    #[test]
    fn a_binary_heavy_history_is_never_refused_on_the_ratio_alone() {
        let binaries = DiskSurvey {
            history_bytes: 5 * GIB,
            git_object_bytes: 5 * GIB,
            git_objects_partial: false,
        };
        let check = verdict(binaries, 11 * GIB);
        assert!(
            !check.refuses(),
            "11 GiB holds both 5 GiB copies, whatever a ratio says the store could reach"
        );
    }

    /// A walk that stopped early is shown as a floor.
    #[test]
    fn a_partial_object_store_walk_is_shown_as_a_floor() {
        let survey = DiskSurvey {
            git_objects_partial: true,
            ..requests()
        };
        let line = verdict(survey, survey.floor_bytes())
            .advisory_line()
            .expect("under the forecast");
        assert!(line.contains("at least 13.9 MiB"), "{line}");
    }

    /// The object store walk sums files and stops at its bound.
    #[test]
    fn the_object_walk_sums_files_under_the_store() {
        let root = tempfile::tempdir().unwrap();
        let pack = root.path().join("pack");
        std::fs::create_dir_all(&pack).unwrap();
        std::fs::write(pack.join("a.pack"), vec![0_u8; 3000]).unwrap();
        std::fs::write(root.path().join("loose"), vec![0_u8; 20]).unwrap();
        assert_eq!(git_object_bytes(root.path()), (3020, false));
        let (_, partial) = git_object_bytes(&root.path().join("absent"));
        assert!(
            partial,
            "an unreadable store is a floor, not a total of zero"
        );
    }

    /// An override Kin cannot read refuses rather than disarming the check.
    #[test]
    fn an_unreadable_override_refuses_by_name() {
        let refused = DiskVerdict::InvalidFreeOverride {
            raw: "lots".to_string(),
        };
        assert!(refused.refuses());
        let lines = refused.refusal_lines().join("\n");
        assert!(
            lines.contains(INIT_DISK_FREE_ENV) && lines.contains("\"lots\""),
            "{lines}"
        );
    }
}
