// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable record of the replay semantics a store was created under.
//!
//! [`kin_index::history::HYDRATION_SEMANTICS_VERSION`] declares which revision
//! of the replay algorithm authors a repository's historical entity and relation
//! deltas. Its own doc comment says the constant is a declaration and not an
//! enforcement point: nothing persisted it beside a graph and nothing compared it
//! when one was opened, so bumping it recorded a decision no surface could act
//! on. This module is the half that makes the decision legible.
//!
//! The consequence was measured rather than imagined. kin#1186 raised the dial
//! from 9 to 10 because about 48% of the graph's entity population across five
//! production repositories was method-call receivers minted as `Module`
//! entities. Every store already admitted kept serving that population after the
//! fix shipped, and `kin status`, `kin doctor` and the `_kin` envelope all read
//! healthy over it.
//!
//! ## Where the stamp is written, and why there
//!
//! [`stamp_staged`] is called once, by
//! [`crate::init::prepare_repository_layout_with_origin`], which is the single
//! staging boundary every store-creation path goes through: `kin init` on a bare
//! directory, `kin init` over a Git checkout, a replica staged by `kin clone`,
//! and both of `kin-migrate`'s doors. It writes into the STAGED layout, before
//! the one no-replace rename that publishes `.kin`, so the store and its stamp
//! become visible in the same instant.
//!
//! That placement is what makes an absent stamp unambiguous, and the ambiguity
//! it removes is the whole hazard. An absence has producers, and keying a
//! verdict on one without enumerating the rest is how a healthy freshly
//! initialized store gets called stale. The producers of "no stamp" are:
//!
//! 1. A store created by a build that predates this record. Determinate: its
//!    graph was authored under replay semantics older than the constant this
//!    binary carries. That is every store in existence when this landed.
//! 2. A store whose creation is still in flight, or was killed part way. Not
//!    observable: the staged layout lives under `.kin.init-<uuid>` and is
//!    published by rename, so a `.kin` a reader can see is a conversion that
//!    finished. An interrupted one leaves staging, which `kin doctor`'s
//!    `interrupted_init` row is what reports.
//! 3. A store whose stamp write failed. Not reachable as a silent state: the
//!    write happens before publication and its error aborts the conversion,
//!    which cleans up the staging root rather than publishing a store missing
//!    its own record.
//! 4. A store whose stamp a person removed. Reads as (1), which errs toward
//!    disclosure and never toward a false all-clear.
//!
//! ## What the stamp claims, and what it does not
//!
//! It claims the version in force when this store was created, which for every
//! locally admitted store is the version its history was authored under. It does
//! not claim anything about history a replica later admits over the native
//! transport: those deltas were authored on whichever host converted the
//! repository, and the transport carries no version beside them. That limit is
//! recorded rather than papered over, and closing it belongs to the phase that
//! puts the version on the wire.
//!
//! ## What this module deliberately does not do
//!
//! It does not migrate, re-derive, or refuse. A gap is disclosed and the reader
//! decides. Auto-migration and refusal are later phases and carry their own
//! decisions.

use crate::layout::KinLayout;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Schema token carried in the record so a future format change is legible
/// rather than silently misparsed.
pub const HYDRATION_SEMANTICS_SCHEMA: &str = "kin.hydration-semantics.v1";

/// The replay-semantics version this binary derives history under.
///
/// Read straight from the declaring constant rather than mirrored here. A second
/// copy of a dial is a second thing to forget, and the manifest guard
/// (`scripts/verify-hydration-semantics.py`) pins the constant where it is
/// declared, not where it is consumed.
pub fn binary_version() -> u32 {
    kin_index::history::HYDRATION_SEMANTICS_VERSION
}

/// The replay-semantics version a store was created under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HydrationSemanticsStamp {
    pub schema: String,
    /// The value of `HYDRATION_SEMANTICS_VERSION` in the binary that created
    /// this store.
    pub created_under: u32,
    pub at: DateTime<Utc>,
}

impl HydrationSemanticsStamp {
    pub fn new(created_under: u32, at: DateTime<Utc>) -> Self {
        Self {
            schema: HYDRATION_SEMANTICS_SCHEMA.to_string(),
            created_under,
            at,
        }
    }
}

/// The outcome of consulting the record.
///
/// Three variants rather than an `Option`, for the reason the last-admission
/// marker beside it has three: a record that exists but will not parse is a
/// different and louder fact than one that was never written, and collapsing
/// them would let a truncated file present as a legacy store forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationSemanticsRead {
    Recorded(HydrationSemanticsStamp),
    Absent,
    Unreadable(String),
}

/// How the store's recorded version stands against the one this binary derives.
///
/// One type computed in one place, so `kin graph status`, `kin doctor` and the
/// `_kin` envelope cannot reach different conclusions about the same store. Each
/// surface renders it; none of them decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationStanding {
    /// The store was created under the version this binary derives.
    Current { version: u32 },
    /// The store was created under an older version, so its persisted history
    /// was authored by replay semantics this binary has since revised.
    Behind { created_under: u32, derives: u32 },
    /// The store was created under a newer version than this binary derives, so
    /// this binary is older than the build that made the store.
    Ahead { created_under: u32, derives: u32 },
    /// The store carries no record, which means it was created before one was
    /// written. See the producer enumeration in the module doc.
    Unstamped { derives: u32 },
    /// A record exists and could not be read. Never treated as agreement.
    Unreadable { reason: String, derives: u32 },
}

impl HydrationStanding {
    /// Whether this store's history and this binary's replay semantics disagree.
    ///
    /// [`HydrationStanding::Unreadable`] counts, because "we could not tell" is
    /// not "they agree", and a surface that silently treated it as agreement
    /// would reintroduce the defect this record exists to end.
    pub fn is_gap(&self) -> bool {
        !matches!(self, Self::Current { .. })
    }

    /// A stable machine label for the standing, for a structured report.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Current { .. } => "current",
            Self::Behind { .. } => "behind",
            Self::Ahead { .. } => "ahead",
            Self::Unstamped { .. } => "unstamped",
            Self::Unreadable { .. } => "unreadable",
        }
    }

    /// The one sentence every surface prints, so a reader who has seen it on
    /// `kin doctor` recognises it on `kin graph status` and in an agent's
    /// envelope.
    ///
    /// Names both numbers wherever both are known. "The graph is stale" invites
    /// a shrug; "authored under 9, this build derives 10" tells a reader what
    /// changed and lets them look up what version 10 fixed.
    pub fn sentence(&self) -> String {
        match self {
            Self::Current { version } => format!(
                "this graph was authored under hydration semantics version {version}, which is \
                 what this build derives"
            ),
            Self::Behind {
                created_under,
                derives,
            } => format!(
                "this graph was authored under hydration semantics version {created_under} and \
                 this build derives version {derives}, so its historical entities and relations \
                 are what the older replay produced and no path re-derives them in place"
            ),
            Self::Ahead {
                created_under,
                derives,
            } => format!(
                "this graph was authored under hydration semantics version {created_under} and \
                 this build derives the older version {derives}, so this binary is behind the \
                 build that created the store"
            ),
            Self::Unstamped { derives } => format!(
                "this graph records no hydration semantics version, so it was authored before \
                 stores recorded one and by replay semantics older than the version {derives} \
                 this build derives"
            ),
            Self::Unreadable { reason, derives } => format!(
                "this graph's hydration semantics record could not be read ({reason}), so which \
                 replay authored it is unknown rather than equal to the version {derives} this \
                 build derives"
            ),
        }
    }

    /// What the reader can do about it, when there is anything to do.
    ///
    /// A re-ingest is the only remedy phase one has, and it is honest only where
    /// this binary's replay is the newer one. Telling somebody running an old
    /// binary against a newer store to re-ingest would destroy the better graph
    /// with a worse one, so that case names the real fix instead.
    pub fn remedy(&self) -> Option<String> {
        match self {
            Self::Current { .. } => None,
            Self::Behind { .. } | Self::Unstamped { .. } => Some(
                "re-ingest the repository with `kin init` into a fresh store to author its \
                 history under this build's replay semantics"
                    .to_string(),
            ),
            Self::Ahead { .. } => Some(
                "upgrade this Kin build to at least the one that created the store, rather than \
                 re-ingesting, which would author its history under the older replay"
                    .to_string(),
            ),
            Self::Unreadable { .. } => Some(
                "re-ingest the repository with `kin init` into a fresh store to rewrite the \
                 record"
                    .to_string(),
            ),
        }
    }
}

/// Compare `read` against `derives`.
///
/// Split from the filesystem so every branch is testable without a store.
pub fn standing_of(read: &HydrationSemanticsRead, derives: u32) -> HydrationStanding {
    match read {
        HydrationSemanticsRead::Recorded(stamp) if stamp.created_under == derives => {
            HydrationStanding::Current { version: derives }
        }
        HydrationSemanticsRead::Recorded(stamp) if stamp.created_under < derives => {
            HydrationStanding::Behind {
                created_under: stamp.created_under,
                derives,
            }
        }
        HydrationSemanticsRead::Recorded(stamp) => HydrationStanding::Ahead {
            created_under: stamp.created_under,
            derives,
        },
        HydrationSemanticsRead::Absent => HydrationStanding::Unstamped { derives },
        HydrationSemanticsRead::Unreadable(reason) => HydrationStanding::Unreadable {
            reason: reason.clone(),
            derives,
        },
    }
}

/// Read the record for `layout`.
///
/// Never fails. A missing record is [`HydrationSemanticsRead::Absent`] and
/// anything unparseable is [`HydrationSemanticsRead::Unreadable`], both of which
/// the surfaces state honestly. A read error must never be able to present as
/// agreement.
pub fn read(layout: &KinLayout) -> HydrationSemanticsRead {
    let path = layout.kindb_hydration_semantics_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return HydrationSemanticsRead::Absent
        }
        Err(error) => return HydrationSemanticsRead::Unreadable(error.to_string()),
    };
    match serde_json::from_str::<HydrationSemanticsStamp>(&raw) {
        Ok(stamp) if stamp.schema == HYDRATION_SEMANTICS_SCHEMA => {
            HydrationSemanticsRead::Recorded(stamp)
        }
        Ok(stamp) => HydrationSemanticsRead::Unreadable(format!(
            "schema {} is not {HYDRATION_SEMANTICS_SCHEMA}",
            stamp.schema
        )),
        Err(error) => HydrationSemanticsRead::Unreadable(error.to_string()),
    }
}

/// This store's standing against this binary, for a `.kin` directory.
pub fn standing(layout: &KinLayout) -> HydrationStanding {
    standing_of(&read(layout), binary_version())
}

/// [`standing`], for a caller that holds a `.kin` path rather than a layout.
///
/// The MCP server discovers a `.kin` directory by walking up from the working
/// directory and never builds a layout, exactly as it does for the relation
/// census hold beside this.
pub fn standing_at(kin_root: &std::path::Path) -> HydrationStanding {
    standing(&KinLayout::new(kin_root.to_path_buf()))
}

/// Record the version this binary derives, into a STAGED layout.
///
/// Returns the error rather than swallowing it, which is the opposite of the
/// last-admission marker beside it and deliberate. That marker is written after
/// an admission is already durable, so failing the admission over the marker
/// would report admitted work as unadmitted. This one is written before the
/// rename that publishes anything, so a failure costs nothing already earned and
/// the alternative is publishing a store that misreports its own provenance for
/// the rest of its life.
pub fn stamp_staged(layout: &KinLayout) -> std::io::Result<()> {
    write(
        layout,
        &HydrationSemanticsStamp::new(binary_version(), Utc::now()),
    )
}

/// Write the record for `layout`, atomically.
///
/// Staged beside the target and renamed into place after an fsync, then the
/// directory metadata is synced, so a crash mid-write leaves either the previous
/// record or the new one and never a truncated file that would read as
/// unreadable forever. This mirrors how the last-admission marker beside it is
/// published.
pub fn write(layout: &KinLayout, stamp: &HydrationSemanticsStamp) -> std::io::Result<()> {
    use std::io::Write;

    let path = layout.kindb_hydration_semantics_path();
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::other("hydration semantics path has no parent directory")
    })?;
    std::fs::create_dir_all(parent)?;
    let staged = path.with_extension(format!("tmp-{}", std::process::id()));
    let body = serde_json::to_vec(stamp).map_err(std::io::Error::other)?;
    {
        let mut file = std::fs::File::create(&staged)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    if let Err(error) = std::fs::rename(&staged, &path) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    sync_directory_metadata(parent)?;
    Ok(())
}

/// Sync the containing directory so the rename that published the record is
/// itself durable.
#[cfg(unix)]
fn sync_directory_metadata(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(path).and_then(|directory| directory.sync_all())
}

/// Non-unix platforms expose no portable directory handle to sync, so the
/// rename's own ordering guarantees are all there is.
#[cfg(not(unix))]
fn sync_directory_metadata(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn layout_in(dir: &std::path::Path) -> KinLayout {
        let kin_dir = dir.join(".kin");
        std::fs::create_dir_all(kin_dir.join("kindb")).unwrap();
        KinLayout::new(kin_dir)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn a_written_record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let stamp = HydrationSemanticsStamp::new(9, at(1_000_000));
        write(&layout, &stamp).unwrap();
        assert_eq!(read(&layout), HydrationSemanticsRead::Recorded(stamp));
    }

    /// The durability property this record exists for: it outlives the process
    /// that wrote it, which is what every later reader is.
    #[test]
    fn a_record_survives_a_reader_that_did_not_write_it() {
        let dir = tempfile::tempdir().unwrap();
        {
            let layout = layout_in(dir.path());
            write(&layout, &HydrationSemanticsStamp::new(7, at(500))).unwrap();
        }
        let reopened = layout_in(dir.path());
        assert_eq!(
            standing_of(&read(&reopened), 10),
            HydrationStanding::Behind {
                created_under: 7,
                derives: 10
            }
        );
    }

    #[test]
    fn stamping_a_staged_layout_records_this_binarys_version() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        stamp_staged(&layout).unwrap();
        assert_eq!(standing(&layout), HydrationStanding::Current {
            version: binary_version()
        });
    }

    /// The dial is read from where it is declared, not mirrored. A second copy
    /// is a second thing to forget, and this is the assertion that would fail if
    /// one were ever introduced and drifted.
    #[test]
    fn the_binary_version_is_the_declared_constant() {
        assert_eq!(
            binary_version(),
            kin_index::history::HYDRATION_SEMANTICS_VERSION
        );
    }

    #[test]
    fn a_missing_record_is_unstamped_and_names_both_facts() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        assert_eq!(read(&layout), HydrationSemanticsRead::Absent);
        let standing = standing_of(&read(&layout), 10);
        assert_eq!(standing, HydrationStanding::Unstamped { derives: 10 });
        assert!(standing.is_gap());
        assert!(
            standing.sentence().contains("records no hydration semantics"),
            "an unstamped store must say so: {}",
            standing.sentence()
        );
        assert!(standing.sentence().contains("10"));
    }

    /// Absent and unreadable must not collapse into each other, and neither may
    /// present as agreement.
    #[test]
    fn a_corrupt_record_is_unreadable_rather_than_absent_or_current() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(layout.kindb_hydration_semantics_path(), b"{ truncated").unwrap();
        let read_back = read(&layout);
        assert!(
            matches!(read_back, HydrationSemanticsRead::Unreadable(_)),
            "a corrupt record must be unreadable, got {read_back:?}"
        );
        let standing = standing_of(&read_back, 10);
        assert!(standing.is_gap());
        assert_eq!(standing.label(), "unreadable");
        assert!(
            standing.sentence().contains("unknown"),
            "an unreadable record must not read as current: {}",
            standing.sentence()
        );
    }

    #[test]
    fn a_wrong_schema_is_unreadable_rather_than_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(
            layout.kindb_hydration_semantics_path(),
            br#"{"schema":"kin.hydration-semantics.v0","created_under":10,"at":"2026-08-27T00:00:00Z"}"#,
        )
        .unwrap();
        assert!(matches!(
            read(&layout),
            HydrationSemanticsRead::Unreadable(_)
        ));
    }

    /// Every branch of the comparison, including the two that must stay silent
    /// and the one nobody writes a test for. A standing that could only ever
    /// report a gap would pass an acceptance suite that only ever plants gaps.
    #[test]
    fn the_standing_separates_agreement_from_every_kind_of_gap() {
        let recorded = |version| {
            HydrationSemanticsRead::Recorded(HydrationSemanticsStamp::new(version, at(0)))
        };
        assert_eq!(
            standing_of(&recorded(10), 10),
            HydrationStanding::Current { version: 10 }
        );
        assert!(!standing_of(&recorded(10), 10).is_gap());
        assert!(standing_of(&recorded(10), 10).remedy().is_none());

        assert_eq!(
            standing_of(&recorded(9), 10),
            HydrationStanding::Behind {
                created_under: 9,
                derives: 10
            }
        );
        assert_eq!(
            standing_of(&recorded(11), 10),
            HydrationStanding::Ahead {
                created_under: 11,
                derives: 10
            }
        );
        assert_eq!(
            standing_of(&HydrationSemanticsRead::Absent, 10),
            HydrationStanding::Unstamped { derives: 10 }
        );
    }

    /// A store created by a newer build must not be told to re-ingest. That
    /// advice would replace a graph authored by the better replay with one
    /// authored by the worse, so the two gap directions carry different remedies
    /// and this is what separates them.
    #[test]
    fn an_ahead_store_is_not_told_to_re_ingest() {
        let behind = HydrationStanding::Behind {
            created_under: 9,
            derives: 10,
        };
        let ahead = HydrationStanding::Ahead {
            created_under: 11,
            derives: 10,
        };
        assert!(behind.remedy().unwrap().contains("re-ingest"));
        let advice = ahead.remedy().unwrap();
        assert!(
            advice.contains("upgrade") && !advice.contains("re-ingest the repository"),
            "an ahead store must not be told to re-ingest: {advice}"
        );
    }

    /// Both numbers, in every gap sentence that knows both. "The graph is
    /// stale" is true and unusable; the pair is what lets a reader look up what
    /// the newer version changed.
    #[test]
    fn every_gap_sentence_names_the_numbers_it_knows() {
        for standing in [
            HydrationStanding::Behind {
                created_under: 9,
                derives: 10,
            },
            HydrationStanding::Ahead {
                created_under: 11,
                derives: 10,
            },
        ] {
            let sentence = standing.sentence();
            assert!(sentence.contains("10"), "missing the derived version: {sentence}");
            assert!(
                sentence.contains('9') || sentence.contains("11"),
                "missing the recorded version: {sentence}"
            );
        }
    }
}
