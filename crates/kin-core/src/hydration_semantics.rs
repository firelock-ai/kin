// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable record of the replay-semantics version in force when a store was
//! created.
//!
//! [`kin_index::history::HYDRATION_SEMANTICS_VERSION`] declares which revision
//! of the replay algorithm this build uses when it authors historical entity and
//! relation deltas. Its own doc comment says the constant is a declaration and
//! not an enforcement point: nothing persisted it beside a graph and nothing
//! compared it when one was opened, so bumping it recorded a decision no surface
//! could act on. This module is the half that makes the decision legible.
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
//! and `kin-migrate`'s Git-admission path. It writes into the STAGED layout,
//! before the one no-replace rename that publishes `.kin`, so the store and its
//! stamp become visible in the same instant.
//!
//! That placement makes an absent stamp safe to disclose without confusing it
//! with an in-flight creation. An absence still has multiple producers, and
//! keying a stronger claim on one without enumerating the rest is how an
//! unverified store gets described as known-stale. The producers of "no stamp"
//! are:
//!
//! 1. A store created by a build that predates this record. This proves that the
//!    store carries no creation-time comparison, not that its history was
//!    authored under a particular older version. Version 10 existed before the
//!    record did, and replicas can receive history authored elsewhere.
//! 2. A store whose creation is still in flight, or was killed part way. Not
//!    observable: the staged layout lives under `.kin.init-<uuid>` and is
//!    published by rename, so a `.kin` a reader can see is a conversion that
//!    finished. An interrupted one leaves staging, which `kin doctor`'s
//!    `interrupted_init` row is what reports.
//! 3. A store whose stamp write failed. Not reachable as a silent state: the
//!    write happens before publication and its error aborts the conversion,
//!    which cleans up the staging root rather than publishing a store missing
//!    its own record.
//! 4. A store whose stamp a person removed. Reads as unverified, which errs
//!    toward disclosure and never toward a false all-clear.
//! 5. A store that admitted a native transfer whose declared authoring version
//!    was not the one this store records, or that declared none at all. This is
//!    the only producer that reaches a store a current build created, and what
//!    it says is exact: this store's own history was replayed under its creation
//!    version and it has since admitted history that was not.
//!
//! ## What the stamp claims, and what it does not
//!
//! It claims only the version in force when this store was created. For a local
//! conversion, creation and historical replay happen in the same operation.
//!
//! History a replica admits over the native transport was authored on whichever
//! host converted that repository, so a receiver can speak for it only when the
//! sender says which version authored it. That used to be recorded and then
//! contradicted by the runtime: a version-10 client cloning a repository whose
//! history was authored under version 9 got a version-10 creation stamp,
//! imported the version-9 deltas with no provenance beside them, and every
//! surface read `Current` over the result.
//!
//! The pack declares it now. `RepositoryTransferPack::source_hydration_semantics`
//! carries the sending store's own creation record, and
//! [`transfer_preserves_creation_record`] is the single comparison a receiver
//! makes over it: the record survives when the sender declared the exact version
//! this store records, and [`invalidate_for_unversioned_transfer`] discards it
//! otherwise, durably, before the authority commit that makes the history
//! visible. So two replicas of one build keep certifying their history through
//! every sync, and a receiver that admits history authored under a version it
//! cannot match reads [`HydrationStanding::Unstamped`] rather than certifying
//! provenance it does not have.
//!
//! Discarding is still what an unversioned sender gets, and that is the whole of
//! the conservative half: a hosted daemon owns no local creation record, and a
//! build older than this wire field declares nothing, so both leave the receiver
//! unstamped exactly as every transfer did before.
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

/// The record's file name inside `.kin/kindb`.
///
/// One constant rather than one string per caller. [`KinLayout`] joins it to
/// build the ambient path a reader opens, and [`HydrationStampCapability`]
/// resolves the same name through a retained directory handle. Two hardcoded
/// copies of one name would let a rename leave both halves green while they
/// addressed different files.
pub const HYDRATION_SEMANTICS_FILE_NAME: &str = "hydration-semantics";

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

impl HydrationSemanticsRead {
    /// The creation-time version this read establishes, when it establishes one.
    ///
    /// `None` for both gap variants. A record that will not parse establishes no
    /// version, and reporting "we could not tell" as a number is what the three
    /// variants beside it exist to prevent.
    pub fn created_under(&self) -> Option<u32> {
        match self {
            Self::Recorded(stamp) => Some(stamp.created_under),
            Self::Absent | Self::Unreadable(_) => None,
        }
    }
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
    /// The store records an older creation-time version than this binary
    /// derives. The record alone does not prove which replay authored history
    /// later admitted over the native transport.
    Behind { created_under: u32, derives: u32 },
    /// The store was created under a newer version than this binary derives, so
    /// this binary is older than the build that made the store.
    Ahead { created_under: u32, derives: u32 },
    /// The store carries no record, so no creation-time comparison can be made.
    /// See the producer enumeration in the module doc.
    Unstamped { derives: u32 },
    /// A record exists and could not be read. Never treated as agreement.
    Unreadable { reason: String, derives: u32 },
}

impl HydrationStanding {
    /// Whether the store's creation-time record differs from this binary or
    /// cannot establish agreement.
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
    /// a shrug; "the store records 9 at creation, this build derives 10" tells a
    /// reader what changed without claiming more provenance than the record
    /// contains.
    pub fn sentence(&self) -> String {
        match self {
            Self::Current { version } => format!(
                "this store records hydration semantics version {version} at creation, matching \
                 the version this build derives"
            ),
            Self::Behind {
                created_under,
                derives,
            } => format!(
                "this store records hydration semantics version {created_under} at creation and \
                 this build derives version {derives}, so the store cannot certify that its \
                 persisted history reflects this build's replay semantics and no path re-derives \
                 that history in place"
            ),
            Self::Ahead {
                created_under,
                derives,
            } => format!(
                "this store records hydration semantics version {created_under} at creation and \
                 this build derives the older version {derives}, so this binary predates the \
                 store's recorded semantics"
            ),
            Self::Unstamped { derives } => format!(
                "this store records no hydration semantics version, so its persisted history \
                 cannot be shown to match the version {derives} this build derives"
            ),
            Self::Unreadable { reason, derives } => format!(
                "this store's hydration semantics record could not be read ({reason}), so its \
                 creation-time version cannot be shown to match the version {derives} this build \
                 derives"
            ),
        }
    }

    /// What the reader can do about it, when there is anything to do.
    ///
    /// Re-ingest only when the record proves this binary is newer. An ahead,
    /// absent or unreadable record can belong to a newer store, so those cases
    /// name upgrade-first advice and preserve the original store until the
    /// direction is known.
    ///
    /// The unknown-provenance arm also refuses to presume a source. A native
    /// store is its own only source, so telling one to re-ingest names no
    /// reachable action; it says what re-ingesting actually does instead, and
    /// says first that the store keeps working. That is the sentence a store
    /// minutes old reads after its first sync with a peer it cannot match.
    pub fn remedy(&self) -> Option<String> {
        match self {
            Self::Current { .. } => None,
            Self::Behind { .. } => Some(
                "re-ingest the repository with `kin init` into a fresh store recorded under this \
                 build's replay semantics"
                    .to_string(),
            ),
            Self::Ahead { .. } => Some(
                "upgrade this Kin build to at least the one that created the store, rather than \
                 re-ingesting with the older replay version"
                    .to_string(),
            ),
            Self::Unstamped { .. } | Self::Unreadable { .. } => Some(
                "upgrade Kin to the newest build first, because a record this build cannot read \
                 can belong to a store a newer build created. If the newest build still reads no \
                 record, nothing recovers one in place: this store keeps serving its history with \
                 its creation-time version unknown, and re-ingesting builds a fresh store from \
                 source files rather than carrying this store's own history over"
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
    read_from(|| std::fs::read_to_string(layout.kindb_hydration_semantics_path()))
}

/// [`read`] over any source of the record's bytes.
///
/// One parser rather than one per caller. The daemon reads this record through a
/// directory handle it pinned at startup and every other surface reads it
/// through the layout's ambient path; two parsers would let one surface certify
/// a store the other discloses, which is the exact failure the three read
/// variants exist to prevent.
fn read_from(load: impl FnOnce() -> std::io::Result<String>) -> HydrationSemanticsRead {
    let raw = match load() {
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
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("hydration semantics path has no parent directory"))?;
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

/// Whether a receiver may keep its own creation record after admitting history
/// a pack declared was authored under `declared`.
///
/// True only when both numbers exist and are equal, which is deliberately narrow.
/// The record claims a creation-time version, so it can survive exactly the case
/// where the arriving deltas were replayed under the same version this store's
/// own history was. Every other pairing leaves the store holding history its
/// number does not speak for, which is what
/// [`invalidate_for_unversioned_transfer`] is for.
///
/// A receiver with no record of its own reads `false`, and that costs nothing:
/// discarding an absent record is a no-op that still makes the absence durable.
pub fn transfer_preserves_creation_record(recorded: Option<u32>, declared: Option<u32>) -> bool {
    recorded.is_some() && recorded == declared
}

/// Which of the two removal outcomes the invalidation observed.
///
/// Named rather than folded into a bool because the sync that follows must
/// happen on both, and a spy in the tests below asserts exactly that. An
/// earlier attempt can have unlinked the record and then failed its directory
/// sync, so a retry that treats `NotFound` as already-complete would commit
/// history before the first unlink is durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StampRemoval {
    Removed,
    NotFound,
}

/// The invalidation's two halves, with the filesystem passed in.
///
/// Split so a test can prove the ordering the transfer commit boundary depends
/// on without a store: the sync runs after the removal attempt, on both of its
/// outcomes, and a sync failure is the caller's error rather than a swallowed
/// one.
fn invalidate_with_sync(
    remove: impl FnOnce() -> std::io::Result<()>,
    sync: impl FnOnce(StampRemoval) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let removal = match remove() {
        Ok(()) => StampRemoval::Removed,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => StampRemoval::NotFound,
        Err(error) => return Err(error),
    };
    sync(removal)
}

/// Durably discard the creation record because this store has admitted history
/// the wire carried no version for.
///
/// Deletion rather than a rewrite to some "mixed" value, because there is no
/// honest value to write. The reader already maps absence to
/// [`HydrationStanding::Unstamped`], which every surface treats as a gap, so
/// the store discloses that its provenance is unknown instead of certifying a
/// creation-time number that no longer speaks for its contents.
///
/// The error is returned rather than logged. Its one caller runs it immediately
/// before the authority commit that publishes the transported history, and a
/// commit that proceeded over a failed invalidation would leave exactly the
/// false `Current` this exists to prevent.
pub fn invalidate_for_unversioned_transfer(layout: &KinLayout) -> std::io::Result<()> {
    let path = layout.kindb_hydration_semantics_path();
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("hydration semantics path has no parent directory"))?
        .to_path_buf();
    invalidate_with_sync(
        || std::fs::remove_file(&path),
        |_| sync_directory_metadata(&parent),
    )
}

/// A retained handle to one store's `.kin/kindb` directory, for the daemon path
/// that must not resolve it again at request time.
///
/// The local authority is already pinned at startup through a `LocalFileBackend`
/// opened once, because replacing `.kin/kindb` under a live daemon must not
/// silently redirect it. A path resolved per request would reintroduce exactly
/// that: a transfer admitted into the pinned namespace could invalidate the
/// stamp of whatever directory the display path pointed at by then. This holds
/// the same directory the backend was pinned to, opened once beside it.
///
/// Wrapping the capability here rather than exposing `cap_std` keeps the
/// dependency in the crate that already carries it, and keeps the Unix
/// directory `fsync` in one place.
#[derive(Debug)]
pub struct HydrationStampCapability {
    kindb: cap_std::fs::Dir,
    /// A second handle to the same directory, retained for the durability half.
    ///
    /// The removal goes through `kindb`, which is the capability that matters.
    /// The `fsync` cannot: on Linux the descriptor behind a `cap_std` directory
    /// refuses `fsync` with `EBADF`, which macOS accepts, so a run that is green
    /// on this host is red on the Linux leg. This is the same
    /// `File::open(dir).sync_all()` shape the record's writer already uses on
    /// both platforms, opened once beside the capability rather than resolved
    /// again at request time.
    #[cfg(unix)]
    sync_handle: std::fs::File,
}

impl HydrationStampCapability {
    /// Retain `kindb_dir`, which is `.kin/kindb` for a local store.
    pub fn open(kindb_dir: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self {
            kindb: cap_std::fs::Dir::open_ambient_dir(kindb_dir, cap_std::ambient_authority())?,
            #[cfg(unix)]
            sync_handle: std::fs::File::open(kindb_dir)?,
        })
    }

    /// This store's creation record, through the retained handle.
    pub fn read(&self) -> HydrationSemanticsRead {
        read_from(|| self.kindb.read_to_string(HYDRATION_SEMANTICS_FILE_NAME))
    }

    /// Reconcile this store's creation record against the version a received
    /// pack declared for the history it carries.
    ///
    /// Keeps the record when the sender declared the exact version this store
    /// records at creation, because the arriving deltas were then replayed under
    /// the same semantics this store's own history was and the number still
    /// speaks for the whole store. Discards it otherwise, which is what every
    /// transfer did before the wire carried a version at all.
    ///
    /// The error is returned rather than logged, for the reason
    /// [`invalidate_for_unversioned_transfer`] states: this runs immediately
    /// before the authority commit that publishes the transported history, and a
    /// commit that proceeded over a failed discard would leave exactly the false
    /// `Current` the discard exists to prevent.
    pub fn reconcile_after_transfer(&self, declared: Option<u32>) -> std::io::Result<()> {
        if transfer_preserves_creation_record(self.read().created_under(), declared) {
            return Ok(());
        }
        self.invalidate_for_unversioned_transfer()
    }

    /// [`invalidate_for_unversioned_transfer`], through the retained handle.
    pub fn invalidate_for_unversioned_transfer(&self) -> std::io::Result<()> {
        invalidate_with_sync(
            || self.kindb.remove_file(HYDRATION_SEMANTICS_FILE_NAME),
            |_| self.sync_kindb_metadata(),
        )
    }

    /// Make the unlink itself durable before a caller commits over it.
    #[cfg(unix)]
    fn sync_kindb_metadata(&self) -> std::io::Result<()> {
        self.sync_handle.sync_all()
    }

    /// Same durability boundary the record's writer states for this platform:
    /// no portable directory handle to sync, so the rename and unlink ordering
    /// guarantees are all there is.
    #[cfg(not(unix))]
    fn sync_kindb_metadata(&self) -> std::io::Result<()> {
        Ok(())
    }
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
        assert_eq!(
            standing(&layout),
            HydrationStanding::Current {
                version: binary_version()
            }
        );
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
            standing
                .sentence()
                .contains("records no hydration semantics"),
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
            standing.sentence().contains("cannot be shown to match"),
            "an unreadable record must not read as current: {}",
            standing.sentence()
        );
        let advice = standing.remedy().expect("an unreadable record has advice");
        assert!(
            advice.starts_with("upgrade Kin to the newest build"),
            "unknown provenance must preserve a potentially newer store: {advice}"
        );
        assert!(
            !advice.starts_with("re-ingest"),
            "unknown provenance must not begin with destructive re-ingest advice: {advice}"
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

    /// A store created by a newer build must not be told to re-ingest with this
    /// older binary. The two gap directions therefore carry different remedies.
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

    /// Unknown provenance can be a deleted record or a schema from a newer
    /// build. The advice must preserve the store until that distinction is known
    /// instead of treating every unknown as an older graph.
    #[test]
    fn unknown_provenance_is_given_non_destructive_advice() {
        for standing in [
            HydrationStanding::Unstamped { derives: 10 },
            HydrationStanding::Unreadable {
                reason: "schema kin.hydration-semantics.v2 is not v1".to_string(),
                derives: 10,
            },
        ] {
            let advice = standing.remedy().unwrap();
            assert!(advice.starts_with("upgrade Kin to the newest build"));
            assert!(!advice.contains("rewrite the record"));
            // A native store is its own only source, so the advice may not name
            // re-ingest as a step that keeps this store's history. The journey
            // run that produced this change read the old sentence on a native
            // store minutes old, where "re-ingest the repository into a separate
            // fresh store" named nothing the reader could do.
            assert!(
                !advice.contains("re-ingest the repository into a separate fresh store"),
                "unknown provenance must not presume a source outside the store: {advice}"
            );
            assert!(
                advice.contains("keeps serving its history"),
                "the advice must say the store still works: {advice}"
            );
            assert!(
                advice.contains("rather than carrying this store's own history over"),
                "the advice must say what re-ingesting costs: {advice}"
            );
        }
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
            assert!(
                sentence.contains("10"),
                "missing the derived version: {sentence}"
            );
            assert!(
                sentence.contains('9') || sentence.contains("11"),
                "missing the recorded version: {sentence}"
            );
        }
    }

    /// The record is creation-time provenance. Native replicas can later admit
    /// history authored elsewhere, and an absent record can also be a deleted
    /// file, so no sentence may upgrade the record into unproved authoring fact.
    #[test]
    fn sentences_claim_only_what_the_creation_record_proves() {
        let behind = HydrationStanding::Behind {
            created_under: 9,
            derives: 10,
        }
        .sentence();
        assert!(behind.contains("records hydration semantics version 9 at creation"));
        assert!(!behind.contains("was authored under"), "{behind}");

        let unstamped = HydrationStanding::Unstamped { derives: 10 }.sentence();
        assert!(
            unstamped.contains("cannot be shown to match"),
            "{unstamped}"
        );
        assert!(!unstamped.contains("older than"), "{unstamped}");
        assert!(!unstamped.contains("was authored"), "{unstamped}");
    }

    /// The one comparison a receiver makes over a declared authoring version,
    /// in every pairing. Five of the six must discard, and the sixth is the
    /// whole point of the change.
    #[test]
    fn a_creation_record_survives_only_a_declaration_that_matches_it() {
        assert!(transfer_preserves_creation_record(Some(10), Some(10)));
        assert!(!transfer_preserves_creation_record(Some(10), Some(9)));
        assert!(!transfer_preserves_creation_record(Some(9), Some(10)));
        assert!(!transfer_preserves_creation_record(Some(10), None));
        assert!(!transfer_preserves_creation_record(None, Some(10)));
        assert!(!transfer_preserves_creation_record(None, None));
    }

    /// The capability and the layout read one file through one parser. Asserted
    /// against what the layout's own writer produced rather than by comparing
    /// two hardcoded names, which is the shape where a rename leaves both halves
    /// green over different files.
    #[test]
    fn the_capability_reads_the_record_the_layout_names() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        write(&layout, &HydrationSemanticsStamp::new(7, at(2))).unwrap();
        let capability = HydrationStampCapability::open(&layout.kindb_dir()).unwrap();

        assert_eq!(capability.read(), read(&layout));
        assert_eq!(capability.read().created_under(), Some(7));

        std::fs::remove_file(layout.kindb_hydration_semantics_path()).unwrap();
        assert_eq!(capability.read(), HydrationSemanticsRead::Absent);
        assert_eq!(capability.read().created_under(), None);

        std::fs::write(layout.kindb_hydration_semantics_path(), b"{ truncated").unwrap();
        assert!(matches!(
            capability.read(),
            HydrationSemanticsRead::Unreadable(_)
        ));
        assert_eq!(
            capability.read().created_under(),
            None,
            "a record that will not parse must establish no version"
        );
    }

    /// The reconciliation on the real filesystem, through the capability the
    /// daemon holds. A matching declaration must leave the record BYTE-identical
    /// rather than rewrite it, because a rewrite would move the recorded
    /// timestamp and quietly restate a claim the receiver never re-earned.
    #[test]
    fn reconciling_after_a_transfer_keeps_only_a_matching_declaration() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        write(&layout, &HydrationSemanticsStamp::new(10, at(1))).unwrap();
        let path = layout.kindb_hydration_semantics_path();
        let before = std::fs::read(&path).unwrap();
        let capability = HydrationStampCapability::open(&layout.kindb_dir()).unwrap();

        capability.reconcile_after_transfer(Some(10)).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a matching declaration rewrote or removed the record"
        );
        assert_eq!(
            standing_of(&read(&layout), 10),
            HydrationStanding::Current { version: 10 }
        );

        capability.reconcile_after_transfer(Some(9)).unwrap();
        assert_eq!(
            read(&layout),
            HydrationSemanticsRead::Absent,
            "a declaration this store cannot match must cost it the record"
        );
    }

    /// A sender that declares nothing is a hosted daemon or a build older than
    /// the wire field, and both must still cost the receiver its record. This is
    /// the behaviour every transfer had before the declaration existed, and the
    /// arm that stops the change from becoming "keep the record always".
    #[test]
    fn reconciling_after_an_undeclared_transfer_discards_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        stamp_staged(&layout).unwrap();
        assert!(
            !standing(&layout).is_gap(),
            "the fixture did not start current"
        );

        HydrationStampCapability::open(&layout.kindb_dir())
            .unwrap()
            .reconcile_after_transfer(None)
            .unwrap();

        assert_eq!(read(&layout), HydrationSemanticsRead::Absent);
        assert_eq!(
            standing(&layout),
            HydrationStanding::Unstamped {
                derives: binary_version()
            }
        );
    }

    /// The invalidation the native transfer commit boundary depends on. A store
    /// that reads `Current` before admitting version-unknown history must read
    /// a gap after it, on the real filesystem and through the capability the
    /// daemon holds rather than through a path resolved again at request time.
    #[test]
    fn invalidating_a_current_store_leaves_it_unstamped() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        stamp_staged(&layout).unwrap();
        assert!(
            !standing(&layout).is_gap(),
            "the fixture did not start current"
        );

        let capability = HydrationStampCapability::open(&layout.kindb_dir()).unwrap();
        capability.invalidate_for_unversioned_transfer().unwrap();

        assert_eq!(read(&layout), HydrationSemanticsRead::Absent);
        assert_eq!(
            standing(&layout),
            HydrationStanding::Unstamped {
                derives: binary_version()
            }
        );
        assert!(standing(&layout).is_gap());
    }

    /// The capability and the layout must address one file. Asserted by writing
    /// through the layout's own path and requiring the capability to remove what
    /// that produced, rather than by comparing two hardcoded names, which is the
    /// shape where a rename leaves both halves green over different files.
    #[test]
    fn the_capability_removes_the_record_the_layout_names() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        write(&layout, &HydrationSemanticsStamp::new(9, at(1))).unwrap();
        let path = layout.kindb_hydration_semantics_path();
        assert!(path.exists(), "the writer produced no file at {path:?}");

        HydrationStampCapability::open(&layout.kindb_dir())
            .unwrap()
            .invalidate_for_unversioned_transfer()
            .unwrap();

        assert!(!path.exists(), "{path:?} survived the capability's removal");
    }

    /// A retry after a failed directory sync arrives with the record already
    /// gone. It must still succeed, and the sync assertion below is what stops
    /// that success from being a silent skip.
    #[test]
    fn invalidating_an_already_absent_record_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        assert_eq!(read(&layout), HydrationSemanticsRead::Absent);

        invalidate_for_unversioned_transfer(&layout).unwrap();
        HydrationStampCapability::open(&layout.kindb_dir())
            .unwrap()
            .invalidate_for_unversioned_transfer()
            .unwrap();

        assert_eq!(read(&layout), HydrationSemanticsRead::Absent);
    }

    /// The precondition the commit boundary rests on: the directory sync runs on
    /// BOTH removal outcomes. An earlier attempt can have unlinked the record and
    /// then failed its sync, so a retry that returned early on `NotFound` would
    /// let history commit over an unlink that is not yet durable.
    #[test]
    fn the_directory_sync_runs_on_both_removal_outcomes() {
        for (label, removal, expected) in [
            ("removed", Ok(()), StampRemoval::Removed),
            (
                "absent",
                Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
                StampRemoval::NotFound,
            ),
        ] {
            let mut observed: Option<StampRemoval> = None;
            invalidate_with_sync(
                || removal,
                |outcome| {
                    observed = Some(outcome);
                    Ok(())
                },
            )
            .unwrap_or_else(|error| panic!("{label} branch failed: {error}"));
            assert_eq!(observed, Some(expected), "{label} branch skipped the sync");
        }
    }

    /// A sync failure is the caller's error. Its one caller runs immediately
    /// before the authority commit that publishes transported history, and a
    /// commit that proceeded over a swallowed failure is the false `Current`
    /// this whole path exists to prevent.
    #[test]
    fn a_failed_directory_sync_propagates() {
        for removal in [
            Ok(()),
            Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        ] {
            let error = invalidate_with_sync(
                || removal,
                |_| Err(std::io::Error::other("directory sync refused")),
            )
            .expect_err("a failed sync reported success");
            assert!(
                error.to_string().contains("directory sync refused"),
                "{error}"
            );
        }
    }

    /// A removal error that is not `NotFound` stops before the sync and is
    /// returned, so the caller never commits over an unresolved record.
    #[test]
    fn a_removal_error_other_than_not_found_stops_the_invalidation() {
        let mut synced = false;
        let error = invalidate_with_sync(
            || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            |_| {
                synced = true;
                Ok(())
            },
        )
        .expect_err("a refused removal reported success");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!synced, "the sync ran after a refused removal");
    }
}
