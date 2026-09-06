// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whether the host still holds the bytes a graph answer describes, one path at
//! a time.
//!
//! This is the disk half of the staleness FIR-3201 closed the graph-internal
//! half of. That fix compares each entity's recorded source digest against the
//! blob the repository tree holds at its path, which catches the window where an
//! admission moved the tree and the reconciler had not yet re-derived the spans.
//! It cannot catch the window before the admission runs at all: an edit that no
//! pass has taken leaves the entity digest and the tree blob both describing the
//! same pre-edit bytes, so the pair agrees and the reading is a correct
//! `digest_verified` over spans into a file that has since moved underneath it.
//!
//! Measured on a `kin init` of `expressjs/express` at `023767fe`, an edit
//! inserting three lines into `lib/utils.js` at 02:44:12.971642Z was followed
//! 0.589 ms later by a `list_file_entities` that returned `setCharset` at lines
//! 225 to 238 against a file holding 225 to 241, under `verdict: certified` with
//! `limiting_factor: null` and `span_provenance: digest_verified`.
//!
//! ## Why this is a byte comparison and not a clock
//!
//! The obvious cheaper reading is the file's modification time against the
//! store's last complete admission, and it does not work. The daemon's
//! last-admission stamp is its own in-memory record, set only when a complete
//! admission finishes in this process, so a daemon that has just come up carries
//! none. On the express run above the failing response's envelope read
//! `freshness: {"state": "no_admission_recorded"}`: there was no clock on the
//! exact call the defect was found on, and a clock comparison would have
//! reported unknown and certified anyway.
//!
//! The content identity is available whether or not an admission has ever run,
//! and it is exact in both directions rather than conservative in one. So the
//! probe asks the question the daemon's own admission guard asks
//! (`host_entry_matches_graph` in `kin-daemon`): does the host entry at this
//! path still hash to the content identity graph truth carries for it.
//!
//! ## Why this is not a file search
//!
//! The answer is produced entirely from the graph, exactly as before. Nothing
//! here ranks, walks, greps or fills from the filesystem, and no row in any
//! response comes from a byte this module read. It reads one host entry, at a
//! path the caller already named, and the only thing it can do with what it
//! finds is refuse to certify. A disclosure that can only ever weaken an answer
//! is not an authority for it.
//!
//! ## Why it is scoped to the answer rather than to the working copy
//!
//! The daemon already measures the working copy, and that measurement cannot
//! serve this. It counts host paths repository authority does not track, which a
//! tracked file with changed bytes is not; and it rate-limits itself to at most
//! one walk per second, which is longer than the gap between an agent's edit and
//! its next question. Scoping to the one path an answer covers costs one stat
//! and at most one read of a file the graph already parsed, and it has no
//! blind spot in time at all.

use std::path::{Path, PathBuf};

use kin_model::{Hash256, RepoPath, TreeEntry};

/// Largest host entry this probe will read to hash.
///
/// A ceiling rather than a policy: every file this probe is asked about is one
/// whose entities the graph already holds, so a parser has already read it whole
/// and the ceiling is unreachable in the case that matters. It exists so a path
/// that became something enormous between the admission and the question costs
/// one `metadata` call rather than a read of it, and the reading then says
/// nothing rather than blocking the answer.
const MAX_PROBE_BYTES: u64 = 64 * 1024 * 1024;

/// What the host holds at one repository path, relative to what graph truth
/// carries for it.
///
/// Three states, and the middle one is the point: `Unobserved` and `Admitted`
/// both permit certification and mean different things, so a reader can tell a
/// probe that ran and agreed from one that never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEntryReading {
    /// Nothing compared the host with the graph.
    ///
    /// The honest state for every case where the working copy is not evidence
    /// about graph truth: no probe was supplied, the path is a gitlink with no
    /// content identity to compare, the host entry could not be read, or it is
    /// larger than this probe will hash. Certification is unaffected, exactly as
    /// [`crate::handlers::file_entities::SpanProvenance::Unverified`] leaves it
    /// unaffected, because refusing on an absence of evidence would floor every
    /// answer on every store this cannot see.
    Unobserved,
    /// The host entry hashes to the content identity graph truth holds for this
    /// path, so the spans this answer serves were derived from the bytes that
    /// are there now.
    Admitted,
    /// The host entry holds content graph truth does not carry at this path.
    ///
    /// A provable divergence, not a suspicion: two content addresses over the
    /// same path that are not equal. Whatever the graph says about this file, it
    /// says it about other bytes, so an enumeration over it cannot be certified
    /// as the file's whole surface.
    Diverged,
}

impl HostEntryReading {
    /// The wire word, published beside `span_provenance` in `file_coverage`.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Unobserved => "unobserved",
            Self::Admitted => "admitted",
            Self::Diverged => "diverged",
        }
    }

    /// Whether this reading permits certifying an answer about the path. Only a
    /// provable divergence refuses.
    pub fn permits_certification(self) -> bool {
        !matches!(self, Self::Diverged)
    }
}

/// One repository's working copy, asked about one path at a time.
///
/// Held by whichever layer knows that this repository has a working copy the
/// graph is supposed to be level with. A daemon whose graph is its own write
/// authority holds no such thing: nothing on its projected checkout is content
/// an admission failed to take, so it supplies no probe rather than supplying
/// one that would manufacture a divergence out of the projection. That is the
/// same rule the daemon's untracked measurement already applies to itself.
#[derive(Debug, Clone)]
pub struct WorkingCopyProbe {
    root: PathBuf,
}

impl WorkingCopyProbe {
    /// A probe over the working directory of one repository.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Compare the host entry at `path` with the tree entry graph truth holds
    /// for it.
    ///
    /// `admitted` is the entry the caller already resolved from the store, so
    /// this adds no graph read to the answer it qualifies.
    ///
    /// The executable bit is deliberately excluded from the comparison, unlike
    /// the daemon's admission guard, which compares the whole `TreeEntry`. A
    /// mode change moves no span and produces no entity, so refusing to certify
    /// an enumeration over a `chmod` would be a floor with nothing behind it.
    /// Content identity is the whole of what this reading is about.
    pub fn observe(&self, path: &RepoPath, admitted: Option<&TreeEntry>) -> HostEntryReading {
        let Some(expected) = admitted.and_then(TreeEntry::blob_identity) else {
            return HostEntryReading::Unobserved;
        };
        let Some(relative) = path.as_utf8() else {
            return HostEntryReading::Unobserved;
        };
        match self.host_content_identity(&self.root.join(relative)) {
            Some(observed) if observed == expected => HostEntryReading::Admitted,
            Some(_) => HostEntryReading::Diverged,
            None => HostEntryReading::Unobserved,
        }
    }

    /// The content identity of one host entry, or `None` when the host is not
    /// evidence.
    ///
    /// A missing path returns `None` rather than a divergence on purpose. The
    /// graph is the authority for what the repository holds, and a materialized
    /// checkout is one projection of it among several: a repository whose files
    /// are served through a projection, or a clone whose checkout has not been
    /// written yet, holds graph truth no host entry stands behind, and calling
    /// that a divergence would floor every answer over it. What this reading is
    /// about is a path that IS on the host and holds other bytes.
    fn host_content_identity(&self, host_path: &Path) -> Option<Hash256> {
        let metadata = std::fs::symlink_metadata(host_path).ok()?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let target = std::fs::read_link(host_path).ok()?;
            // Byte-exact link target, matching what an admission stores for a
            // symlink: the blob under a symlink entry is the target path's own
            // bytes.
            return Some(Hash256::from_bytes(kin_blobs::digest_bytes(
                &symlink_target_bytes(&target)?,
            )));
        }
        if !file_type.is_file() {
            return None;
        }
        if metadata.len() > MAX_PROBE_BYTES {
            return None;
        }
        Some(Hash256::from_bytes(kin_blobs::digest_bytes(
            &std::fs::read(host_path).ok()?,
        )))
    }
}

/// The bytes an admission stores for a symlink target.
///
/// Split by platform exactly as the daemon's own admission path splits it, so
/// the two cannot come to disagree about what a symlink's content identity is.
/// On unix a target is arbitrary bytes and is taken as such; elsewhere a target
/// with no UTF-8 rendering is one this repository could not have admitted in the
/// first place, so there is nothing to compare rather than something that
/// differs.
#[cfg(unix)]
fn symlink_target_bytes(target: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;
    Some(target.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn symlink_target_bytes(target: &Path) -> Option<Vec<u8>> {
    target.to_str().map(|target| target.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_over(root: &Path) -> WorkingCopyProbe {
        WorkingCopyProbe::new(root)
    }

    fn repo_path(path: &str) -> RepoPath {
        RepoPath::from_utf8(path).expect("a usable repository path")
    }

    fn digest_of(bytes: &[u8]) -> Hash256 {
        Hash256::from_bytes(kin_blobs::digest_bytes(bytes))
    }

    fn blob_of(bytes: &[u8]) -> TreeEntry {
        TreeEntry::blob(digest_of(bytes), false)
    }

    /// The state the probe exists to report: the host holds other bytes.
    #[test]
    fn a_host_entry_holding_other_bytes_reads_diverged() {
        let root = tempfile::tempdir().expect("a scratch working copy");
        let admitted = blob_of(b"fn one() {}\n");
        std::fs::write(root.path().join("lib.rs"), b"fn one() {}\nfn two() {}\n")
            .expect("the host entry is written");

        assert_eq!(
            probe_over(root.path()).observe(&repo_path("lib.rs"), Some(&admitted)),
            HostEntryReading::Diverged
        );
    }

    /// The positive control for the arm above, over the same probe and the same
    /// path: identical bytes must read `Admitted`, or `Diverged` would be a
    /// verdict this probe returns for everything.
    #[test]
    fn a_host_entry_holding_the_admitted_bytes_reads_admitted() {
        let root = tempfile::tempdir().expect("a scratch working copy");
        let body = b"fn one() {}\n";
        let admitted = blob_of(body);
        std::fs::write(root.path().join("lib.rs"), body).expect("the host entry is written");

        assert_eq!(
            probe_over(root.path()).observe(&repo_path("lib.rs"), Some(&admitted)),
            HostEntryReading::Admitted
        );
    }

    /// A mode change moves no span, so it is not a divergence. Asserted rather
    /// than assumed, because the daemon's own admission guard next door DOES
    /// compare the executable bit and copying it here would floor an enumeration
    /// over a `chmod`.
    #[test]
    fn a_mode_change_alone_is_not_a_divergence() {
        let root = tempfile::tempdir().expect("a scratch working copy");
        let body = b"fn one() {}\n";
        // Graph truth carries the path as non-executable; the host holds the
        // same bytes. Only the mode differs.
        let admitted = TreeEntry::blob(digest_of(body), false);
        let host = root.path().join("lib.rs");
        std::fs::write(&host, body).expect("the host entry is written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o755))
                .expect("the host entry becomes executable");
        }

        assert_eq!(
            probe_over(root.path()).observe(&repo_path("lib.rs"), Some(&admitted)),
            HostEntryReading::Admitted
        );
    }

    /// A path with no host entry is not evidence. A projected checkout and a
    /// clone that has not materialized both look like this, and calling either a
    /// divergence would floor every answer over them.
    #[test]
    fn a_path_absent_from_the_host_is_unobserved() {
        let root = tempfile::tempdir().expect("a scratch working copy");
        let admitted = blob_of(b"fn one() {}\n");

        assert_eq!(
            probe_over(root.path()).observe(&repo_path("lib.rs"), Some(&admitted)),
            HostEntryReading::Unobserved
        );
    }

    /// A gitlink carries no content identity, so there is nothing to compare.
    #[test]
    fn a_tree_entry_with_no_blob_identity_is_unobserved() {
        let root = tempfile::tempdir().expect("a scratch working copy");
        let admitted = TreeEntry::gitlink(kin_model::GitObjectId::sha1([7u8; 20]));
        std::fs::create_dir(root.path().join("vendor")).expect("the submodule directory exists");

        assert_eq!(
            probe_over(root.path()).observe(&repo_path("vendor"), Some(&admitted)),
            HostEntryReading::Unobserved
        );
    }

    /// No tree entry at all is the same absence of evidence.
    #[test]
    fn no_admitted_entry_is_unobserved() {
        let root = tempfile::tempdir().expect("a scratch working copy");
        std::fs::write(root.path().join("lib.rs"), b"fn one() {}\n")
            .expect("the host entry is written");

        assert_eq!(
            probe_over(root.path()).observe(&repo_path("lib.rs"), None),
            HostEntryReading::Unobserved
        );
    }

    /// Only a divergence refuses certification, and the two permitting states
    /// are asserted separately so a change that collapsed them would be caught.
    #[test]
    fn only_a_divergence_refuses_certification() {
        assert!(!HostEntryReading::Diverged.permits_certification());
        assert!(HostEntryReading::Admitted.permits_certification());
        assert!(HostEntryReading::Unobserved.permits_certification());
    }

    /// The wire words are distinct, because two states rendering the same word
    /// would make the disclosure unreadable on the wire while every assertion
    /// above still passed.
    #[test]
    fn every_reading_has_its_own_wire_word() {
        let words = [
            HostEntryReading::Unobserved.wire(),
            HostEntryReading::Admitted.wire(),
            HostEntryReading::Diverged.wire(),
        ];
        let mut sorted = words.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), words.len(), "wire words collided: {words:?}");
    }

    /// A symlink is compared against the bytes of its target path, which is what
    /// an admission stores for one. Without this arm the symlink branch could
    /// hash the wrong thing and every symlink would read `Diverged`.
    #[cfg(unix)]
    #[test]
    fn a_symlink_is_compared_against_its_target_path_bytes() {
        let root = tempfile::tempdir().expect("a scratch working copy");
        std::os::unix::fs::symlink("lib.rs", root.path().join("alias.rs"))
            .expect("the symlink is created");
        let admitted = TreeEntry::symlink(digest_of(b"lib.rs"));
        let moved = TreeEntry::symlink(digest_of(b"other.rs"));

        let probe = probe_over(root.path());
        assert_eq!(
            probe.observe(&repo_path("alias.rs"), Some(&admitted)),
            HostEntryReading::Admitted
        );
        assert_eq!(
            probe.observe(&repo_path("alias.rs"), Some(&moved)),
            HostEntryReading::Diverged
        );
    }

    /// A host entry past the ceiling costs a `metadata` call and reports
    /// nothing, rather than being read. Falsified by the control beneath it: the
    /// same probe over a small file with the same mismatched identity does
    /// report the divergence, so `Unobserved` here is the ceiling firing and not
    /// the comparison being broken.
    #[test]
    fn a_host_entry_past_the_ceiling_reports_nothing() {
        let root = tempfile::tempdir().expect("a scratch working copy");
        let admitted = blob_of(b"fn one() {}\n");
        let huge = root.path().join("huge.rs");
        let file = std::fs::File::create(&huge).expect("the host entry is created");
        file.set_len(MAX_PROBE_BYTES + 1)
            .expect("the host entry is grown past the ceiling");
        drop(file);
        std::fs::write(root.path().join("small.rs"), b"fn two() {}\n")
            .expect("the control entry is written");

        let probe = probe_over(root.path());
        assert_eq!(
            probe.observe(&repo_path("huge.rs"), Some(&admitted)),
            HostEntryReading::Unobserved
        );
        assert_eq!(
            probe.observe(&repo_path("small.rs"), Some(&admitted)),
            HostEntryReading::Diverged,
            "the control must divergence-detect, or the arm above proves nothing"
        );
    }
}
