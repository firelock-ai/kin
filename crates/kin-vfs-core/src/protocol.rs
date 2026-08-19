// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire protocol types for VFS shim ↔ daemon communication.
//!
//! This is the single source of truth. Both `kin-vfs-daemon` and `kin-vfs-shim`
//! re-export these types rather than defining their own copies.
//!
//! Path identity on this protocol is byte-exact: every request path is a
//! validated [`VfsPath`], every directory-entry name a validated
//! [`crate::path::VfsName`], and invalidation pushes carry canonical path
//! bytes. Malformed paths (absolute, `.`/`..`, NUL, empty components) are
//! rejected at decode time.

use crate::canary::InterposeStatus;
use crate::path::VfsPath;
use crate::{DirEntry, VirtualStat};
use serde::{Deserialize, Serialize};

/// Protocol version. Bump when making breaking wire-format changes.
///
/// v5: projection surfaces can carry a write across this protocol.
/// [`VfsRequest::Write`], [`VfsRequest::Remove`] and [`VfsRequest::Rename`]
/// are appended at the end of the request enum, so a v4 peer still decodes
/// every frame a v4 peer sends. The break is one-directional and worth
/// recording: a v5 shim sending a write to a v4 daemon gets a decode error
/// rather than an answer, which is a loud failure and not a silent one, but it
/// is still a failure a reader should be able to date.
///
/// v4: stat answers are stamped with the repository-authority generation that
/// produced them. [`VfsResponse::Stat`] and [`VfsResponse::Error`] both carry a
/// `generation`, so a client can key an attribute cache on graph truth rather
/// than on a clock, and can key a negative answer as well as a positive one.
///
/// v3: byte-exact path authority — request paths and directory-entry names
/// are raw validated bytes (no `String` path identity), invalidations carry
/// canonical path bytes, and `ErrorCode::UnsupportedBoundary` reports gitlink
/// repository boundaries.
pub const VFS_PROTOCOL_VERSION: u32 = 5;

/// The largest frame either end of this protocol will read.
///
/// Lives here rather than in the daemon's framing module because the shim
/// needs the same number to know what it may send, and two copies of a cap
/// drift into one peer sending frames the other refuses.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Room reserved inside a frame for everything a write carries besides its
/// body: the variant name, the array headers, and the path.
const WRITE_FRAME_OVERHEAD: usize = 64 * 1024;

/// The most bytes one [`VfsRequest::Write`] may carry.
///
/// Derived from [`MAX_FRAME_BYTES`] rather than picked to look round. `Vec<u8>`
/// encodes as a MessagePack array of integers rather than a `bin` blob
/// (matching [`VfsResponse::Content`] on the read path), and every byte from
/// `0x80` to `0xff` costs two bytes there, so a body of binary content doubles.
/// A flat 8 MiB bound therefore does NOT fit: measured, it encodes to 16777240
/// bytes against a 16777216-byte cap, and only the worst-case fixture in
/// `tests::a_write_at_the_bound_still_fits_one_frame` shows it. An ASCII
/// fixture passes at 8 MiB and the first binary asset in production fails.
///
/// A surface with more than this to admit must say so. The bytes it is
/// reporting have already landed on its own backing store, so a write dropped
/// here is graph divergence, and the one thing that must not happen is for it
/// to be dropped quietly.
pub const MAX_PROJECTION_WRITE: usize = (MAX_FRAME_BYTES - WRITE_FRAME_OVERHEAD) / 2;

/// Request from VFS shim to daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum VfsRequest {
    /// Get metadata for a repo-relative graph path (root is the empty path).
    Stat { path: VfsPath },

    /// List directory contents for a repo-relative graph path.
    ReadDir { path: VfsPath },

    /// Read file content (full or range) by repo-relative graph path.
    Read {
        path: VfsPath,
        offset: u64,
        len: u64,
    },

    /// Read symbolic link target by repo-relative graph path.
    ReadLink { path: VfsPath },

    /// Check if a repo-relative graph path is accessible.
    Access { path: VfsPath, mode: u32 },

    /// Keepalive ping.
    Ping,

    /// Register for push invalidation events.
    Subscribe,

    /// Interposition canary handshake. Sent once by the shim when it loads and
    /// activates with a `KIN_VFS_CANARY` launch token, so the daemon can record
    /// that this process is genuinely graph-native. A process whose
    /// `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` was stripped never loads the shim
    /// and therefore never sends this — letting a launcher fail it loud instead
    /// of trusting raw-disk reads as graph truth.
    Announce { pid: u32, token: String },

    /// A launcher registers, before it starts a child under interposition, that
    /// it expects `token` to be announced. Recorded in the daemon's canary
    /// registry so a never-confirmed token reads back as stripped.
    CanaryExpect { token: String },

    /// A launcher queries the interposition verdict for a token it previously
    /// expected (after the child has run). The daemon answers with
    /// [`VfsResponse::CanaryStatus`].
    CanaryVerdict { token: String },

    /// The shim reports that a workspace-owned path was answered by the real
    /// filesystem through `surface`, a libc entry point interposition does not
    /// route through the graph. Loading is not enough to make a run
    /// graph-native, so this is what keeps the verdict falsifiable: a run whose
    /// shim loaded perfectly still reads back as
    /// [`InterposeStatus::Bypassed`] once a surface is reported.
    ///
    /// Appended last, which is the convention for this enum. What actually
    /// decides wire compatibility here is narrower than declaration order:
    /// `rmp-serde` keys a variant by its NAME and a struct variant's fields by
    /// POSITION, so renaming a variant or reordering its fields is the
    /// breaking edit and adding one is not.
    /// `tests::request_wire_encoding_is_pinned` is what enforces that.
    CanaryBypass { token: String, surface: String },

    /// A launcher asks which surfaces were reported for a token, so its
    /// diagnostic can name them instead of telling the operator only that
    /// something bypassed. Answered with [`VfsResponse::CanaryBypasses`].
    CanaryBypassSurfaces { token: String },

    /// A projection surface reports the complete contents a separate process
    /// wrote to `path`, for admission into graph truth.
    ///
    /// The bytes travel, not the host path the surface wrote them to. A
    /// virtualization root is not the served repository's working copy, so a
    /// path-only notification would leave the daemon to go find the written
    /// file on raw disk. Carrying the bytes keeps the write side an admission
    /// boundary fed by the surface, which is the shape the FUSE and NFS mounts
    /// already have, and keeps the daemon's only filesystem write the staging
    /// one its admission phase already reads.
    ///
    /// A whole-file replacement rather than a ranged write: the notification a
    /// ProjFS provider receives names a file whose handle has already closed,
    /// so the surface knows the final contents and never the individual
    /// writes that produced them.
    ///
    /// Appended after [`Self::CanaryBypassSurfaces`] by the convention that
    /// variant records. `data` carries at most [`MAX_PROJECTION_WRITE`] bytes;
    /// a surface that has more to admit than that must refuse loudly rather
    /// than send a frame the daemon will reject.
    Write { path: VfsPath, data: Vec<u8> },

    /// A projection surface reports that `path` was removed.
    Remove { path: VfsPath },

    /// A projection surface reports that `from` now lives at `to`.
    Rename { from: VfsPath, to: VfsPath },
}

/// Response from daemon to VFS shim.
#[derive(Debug, Serialize, Deserialize)]
pub enum VfsResponse {
    /// Metadata, stamped with the generation of the snapshot that produced it.
    ///
    /// `generation` is the monotonic repository-authority generation the
    /// responder held when it resolved this path, or `0` when the responder has
    /// no authority generation to report. A client may remember this answer
    /// only while that exact generation is still current; `0` is never
    /// rememberable.
    Stat { stat: VirtualStat, generation: u64 },

    /// Directory listing with byte-exact entry names.
    DirEntries(Vec<DirEntry>),

    /// File content (or range).
    Content { data: Vec<u8>, total_size: u64 },

    /// Symlink target (exact stored bytes).
    LinkTarget(Vec<u8>),

    /// Access check result.
    Accessible(bool),

    /// Pong.
    Pong,

    /// Error, stamped like [`VfsResponse::Stat`].
    ///
    /// A definitive `NotFound` is an answer about graph truth, so it carries a
    /// generation for the same reason a positive answer does: a client that
    /// cannot key an absence cannot remember one, and absence is the hot
    /// result for tools that probe.
    Error {
        code: ErrorCode,
        message: String,
        generation: u64,
    },

    /// Push invalidation from daemon to shim, carrying canonical path bytes.
    /// An empty list means "everything may have changed".
    Invalidate { paths: Vec<VfsPath> },

    /// Acknowledge an interposition canary [`VfsRequest::Announce`] or
    /// [`VfsRequest::CanaryExpect`].
    Announced,

    /// Interposition verdict for a [`VfsRequest::CanaryVerdict`] query.
    CanaryStatus(InterposeStatus),

    /// Surfaces reported as having served a workspace path from raw disk, in
    /// stable order. Appended last, for the same wire-compatibility reason as
    /// [`VfsRequest::CanaryBypass`].
    CanaryBypasses(Vec<String>),

    /// A [`VfsRequest::Write`] was staged for admission, with the staged
    /// metadata for the path.
    ///
    /// Staged is not admitted. These bytes become graph truth when the
    /// writer's admission runs, and `WriteHealth` is what reports whether it
    /// has; this answer says only that the surface's write was taken.
    Written { stat: VirtualStat },

    /// A [`VfsRequest::Remove`] or [`VfsRequest::Rename`] was staged. Neither
    /// leaves metadata for the path it names, so there is nothing to report
    /// but acceptance.
    WriteAccepted,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorCode {
    NotFound,
    PermissionDenied,
    IsDirectory,
    NotDirectory,
    InvalidInput,
    /// The path names a nested-repository (gitlink) boundary with no child
    /// projection; its contents cannot be served without fabricating state.
    UnsupportedBoundary,
    IoError,
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vpath(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).expect("valid test path")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// One request of every variant, in declaration order.
    ///
    /// The exhaustive match at the end is what makes this list complete: a
    /// variant nobody added here fails to compile rather than shipping with no
    /// pinned encoding.
    fn every_request_variant() -> Vec<(&'static str, VfsRequest)> {
        let all = vec![
            ("Stat", VfsRequest::Stat { path: vpath("a") }),
            ("ReadDir", VfsRequest::ReadDir { path: vpath("a") }),
            (
                "Read",
                VfsRequest::Read {
                    path: vpath("a"),
                    offset: 0,
                    len: 0,
                },
            ),
            ("ReadLink", VfsRequest::ReadLink { path: vpath("a") }),
            (
                "Access",
                VfsRequest::Access {
                    path: vpath("a"),
                    mode: 4,
                },
            ),
            ("Ping", VfsRequest::Ping),
            ("Subscribe", VfsRequest::Subscribe),
            (
                "Announce",
                VfsRequest::Announce {
                    pid: 1,
                    token: "t".into(),
                },
            ),
            (
                "CanaryExpect",
                VfsRequest::CanaryExpect { token: "t".into() },
            ),
            (
                "CanaryVerdict",
                VfsRequest::CanaryVerdict { token: "t".into() },
            ),
            (
                "CanaryBypass",
                VfsRequest::CanaryBypass {
                    token: "t".into(),
                    surface: "s".into(),
                },
            ),
            (
                "CanaryBypassSurfaces",
                VfsRequest::CanaryBypassSurfaces { token: "t".into() },
            ),
            (
                "Write",
                VfsRequest::Write {
                    path: vpath("a"),
                    data: b"x".to_vec(),
                },
            ),
            ("Remove", VfsRequest::Remove { path: vpath("a") }),
            (
                "Rename",
                VfsRequest::Rename {
                    from: vpath("a"),
                    to: vpath("b"),
                },
            ),
        ];
        for (_, request) in &all {
            match request {
                VfsRequest::Stat { .. }
                | VfsRequest::ReadDir { .. }
                | VfsRequest::Read { .. }
                | VfsRequest::ReadLink { .. }
                | VfsRequest::Access { .. }
                | VfsRequest::Ping
                | VfsRequest::Subscribe
                | VfsRequest::Announce { .. }
                | VfsRequest::CanaryExpect { .. }
                | VfsRequest::CanaryVerdict { .. }
                | VfsRequest::CanaryBypass { .. }
                | VfsRequest::CanaryBypassSurfaces { .. }
                | VfsRequest::Write { .. }
                | VfsRequest::Remove { .. }
                | VfsRequest::Rename { .. } => {}
            }
        }
        all
    }

    /// The exact bytes each request variant puts on the wire.
    ///
    /// This is the only check that can see a wire break, because both ends of
    /// this protocol are built from this one file: a rename or a field
    /// reorder recompiles cleanly, round-trips perfectly, and still makes a
    /// peer built from the previous revision decode a frame as something else.
    ///
    /// What the encoding actually keys on, measured rather than assumed:
    /// `rmp-serde` writes a struct variant as a one-entry map from the
    /// variant's NAME to an array of its fields IN DECLARATION ORDER, and a
    /// unit variant as the bare name. So renaming a variant, renaming nothing
    /// but reordering a struct variant's fields, or changing a field's type
    /// are the breaking edits. Adding a variant is not, wherever it goes.
    ///
    /// A new variant therefore adds one row here and changes no existing row.
    /// A diff that changes an existing row is the bug this test exists to
    /// name.
    #[test]
    fn request_wire_encoding_is_pinned() {
        let expected = [
            ("Stat", "81a45374617491c40161"),
            ("ReadDir", "81a75265616444697291c40161"),
            ("Read", "81a45265616493c401610000"),
            ("ReadLink", "81a8526561644c696e6b91c40161"),
            ("Access", "81a641636365737392c4016104"),
            ("Ping", "a450696e67"),
            ("Subscribe", "a9537562736372696265"),
            ("Announce", "81a8416e6e6f756e63659201a174"),
            ("CanaryExpect", "81ac43616e61727945787065637491a174"),
            ("CanaryVerdict", "81ad43616e6172795665726469637491a174"),
            ("CanaryBypass", "81ac43616e61727942797061737392a174a173"),
            (
                "CanaryBypassSurfaces",
                "81b443616e617279427970617373537572666163657391a174",
            ),
            ("Write", "81a5577269746592c401619178"),
            ("Remove", "81a652656d6f766591c40161"),
            ("Rename", "81a652656e616d6592c40161c40162"),
        ];
        let variants = every_request_variant();
        assert_eq!(
            variants.len(),
            expected.len(),
            "a request variant was added or removed without pinning its encoding"
        );
        for ((name, request), (expected_name, expected_hex)) in variants.iter().zip(expected) {
            assert_eq!(
                *name, expected_name,
                "the pinned list is out of step at {name}"
            );
            let encoded = hex(&rmp_serde::to_vec(request).expect("encode request"));
            assert_eq!(
                encoded, expected_hex,
                "the wire encoding of `VfsRequest::{name}` changed. A peer built \
                 from the previous revision decodes this frame as something else, \
                 or not at all. Renaming a variant and reordering a struct \
                 variant's fields are both breaking; adding a variant is not."
            );
        }
    }

    /// The same pin for the answers, which break the same way.
    #[test]
    fn write_response_wire_encoding_is_pinned() {
        let stat = VirtualStat::regular_file(1, [0u8; 32], false, 0);
        let written = hex(&rmp_serde::to_vec(&VfsResponse::Written { stat }).expect("encode"));
        assert!(
            written.starts_with("81a75772697474656e"),
            "the `Written` variant name moved on the wire: {written}"
        );
        assert_eq!(
            hex(&rmp_serde::to_vec(&VfsResponse::WriteAccepted).expect("encode")),
            "ad57726974654163636570746564",
            "the `WriteAccepted` variant name moved on the wire"
        );
    }

    /// Every new variant survives a round trip with its payload intact.
    ///
    /// Separate from the encoding pin because the two fail for different
    /// reasons: a rename breaks the pin while round-tripping perfectly within
    /// one build, and a payload bug breaks the round trip while the leading
    /// bytes still match.
    #[test]
    fn write_requests_round_trip_with_their_payloads() {
        let request = VfsRequest::Write {
            path: vpath("src/main.rs"),
            data: b"graph-owned bytes".to_vec(),
        };
        let wire = rmp_serde::to_vec(&request).expect("encode");
        match rmp_serde::from_slice::<VfsRequest>(&wire).expect("decode") {
            VfsRequest::Write { path, data } => {
                assert_eq!(path.as_bytes(), b"src/main.rs");
                assert_eq!(data, b"graph-owned bytes");
            }
            other => panic!("decoded as {other:?}"),
        }

        let wire = rmp_serde::to_vec(&VfsRequest::Remove {
            path: vpath("src/gone.rs"),
        })
        .expect("encode");
        match rmp_serde::from_slice::<VfsRequest>(&wire).expect("decode") {
            VfsRequest::Remove { path } => assert_eq!(path.as_bytes(), b"src/gone.rs"),
            other => panic!("decoded as {other:?}"),
        }

        let wire = rmp_serde::to_vec(&VfsRequest::Rename {
            from: vpath("old.rs"),
            to: vpath("new.rs"),
        })
        .expect("encode");
        match rmp_serde::from_slice::<VfsRequest>(&wire).expect("decode") {
            VfsRequest::Rename { from, to } => {
                assert_eq!(from.as_bytes(), b"old.rs");
                assert_eq!(to.as_bytes(), b"new.rs");
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn write_responses_round_trip() {
        let stat = VirtualStat::regular_file(17, [0u8; 32], false, 1_704_067_200);
        let wire = rmp_serde::to_vec(&VfsResponse::Written { stat }).expect("encode");
        match rmp_serde::from_slice::<VfsResponse>(&wire).expect("decode") {
            VfsResponse::Written { stat } => assert_eq!(stat.size, 17),
            other => panic!("decoded as {other:?}"),
        }
        let wire = rmp_serde::to_vec(&VfsResponse::WriteAccepted).expect("encode");
        assert!(matches!(
            rmp_serde::from_slice::<VfsResponse>(&wire).expect("decode"),
            VfsResponse::WriteAccepted
        ));
    }

    /// A body at the bound encodes into a frame the daemon's 16 MiB cap
    /// accepts, and the worst case (every byte above `0x7f`) is what decides
    /// that. A bound picked from the average case would pass this test with
    /// ASCII and fail in production on a binary file.
    #[test]
    fn a_write_at_the_bound_still_fits_one_frame() {
        const DAEMON_FRAME_CAP: usize = MAX_FRAME_BYTES;
        let request = VfsRequest::Write {
            path: vpath("bin/asset"),
            data: vec![0xffu8; MAX_PROJECTION_WRITE],
        };
        let encoded = rmp_serde::to_vec(&request).expect("encode").len();
        assert!(
            encoded <= DAEMON_FRAME_CAP,
            "a {MAX_PROJECTION_WRITE}-byte write encoded to {encoded} bytes, over the \
             {DAEMON_FRAME_CAP}-byte frame cap"
        );
    }
}
