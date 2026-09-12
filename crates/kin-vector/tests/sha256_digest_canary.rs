// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Backend-independence canary for the SHA-256 behind the recovery marker.
//!
//! `sha2` 0.11 chooses its compression backend at runtime: on aarch64 it probes
//! for the `sha2` CPU feature and calls the ARMv8 SHA instructions, falling back
//! to the software compressor when the probe fails. One binary therefore takes
//! two different code paths on two different machines, and the recovery marker
//! this crate writes beside a persisted index is checked on the way back in. A
//! digest that depended on the host would turn a perfectly good index into a
//! checksum mismatch on any machine but the one that wrote it.
//!
//! The expected values below are not this crate's output recorded back as truth.
//! They are the SHA-256 examples published in FIPS 180-4 (plus the empty
//! message), so the assertion is against the standard and a backend that
//! disagreed with it would fail here rather than be blessed. Between them they
//! cover one padded block, two blocks, and 15,625 blocks: the long case is the
//! loop a hardware backend actually replaces, and a single-block-only test would
//! not reach it.
//!
//! Which backend the host took is deliberately not asserted — this test has to
//! pass on a CPU without the extension too. Proving the fast path is reachable
//! is a measurement question, answered by probing the same `sha2` feature the
//! crate probes, not a correctness one.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

fn hex32(digest: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        write!(out, "{byte:02x}").expect("writing hex into a String cannot fail");
    }
    out
}

#[test]
fn sha256_matches_published_vectors() {
    let cases: [(&str, Vec<u8>, &str); 4] = [
        (
            "empty",
            Vec::new(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "fips-180-4 one block",
            b"abc".to_vec(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "fips-180-4 two blocks",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            "one million 'a'",
            vec![b'a'; 1_000_000],
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
    ];

    for (name, message, expected) in cases {
        let digest: [u8; 32] = Sha256::digest(&message).into();
        assert_eq!(hex32(digest), expected, "SHA-256 of {name} changed");
    }
}

#[test]
fn streaming_updates_match_one_shot_across_unaligned_chunks() {
    let message: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
    let one_shot: [u8; 32] = Sha256::digest(&message).into();

    // 64 is the block size, so every other width leaves the buffer holding a
    // partial block across calls — the state a backend swap is most likely to
    // get wrong.
    for chunk in [1_usize, 7, 63, 64, 65, 1000] {
        let mut hasher = Sha256::new();
        for part in message.chunks(chunk) {
            hasher.update(part);
        }
        let streamed: [u8; 32] = hasher.finalize().into();
        assert_eq!(
            streamed, one_shot,
            "hashing in {chunk}-byte chunks diverged from the one-shot digest"
        );
    }
}
