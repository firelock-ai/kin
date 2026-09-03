// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Does a root bundle written by the copying identity still recompute under the
//! borrowing one?
//!
//! kin-model 0.7.24 turns `RepositoryOperationRecord::canonicalized` from
//! always-clone into a `Cow` that borrows when `ref_mutations` and
//! `tree_deltas` are already sorted. `local_state_root` folds
//! `RepositoryOperationRecord::identity_hash` over the whole operation log, and
//! `local_state_root` is one of the five roots in the persisted `RootBundle`.
//! So that pin move edits an input to a persisted authority root, and a byte
//! that differs is not a faster hash, it is every store refusing its own
//! bundle at the next open that recomputes.
//!
//! **Why this needs its own harness: the ordinary open cannot see it.** A store
//! whose `history_validation.validator_version` equals the opening binary's
//! `HISTORY_VALIDATION_VERSION` satisfies every clause of
//! `reused_complete_validation`, which routes the decode to
//! `from_bytes_reusing_exact_validation` or the streamed variant. Both pass
//! `validate_storage_admission = false`. The open then skips its own
//! `validate_storage_admission` because recovery produced an authority, and
//! skips `validate_history_replay` because the reopen proof verified. Nothing
//! on that path reaches `compute_roots`. Opening the store before and after a
//! fold change therefore reads the same persisted bundle back out twice and
//! reports SAME while folding nothing, which is a check that cannot fail.
//!
//! What this does instead is call the validation the open would have called if
//! there had been no proof: `PersistedRepositoryAuthority::validate_against_snapshot`
//! hardcodes `RootRecomputation::Required`, recomputes the bundle from the
//! snapshot and the envelope, and refuses when it does not match what is
//! persisted. That is a public entry point of this crate and the same one the
//! proofless open takes; it is reached here by a call the open would not have
//! made on a store carrying a current proof, which is the honest limit of this
//! arm. It proves the roots recompute. It does not prove that the field
//! upgrade path exercises the fold.
//!
//! **The controls, because a comparison that cannot report DIFFER is not
//! evidence.** They come in two layers, and the split is not tidiness: every
//! envelope-level mutation has to survive the gates that run BEFORE the roots
//! branch, and the first three this file was written with did not.
//!
//! `validate_against_snapshot_with` checks the operation log long before it
//! recomputes: `receipt.validate_against(operation)` compares `operation_id`,
//! `repository_id`, `transaction_hash`, `roots_before` and `roots_after`
//! against the receipt, and refuses outright when the receipt's embedded copy
//! of the record is not equal to the log's. This store carries fat receipts, so
//! that embedded copy is present. Separately, `last.roots_after != self.roots`
//! refuses with "does not match the last operation", and the `roots_before`
//! chain is walked. So a lone mutation to the record, to the persisted bundle
//! or to `roots_after` is refused by one of those gates, whose message has
//! nothing to do with root recomputation and whose refusal would have read
//! exactly like a passing control.
//!
//! Layer one is at the digest, where no envelope gate stands in the way:
//!
//! - the borrowed identity must equal the copying identity. This is the claim.
//! - perturbing `transaction_hash`, which `identity_payload` folds, must CHANGE
//!   the digest. Without it the equality above could hold because the digest
//!   ignores the record.
//! - perturbing `roots_after`, which `identity_payload` excludes by
//!   construction, must NOT change it. This fixes the fold's boundary in both
//!   directions.
//!
//! Layer two is at the envelope, and its one mutation is moved coherently
//! everywhere the earlier gates cross-check it, so the ONLY thing left that can
//! refuse is the roots comparison:
//!
//! - `transaction_hash` is moved on the log record, on its receipt, and on the
//!   receipt's embedded copy. Every earlier gate then sees a consistent
//!   envelope, `identity_hash` moves, `local_state_root` moves, and the roots
//!   gate must refuse with its own message. That is what proves the fold reads
//!   the operation log rather than a cached value, and that the comparison is
//!   live.
//!
//! Each assertion is on the gate's own message rather than on an error being
//! present. An exit code or a bare `is_err()` cannot tell a refusal from a
//! typo, and on 2026-09-03 a sister lane's refusal control passed on an exit
//! code produced by a shell redirect rather than by any refusal at all.
//!
//! Every mutation is applied to the DECODED envelope and never to the stored
//! bytes. A byte mutation changes the frame checksum, the root-hash trailer and
//! the `snapshot_sha256` recorded in `authority.json`, so recovery would refuse
//! at three earlier gates that have nothing to do with roots.
//!
//! **The differential, and the assumption it rests on.** The borrow side is
//! `identity_hash()` on the record as persisted. The copy side is the same hash
//! over a clone whose `ref_mutations` are sorted by name and whose
//! `tree_deltas` are sorted by artifact id, which is what the pre-0.7.24 body
//! always built. Stated in the open rather than in a footnote: reproducing that
//! body needs the semantic delta sorted too, `sort_canonical` is private to
//! kin-model, and this relies on `validate` already refusing any delta vector
//! not strictly increasing by `target_id`, which is the key `sort_canonical`
//! uses. If that enforcement ever goes away, this reproduction is wrong and the
//! roots arm above is what still holds.
//!
//! Digests print as full hex with their character count beside them. The
//! `Debug` for `Hash256` prints twelve hex characters, a 48-bit prefix, and a
//! prefix compared against a prefix is not byte identity.
//!
//! Ignored by default and driven by `ROOTS_STORE`, because it needs a real
//! converted store and a builder slot. Run:
//!
//! ```text
//! ROOTS_STORE=<.kin/kindb dir> cargo test -p kin-db --release \
//!   --test persisted_roots_under_the_borrowing_identity -- --ignored --nocapture
//! ```

use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::RepositoryId;

/// The message `validate_against_snapshot_with` produces when the recomputed
/// bundle does not equal the persisted one.
///
/// Asserted on by substring rather than by `is_err()`, so a refusal from any
/// other gate fails the control instead of satisfying it.
const ROOTS_GATE: &str = "repository root bundle does not recompute from the persisted envelope";

fn hex_of(hash: &kin_model::Hash256) -> String {
    // `Display` is the full 32 bytes. `Debug` is a twelve-character prefix, and
    // printing that as a digest is how a 48-bit comparison gets called byte
    // identity.
    format!("{hash}")
}

/// Print a digest with its character count, so a short one is visible as short.
fn print_digest(label: &str, hash: &kin_model::Hash256) {
    let hex = hex_of(hash);
    println!("{label} {hex} ({} chars)", hex.len());
}

fn roots_gate_refused(result: Result<(), kin_db::KinDbError>) -> bool {
    match result {
        Ok(()) => false,
        Err(error) => {
            let text = error.to_string();
            let matched = text.contains(ROOTS_GATE);
            if !matched {
                println!("REFUSED_BY_ANOTHER_GATE {text}");
            }
            matched
        }
    }
}

#[test]
#[ignore = "needs a real converted store named by ROOTS_STORE, and a builder slot"]
fn the_persisted_root_bundle_recomputes_under_the_borrowing_identity() {
    let Ok(root) = std::env::var("ROOTS_STORE") else {
        panic!("set ROOTS_STORE to the .kin/kindb directory of a converted store");
    };
    let repo_id = std::fs::read_dir(&root)
        .expect("the store directory reads")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("snapshots").is_dir())
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .expect("a repository namespace carrying a snapshots directory");
    println!("STORE {root}");
    println!("REPO  {repo_id}");

    let repository = RepositoryId::new(&repo_id).expect("the namespace is a repository id");
    let backend = Arc::new(LocalFileBackend::new(&root));
    // Timed, because the elapsed open is what tells the two doors apart from
    // outside. A store whose recorded validator version matches this binary
    // reuses its proof and opens in seconds; one carrying an older version
    // fails `reused_complete_validation`, decodes the change map in memory and
    // replays the whole history, which is minutes. Neither is asserted on: the
    // number is reported so the body can say which door this run came through
    // rather than claiming it.
    let open_started = std::time::Instant::now();
    let manager = RepositoryAuthorityManager::open(repository, backend).expect("the store opens");
    let open_elapsed = open_started.elapsed();
    println!("OPEN_ELAPSED_MS {}", open_elapsed.as_millis());
    let lease = manager.read_authority();
    let snapshot = lease.snapshot();
    let envelope = lease.metadata();

    println!("AUTHORITY_SCHEMA {}", envelope.schema_version);
    println!("ROOT_BUNDLE_VERSION {}", envelope.roots.version);
    println!("ROOT_BUNDLE_GENERATION {}", envelope.roots.generation);
    println!("OPERATION_LOG {}", envelope.operation_log.len());
    println!("RECEIPTS {}", envelope.receipts.len());
    print_digest(
        "PERSISTED_LOCAL_STATE_ROOT",
        &envelope.roots.local_state.hash,
    );
    print_digest("PERSISTED_HISTORY_ROOT", &envelope.roots.history.hash);

    assert!(
        !envelope.operation_log.is_empty(),
        "the control: the store must carry at least one operation record, or local_state_root \
         folds no identity and this arm grades nothing"
    );

    // Does the borrow path actually fire on this store? If it does not, the
    // changed code never runs and a green arm below would say nothing about
    // the pin. Read on this copy rather than inherited from an earlier run.
    let mut borrowing_records = 0usize;
    for (index, record) in envelope.operation_log.iter().enumerate() {
        let refs_sorted = record
            .ref_mutations
            .windows(2)
            .all(|pair| pair[0].name <= pair[1].name);
        let tree_deltas = record
            .workspace_mutation
            .as_ref()
            .map_or(0, |workspace| workspace.tree_deltas.len());
        let tree_sorted = record.workspace_mutation.as_ref().is_none_or(|workspace| {
            workspace
                .tree_deltas
                .windows(2)
                .all(|pair| pair[0].artifact_id() <= pair[1].artifact_id())
        });
        let borrows = refs_sorted && tree_sorted;
        if borrows {
            borrowing_records += 1;
        }
        println!(
            "RECORD {index} ref_mutations {} sorted {refs_sorted} tree_deltas {tree_deltas} \
             sorted {tree_sorted} BORROW_PATH_FIRES {borrows}",
            record.ref_mutations.len()
        );

        let borrowed = record.identity_hash().expect("the identity hashes");
        print_digest(&format!("RECORD_{index}_IDENTITY"), &borrowed);

        // The copy side: the body the pre-0.7.24 `canonicalized` always built.
        // Hashing an already-sorted clone hashes the same bytes the sort would
        // have produced, so this reproduces the shipped answer without building
        // the old pin.
        let mut sorted = record.clone();
        sorted
            .ref_mutations
            .sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(workspace) = &mut sorted.workspace_mutation {
            workspace
                .tree_deltas
                .sort_by_key(|delta| delta.artifact_id());
        }
        let copying = sorted.identity_hash().expect("the copying oracle hashes");
        print_digest(&format!("RECORD_{index}_IDENTITY_BY_COPYING"), &copying);
        assert_eq!(
            borrowed, copying,
            "record {index}: the borrowed identity differs from the copying identity, which \
             moves local_state_root and invalidates every persisted bundle"
        );

        // The digest must be sensitive to a field the payload folds, or the
        // equality above could hold because the hash ignores the record.
        let mut folded_moved = record.clone();
        folded_moved.transaction_hash = flip_first_byte(folded_moved.transaction_hash);
        let folded_digest = folded_moved
            .identity_hash()
            .expect("the perturbed record hashes");
        assert_ne!(
            folded_digest, borrowed,
            "record {index}: the control: moving transaction_hash, which identity_payload folds, \
             must change the identity, or this digest is not reading the record"
        );

        // And insensitive to the two fields it excludes by construction, or the
        // fold reads more of the record than the crate documents.
        let mut excluded_moved = record.clone();
        excluded_moved.roots_after.local_state.hash =
            flip_first_byte(excluded_moved.roots_after.local_state.hash);
        excluded_moved.roots_before.local_state.hash =
            flip_first_byte(excluded_moved.roots_before.local_state.hash);
        let excluded_digest = excluded_moved
            .identity_hash()
            .expect("the record with moved root bundles hashes");
        assert_eq!(
            excluded_digest, borrowed,
            "record {index}: the mirror control: identity_payload excludes roots_before and \
             roots_after by construction, so moving them must not change the identity"
        );
        println!("RECORD_{index}_FOLD_BOUNDARY confirmed");
    }
    println!("BORROWING_RECORDS {borrowing_records}");
    assert!(
        borrowing_records > 0,
        "the control: no record takes the borrow path, so the changed code never ran and this \
         arm grades nothing"
    );

    // The proof. This is the call the open makes when there is no validation
    // proof to reuse, and it is the only path that folds the operation log into
    // local_state_root and compares the result with what is stored.
    let proof_started = std::time::Instant::now();
    envelope
        .validate_against_snapshot(snapshot)
        .expect("the persisted root bundle must recompute under the borrowing identity");
    println!(
        "RECOMPUTE_ELAPSED_MS {}",
        proof_started.elapsed().as_millis()
    );
    println!("ROOTS_MATCH_PERSISTED true");

    // The envelope-level control. `transaction_hash` is folded by
    // `identity_payload` and cross-checked by `receipt.validate_against` and by
    // the receipt's embedded copy, so it is moved in all three places at once.
    // Every gate before the roots branch then sees a consistent envelope and
    // the only thing left that can refuse is the recomputation.
    let mut moved = envelope.clone();
    let operation_id = moved.operation_log[0].operation_id;
    let moved_hash = flip_first_byte(moved.operation_log[0].transaction_hash);
    moved.operation_log[0].transaction_hash = moved_hash;
    let mut receipts_touched = 0usize;
    let mut embedded_touched = 0usize;
    for receipt in &mut moved.receipts {
        if receipt.operation_id != operation_id {
            continue;
        }
        receipt.transaction_hash = moved_hash;
        receipts_touched += 1;
        if let Some(embedded) = &mut receipt.operation {
            embedded.transaction_hash = moved_hash;
            embedded_touched += 1;
        }
    }
    println!("CONTROL_RECEIPTS_TOUCHED {receipts_touched}");
    println!("CONTROL_EMBEDDED_RECORDS_TOUCHED {embedded_touched}");
    assert_eq!(
        receipts_touched, 1,
        "the control's own precondition: exactly one receipt must name this operation, or the \
         mutation is not coherent and an earlier gate refuses it for the wrong reason"
    );
    assert!(
        roots_gate_refused(moved.validate_against_snapshot(snapshot)),
        "the control: moving a folded field coherently across the log, the receipt and the \
         embedded copy must be refused by the ROOTS gate specifically; any other refusal means \
         this control never reached the recomputation and proves nothing"
    );
    println!("CONTROL_MOVED_FOLDED_FIELD refused_by_roots_gate");
}

/// Flip the low bit of a digest's first byte.
///
/// Enough to change the value, small enough that nothing else about the record
/// changes shape.
fn flip_first_byte(hash: kin_model::Hash256) -> kin_model::Hash256 {
    let mut bytes = *hash.as_bytes();
    bytes[0] ^= 0x01;
    kin_model::Hash256::from_bytes(bytes)
}
