// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Keep a `kin upgrade` claim honest across the commands that restore state.
//!
//! `kin upgrade` re-derives the state every head serves and records the change
//! each head moved to as an anchor. The store's hydration record then reads
//! current, and that is true exactly while the state this daemon serves
//! descends from an anchor. A rollback, a path checkout, a stash restore, a
//! merge and a branch switch all install state some earlier change recorded,
//! and state recorded before the upgrade was derived by whichever build
//! recorded it.
//!
//! So each of them asks here before it commits. When the store carries an
//! upgrade and the restored change's first-parent line reaches none of its
//! anchors, the upgrade is dropped from the record, durably, before the commit:
//! the store reads behind again, every answer is qualified, and the remedy is
//! `kin upgrade`, which re-derives whatever the restore installed. A store
//! with no upgrade, a hosted daemon with no record, and a restore of upgraded
//! state are left exactly as they are.

use kin_model::{ChangeStore as _, SemanticChangeId};

use crate::state::DaemonState;

/// Drop the store's `kin upgrade` claim before a commit installs state from
/// `restored`, unless that state descends from one of the upgrade's anchors.
///
/// `history` is the change DAG the caller already resolved `restored` in. The
/// error is returned rather than logged: a commit that proceeded over a failed
/// drop would certify state the upgrade never derived.
pub(crate) fn before_restoring(
    state: &DaemonState,
    history: &kin_db::InMemoryGraph,
    restored: SemanticChangeId,
    what: &str,
) -> anyhow::Result<()> {
    let Some(record) = state.local_kindb_capability() else {
        return Ok(());
    };
    let dropped = record
        .drop_upgrade_unless_restoring_upgraded_state(restored, |id| {
            history
                .get_change(id)
                .map(|change| change.map(|change| change.parents.first().copied()))
        })
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if dropped {
        tracing::warn!(
            change = %restored,
            what,
            "this restores state recorded before the store's last `kin upgrade`, so the store \
             reads behind again until `kin upgrade` re-derives it"
        );
    }
    Ok(())
}
