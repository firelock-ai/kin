// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whether a workspace is projected at the tip of the branch its head names.
//!
//! A workspace head can be symbolic and its projected change can still be an
//! older change than the branch names, and nothing about the working copy shows
//! it. That is the everyday shape after this store receives a push: the ref
//! moves, the workspace does not, and `kin status` answers about the workspace
//! it has. The answer is exactly right and reads as "nothing to do", which is
//! how a reader came to edit files that the branch had already moved past.
//! Git refuses the shape outright by default (`receive.denyCurrentBranch`) for
//! the same reason.
//!
//! Read from authority metadata alone. Both readings this needs, the branch's
//! target and the workspace's base target, live in the persisted authority
//! record, so no caller pays a change-DAG decode to learn that its workspace
//! moved. That matters: on a converted repository the change map is most of the
//! snapshot body and `kin status` deliberately never touches it.
//!
//! The distance in changes is therefore NOT part of the reading. It cannot be
//! had without walking history, so it is filled in by [`with_distance`] and only
//! by a caller that already decoded the DAG for its own answer. A reading
//! without it says the tips differ, which is the whole of what metadata proves.

use kin_model::{RefName, RefTarget, SemanticChangeId, WorkspaceHead, WorkspaceState};
use serde::{Deserialize, Serialize};

/// Where a workspace sits relative to the branch its head names.
///
/// Every arm is a statement a reader can act on, including the two that are not
/// about a lagging workspace. A detached head has no branch tip to compare
/// with and an unborn branch has no target yet, and both of those rendered as
/// silence would read exactly like agreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WorkspaceTip {
    /// The workspace is projected at the change its branch names.
    AtBranchTip {
        branch: RefName,
        tip: SemanticChangeId,
    },
    /// The branch names a change this workspace is not projected at.
    Behind {
        branch: RefName,
        tip: SemanticChangeId,
        /// The change the workspace is projected at, absent on an unborn
        /// workspace.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        projected: Option<SemanticChangeId>,
        /// Changes between the projected change and the branch tip, where a
        /// caller established ancestry. `None` means nobody walked, not that
        /// the distance is zero.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        distance: Option<usize>,
    },
    /// The head is symbolic and its branch has no target yet.
    BranchUnborn { branch: RefName },
    /// The head names a change directly, so there is no branch to lag behind.
    Detached,
    /// The comparison could not be made, and why.
    Unknown { reason: String },
}

impl WorkspaceTip {
    /// Whether this reading says the workspace and its branch have come apart.
    pub fn is_behind(&self) -> bool {
        matches!(self, Self::Behind { .. })
    }

    /// The same reading with a distance a caller established by walking history.
    ///
    /// Silently ignored on every arm but [`Self::Behind`], because a distance
    /// means nothing on the others and a caller that computed one anyway has
    /// already spent the walk.
    #[must_use]
    pub fn with_distance(self, changes: usize) -> Self {
        match self {
            Self::Behind {
                branch,
                tip,
                projected,
                ..
            } => Self::Behind {
                branch,
                tip,
                projected,
                distance: Some(changes),
            },
            other => other,
        }
    }
}

/// The branch name a `kin branch switch` argument would take.
///
/// Falls back to the fully qualified name rather than guessing, so a ref
/// outside `refs/heads/` renders a command the reader can still paste.
fn switch_argument(branch: &RefName) -> String {
    let rendered = branch.to_string();
    rendered
        .strip_prefix("refs/heads/")
        .unwrap_or(&rendered)
        .to_string()
}

/// The status and log line for one reading, worded so the next command is in
/// the sentence.
///
/// Never empty. A verb that prints this line only when something is wrong
/// teaches its reader that no line means agreement, and no line is also what a
/// build that lost this reading would print.
pub fn line(tip: &WorkspaceTip) -> String {
    const LEAD: &str = "Workspace tip:";
    match tip {
        WorkspaceTip::AtBranchTip { branch, tip } => {
            format!("{LEAD} projected at {branch} ({tip})")
        }
        WorkspaceTip::Behind {
            branch,
            tip,
            projected,
            distance,
        } => {
            let gap = match (projected, distance) {
                (Some(projected), Some(1)) => {
                    format!("projected at {projected}, 1 change behind {branch} ({tip})")
                }
                (Some(projected), Some(count)) => {
                    format!("projected at {projected}, {count} changes behind {branch} ({tip})")
                }
                // No walk established ancestry, so no count is claimed. Saying
                // the tips differ is the whole of what authority metadata proves.
                (Some(projected), None) => format!(
                    "projected at {projected}, which is not the change {branch} names ({tip})"
                ),
                (None, _) => format!("unborn, while {branch} names {tip}"),
            };
            format!(
                "{LEAD} {gap}; `kin branch switch {}` projects the branch tip, and nothing above \
                 describes it",
                switch_argument(branch)
            )
        }
        WorkspaceTip::BranchUnborn { branch } => {
            format!("{LEAD} {branch} has no target yet, so there is no branch tip to compare with")
        }
        WorkspaceTip::Detached => format!(
            "{LEAD} this head names a change directly, so it follows no branch; `kin branch \
             switch <branch>` attaches it"
        ),
        WorkspaceTip::Unknown { reason } => {
            format!("{LEAD} not compared with this workspace's branch; {reason}")
        }
    }
}

/// Read the tip comparison from resolvers the caller supplies.
///
/// Split from [`read`] so the four interesting shapes are testable without a
/// store: an authority open is O(store) and a test that needs one cannot be run
/// on every arm.
pub fn measure(
    head: &WorkspaceHead,
    base_target: Option<&RefTarget>,
    resolve_ref: impl Fn(&RefName) -> Result<Option<RefTarget>, String>,
    resolve_change: impl Fn(&RefTarget) -> Result<SemanticChangeId, String>,
) -> WorkspaceTip {
    let WorkspaceHead::Symbolic { target: branch } = head else {
        return WorkspaceTip::Detached;
    };
    let branch_target = match resolve_ref(branch) {
        Ok(Some(target)) => target,
        Ok(None) => {
            return WorkspaceTip::BranchUnborn {
                branch: branch.clone(),
            }
        }
        Err(reason) => {
            return WorkspaceTip::Unknown {
                reason: format!("its branch {branch} would not resolve ({reason})"),
            }
        }
    };
    let tip = match resolve_change(&branch_target) {
        Ok(tip) => tip,
        Err(reason) => {
            return WorkspaceTip::Unknown {
                reason: format!("the target of {branch} would not resolve to a change ({reason})"),
            }
        }
    };
    // An unborn workspace under a born branch is behind by construction, and it
    // is the shape a fresh store takes after receiving its first push.
    let Some(base_target) = base_target else {
        return WorkspaceTip::Behind {
            branch: branch.clone(),
            tip,
            projected: None,
            distance: None,
        };
    };
    let projected = match resolve_change(base_target) {
        Ok(projected) => projected,
        Err(reason) => {
            return WorkspaceTip::Unknown {
                reason: format!(
                    "this workspace's own base target would not resolve to a change ({reason})"
                ),
            }
        }
    };
    if projected == tip {
        return WorkspaceTip::AtBranchTip {
            branch: branch.clone(),
            tip,
        };
    }
    WorkspaceTip::Behind {
        branch: branch.clone(),
        tip,
        projected: Some(projected),
        distance: None,
    }
}

/// Read the tip comparison off one authority lease.
///
/// Metadata only. `resolve_ref_target` and `resolve_target_change_id` both
/// answer from the persisted authority record, so this decodes no change map
/// and costs nothing that scales with history.
pub fn read(lease: &kin_db::RepositoryAuthorityState, workspace: &WorkspaceState) -> WorkspaceTip {
    measure(
        &workspace.head,
        workspace.base_target.as_ref(),
        |name| {
            lease
                .resolve_ref_target(name)
                .map_err(|error| error.to_string())
        },
        |target| {
            lease
                .resolve_target_change_id(target)
                .map_err(|error| error.to_string())
        },
    )
}

/// How many changes separate `projected` from `tip`, walking first parents and
/// merges alike, or `None` when ancestry was not established inside `cap`.
///
/// `None` is deliberately not zero and not an error. A projected change that is
/// not an ancestor of the tip is a real state (the branch was force-moved), and
/// so is a walk that ran out of budget on a converted repository's history.
/// Both mean the same thing to a reader: the tips differ and no count is
/// claimed.
pub fn distance(
    tip: &SemanticChangeId,
    projected: &SemanticChangeId,
    parents: impl Fn(&SemanticChangeId) -> Option<Vec<SemanticChangeId>>,
    cap: usize,
) -> Option<usize> {
    if tip == projected {
        return Some(0);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut pending = std::collections::VecDeque::new();
    seen.insert(*tip);
    pending.push_back((*tip, 0_usize));
    let mut visited = 0_usize;
    while let Some((change_id, depth)) = pending.pop_front() {
        visited += 1;
        if visited > cap {
            return None;
        }
        for parent in parents(&change_id)? {
            if &parent == projected {
                return Some(depth + 1);
            }
            if seen.insert(parent) {
                pending.push_back((parent, depth + 1));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::Hash256;

    fn change(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn main_branch() -> RefName {
        RefName::from_utf8("refs/heads/main").expect("refs/heads/main is a legal ref name")
    }

    fn symbolic() -> WorkspaceHead {
        WorkspaceHead::Symbolic {
            target: main_branch(),
        }
    }

    /// Resolvers for a store whose `refs/heads/main` names `tip`.
    fn resolvers(
        tip: SemanticChangeId,
    ) -> (
        impl Fn(&RefName) -> Result<Option<RefTarget>, String>,
        impl Fn(&RefTarget) -> Result<SemanticChangeId, String>,
    ) {
        (
            move |_: &RefName| Ok(Some(RefTarget::change(tip))),
            |target: &RefTarget| match target {
                RefTarget::Change { change_id } => Ok(*change_id),
                other => Err(format!("{other:?} is not a change")),
            },
        )
    }

    /// GAP-8, rebuilt: the origin received a push, its `refs/heads/main` moved,
    /// and its workspace is still projected at the change before it.
    ///
    /// Breaking it: return `AtBranchTip` unconditionally from `measure`, or drop
    /// the `projected == tip` comparison so every workspace reads as current.
    /// Either makes this assertion fail, and either is the defect.
    #[test]
    fn a_workspace_left_behind_by_a_push_says_so_and_names_the_switch() {
        let (resolve_ref, resolve_change) = resolvers(change(0x12));
        let reading = measure(
            &symbolic(),
            Some(&RefTarget::change(change(0x1e))),
            resolve_ref,
            resolve_change,
        );
        assert!(reading.is_behind(), "{reading:?}");
        let rendered = line(&reading);
        assert!(rendered.contains("refs/heads/main"), "{rendered}");
        assert!(
            rendered.contains("kin branch switch main"),
            "the line must name the command that projects the tip: {rendered}"
        );
    }

    /// The control. A workspace projected at its branch tip must not be told it
    /// is behind, or every store reads as lagging and the line means nothing.
    #[test]
    fn a_workspace_at_its_branch_tip_is_not_reported_behind() {
        let tip = change(0x12);
        let (resolve_ref, resolve_change) = resolvers(tip);
        let reading = measure(
            &symbolic(),
            Some(&RefTarget::change(tip)),
            resolve_ref,
            resolve_change,
        );
        assert_eq!(
            reading,
            WorkspaceTip::AtBranchTip {
                branch: main_branch(),
                tip,
            }
        );
        let rendered = line(&reading);
        assert!(!rendered.contains("behind"), "{rendered}");
        assert!(
            !rendered.contains("kin branch switch"),
            "a workspace with nothing to do must not be handed a command: {rendered}"
        );
    }

    /// A detached head follows no branch, and saying nothing would read exactly
    /// like agreement with one.
    #[test]
    fn a_detached_head_says_it_follows_no_branch() {
        let (resolve_ref, resolve_change) = resolvers(change(0x12));
        let reading = measure(
            &WorkspaceHead::Detached {
                target: RefTarget::change(change(0x1e)),
            },
            Some(&RefTarget::change(change(0x1e))),
            resolve_ref,
            resolve_change,
        );
        assert_eq!(reading, WorkspaceTip::Detached);
        assert!(line(&reading).contains("follows no branch"));
    }

    /// An unborn workspace under a born branch is behind, which is the shape a
    /// fresh store takes after receiving its first push.
    #[test]
    fn an_unborn_workspace_under_a_born_branch_is_behind() {
        let (resolve_ref, resolve_change) = resolvers(change(0x12));
        let reading = measure(&symbolic(), None, resolve_ref, resolve_change);
        assert!(reading.is_behind(), "{reading:?}");
        assert!(line(&reading).contains("unborn"), "{}", line(&reading));
    }

    /// A count is claimed only when a caller walked for it, and never invented.
    #[test]
    fn a_distance_is_rendered_only_once_a_caller_establishes_it() {
        let (resolve_ref, resolve_change) = resolvers(change(0x12));
        let reading = measure(
            &symbolic(),
            Some(&RefTarget::change(change(0x1e))),
            resolve_ref,
            resolve_change,
        );
        assert!(
            !line(&reading).contains("behind"),
            "a reading with no walk behind it must not claim a count: {}",
            line(&reading)
        );
        let counted = reading.with_distance(3);
        assert!(
            line(&counted).contains("3 changes behind"),
            "{}",
            line(&counted)
        );
        assert!(line(&WorkspaceTip::Behind {
            branch: main_branch(),
            tip: change(0x12),
            projected: Some(change(0x1e)),
            distance: Some(1),
        })
        .contains("1 change behind"));
    }

    /// The walk counts merges as well as first parents, and refuses rather than
    /// guessing when the projected change is not an ancestor at all.
    #[test]
    fn the_walk_counts_ancestry_and_refuses_a_change_it_cannot_reach() {
        let (tip, mid, root, stray) = (change(1), change(2), change(3), change(9));
        let parents = |id: &SemanticChangeId| {
            if id == &tip {
                Some(vec![mid])
            } else if id == &mid {
                Some(vec![root])
            } else if id == &root || id == &stray {
                Some(Vec::new())
            } else {
                None
            }
        };
        assert_eq!(distance(&tip, &mid, parents, 100), Some(1));
        assert_eq!(distance(&tip, &root, parents, 100), Some(2));
        assert_eq!(distance(&tip, &tip, parents, 100), Some(0));
        assert_eq!(
            distance(&tip, &stray, parents, 100),
            None,
            "a change the tip is not descended from has no distance to claim"
        );
        assert_eq!(
            distance(&tip, &root, parents, 1),
            None,
            "a walk that runs out of budget claims nothing rather than a short count"
        );
    }
}
