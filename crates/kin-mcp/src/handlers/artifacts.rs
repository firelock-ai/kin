// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository-artifact MCP surfaces.
//!
//! Semantic entities are an enrichment of repository truth, not its membership
//! boundary. These handlers therefore read the identity-bearing repository tree
//! directly. Configuration, lockfiles, binaries, unsupported languages,
//! symlinks, and gitlinks remain visible even when no parser emits an entity.

use base64::Engine as _;
use kin_model::{
    ArtifactId, GitObjectId, GraphStore, RepoPath, ResolvedArtifact, ResolvedTree,
    SemanticChangeId, TreeEntry,
};
use serde::Serialize;
use std::collections::HashMap;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

pub const ARTIFACT_LIST_DESC: &str = "\
List the exact graph-owned repository artifacts at one semantic change. This is the \
repository-membership surface: it includes code and every non-code tracked object such as \
Docker Compose files, Dockerfiles, lockfiles, configuration, binary assets, unsupported \
languages, symlinks, executable files, and gitlinks. Paths are returned as canonical \
lowercase `bytes_hex` objects; `path_label` is presentation-only and \
`path_label_lossy` says whether replacement characters were required. Identity comes from \
`artifact_id`, never from a path. Content-addressed ids are lowercase hex strings: each \
entry's blob `hash`, a symlink's `target_blob`, and the response's `source_change_id`, so a \
value this returns can be passed straight back into `kin_artifact_read`'s \
`source_change_id` or compared against what `kin log` prints. A gitlink is the one \
exception: its `target` keeps the algorithm-tagged object, because a repository may be sha1 \
or sha256 and that discriminator is not recoverable from a bare string, and `target_hex` \
carries the printable form beside it. Omit `source_change_id` to read the exact current \
workspace tree.";

pub const ARTIFACT_READ_DESC: &str = "\
Read one exact graph-owned repository artifact by stable `artifact_id` or canonical \
byte-exact `path`. Blob and symlink bytes are returned losslessly as base64 and, only when \
valid UTF-8, as `text_utf8`. Gitlinks return their external object identity, as the \
algorithm-tagged `git_object_id` plus a printable `git_object_id_hex`, and have no \
repository-owned body. Content-addressed hashes are lowercase hex strings, including the \
returned `source_change_id`, which is exactly the form this tool's own `source_change_id` \
parameter takes, so a read can be repeated at the change a \
previous call reported. The read is bound to the resolved tree entry at \
`source_change_id` (or the exact current workspace) and fails loudly when the tree, identity, \
or content-addressed blob is missing. It never reads the working directory.";

/// One tree entry with its content-addressed ids rendered as hex.
///
/// `Hash256` and `GitObjectId` serialize through the model as arrays of 32 and
/// 20 integers, so every blob hash and symlink target reached an agent as a wall
/// of decimal numbers. That is roughly four times the size of the hex it stands
/// for, and it is not the form any Kin surface accepts back: a hash a caller
/// wants to correlate against `kin log`, a formula, or another tool's input has
/// to be reassembled by hand first.
///
/// The tag and field names mirror [`TreeEntry`] exactly, so only the encoding of
/// the ids changes. Rendering is `Display`, which is lowercase hex and the same
/// spelling `Hash256::from_hex` parses, so what this prints round-trips.
///
/// A gitlink is the exception, and the asymmetry is the types' rather than a
/// choice. `Hash256` is always the one algorithm, so hex loses nothing.
/// `GitObjectId` carries an `algorithm` discriminator because a repository may be
/// sha1 or sha256, and collapsing it to a hex string would drop that. Its
/// `target` therefore keeps the model's own tagged object and gains
/// `target_hex` beside it, so the value is readable without the discriminator
/// being thrown away.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TreeEntryWire {
    Blob {
        hash: String,
        executable: bool,
    },
    Symlink {
        target_blob: String,
    },
    Gitlink {
        target: GitObjectId,
        target_hex: String,
    },
}

impl From<TreeEntry> for TreeEntryWire {
    fn from(entry: TreeEntry) -> Self {
        match entry {
            TreeEntry::Blob { hash, executable } => Self::Blob {
                hash: hash.to_string(),
                executable,
            },
            TreeEntry::Symlink { target_blob } => Self::Symlink {
                target_blob: target_blob.to_string(),
            },
            TreeEntry::Gitlink { target } => Self::Gitlink {
                target_hex: target.to_string(),
                target,
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct ArtifactWire {
    artifact_id: ArtifactId,
    path: RepoPath,
    path_label: String,
    path_label_lossy: bool,
    entry: TreeEntryWire,
}

impl From<&ResolvedArtifact> for ArtifactWire {
    fn from(artifact: &ResolvedArtifact) -> Self {
        let path_label_lossy = artifact.path.as_utf8().is_none();
        let path_label = String::from_utf8_lossy(artifact.path.as_bytes()).into_owned();
        Self {
            artifact_id: artifact.artifact_id,
            path: artifact.path.clone(),
            path_label,
            path_label_lossy,
            entry: artifact.entry.into(),
        }
    }
}

/// The change a tree was read at, rendered the way this surface's own input
/// demands it.
///
/// `kin_artifact_read`'s `source_change_id` parameter requires a 64-character
/// hex string, while the response serialized the same id as 32 integers, so the
/// value a caller just received could not be passed back without converting it
/// first. An output that does not round-trip into its own input is a dead end
/// wearing the name of a handle.
fn source_change_id_hex(source_change_id: Option<SemanticChangeId>) -> Option<String> {
    source_change_id.map(|id| id.to_string())
}

#[derive(Debug)]
pub(crate) struct ExactTreeSelection {
    pub source_change_id: Option<SemanticChangeId>,
    pub tree: ResolvedTree,
}

fn require_repository_authority(
    binding: Option<&super::repository_authority::RequestRepositoryAuthority>,
) -> Result<std::sync::Arc<super::repository_authority::ActiveRepositoryAuthority>> {
    binding
        .ok_or_else(|| {
            McpError::Context(
                "graph authority gap: this MCP runtime has no startup-pinned local repository \
                 authority binding"
                    .to_string(),
            )
        })?
        .open()
}

fn explicit_source_change_id(
    args: &HashMap<String, serde_json::Value>,
) -> Result<Option<SemanticChangeId>> {
    args.get("source_change_id")
        .map(|value| {
            let raw = value.as_str().ok_or_else(|| {
                McpError::InvalidParams("source_change_id must be a lowercase hex string".into())
            })?;
            crate::handlers::common::parse_change_id(raw)
        })
        .transpose()
}

pub(crate) fn resolve_tree_selection<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&super::repository_authority::RequestRepositoryAuthority>,
) -> Result<ExactTreeSelection> {
    let explicit = explicit_source_change_id(args)?;
    let (source_change_id, tree) = match explicit {
        Some(id) => {
            let tree = store.resolve_tree_at(&id).map_err(|error| {
                McpError::Context(format!(
                    "graph authority gap: cannot resolve exact repository tree at \
                     {id}: {error}"
                ))
            })?;
            (Some(id), tree)
        }
        None => {
            let authority = require_repository_authority(repository_authority)?;
            let workspace = authority.workspace()?;
            let source_change_id = workspace
                .base_target
                .as_ref()
                .map(|target| authority.resolve_target(target))
                .transpose()?;
            (source_change_id, workspace.tree)
        }
    };
    Ok(ExactTreeSelection {
        source_change_id,
        tree,
    })
}

fn parse_artifact_id(value: &serde_json::Value) -> Result<ArtifactId> {
    serde_json::from_value(value.clone())
        .map_err(|error| McpError::InvalidParams(format!("invalid artifact_id: {error}")))
}

fn parse_repo_path(value: &serde_json::Value) -> Result<RepoPath> {
    serde_json::from_value(value.clone()).map_err(|error| {
        McpError::InvalidParams(format!(
            "invalid byte-exact path; expected {{\"bytes_hex\":\"...\"}}: {error}"
        ))
    })
}

fn select_artifact<'a>(
    args: &HashMap<String, serde_json::Value>,
    tree: &'a ResolvedTree,
) -> Result<&'a ResolvedArtifact> {
    let by_id = args
        .get("artifact_id")
        .map(parse_artifact_id)
        .transpose()?
        .and_then(|id| tree.get(&id));
    let by_path = args
        .get("path")
        .map(parse_repo_path)
        .transpose()?
        .and_then(|path| tree.artifact_at_path(&path));

    match (args.contains_key("artifact_id"), args.contains_key("path")) {
        (false, false) => Err(McpError::InvalidParams(
            "one of artifact_id or path is required".into(),
        )),
        (true, false) => by_id.ok_or_else(|| {
            McpError::Context("graph authority gap: artifact_id is absent from this tree".into())
        }),
        (false, true) => by_path.ok_or_else(|| {
            McpError::Context("graph authority gap: exact path is absent from this tree".into())
        }),
        (true, true) => match (by_id, by_path) {
            (Some(left), Some(right)) if left.artifact_id == right.artifact_id => Ok(left),
            (Some(_), Some(_)) => Err(McpError::InvalidParams(
                "artifact_id and path resolve to different graph artifacts".into(),
            )),
            _ => Err(McpError::Context(
                "graph authority gap: artifact_id and path do not both resolve in this tree".into(),
            )),
        },
    }
}

pub fn handle_artifact_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&super::repository_authority::RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let selection = resolve_tree_selection(args, store, repository_authority)?;
    let offset = args
        .get("offset")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    let limit = args
        .get("limit")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(200)
        .clamp(1, 1_000) as usize;
    let total = selection.tree.len();
    let artifacts = selection
        .tree
        .artifacts_by_path()
        .skip(offset)
        .take(limit)
        .map(ArtifactWire::from)
        .collect::<Vec<_>>();
    let returned = artifacts.len();
    let result = serde_json::json!({
        "source_change_id": source_change_id_hex(selection.source_change_id),
        "artifact_count": total,
        "offset": offset,
        "returned": returned,
        "truncated": offset.saturating_add(returned) < total,
        "artifacts": artifacts,
    });
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&result).map_err(McpError::Json)?,
    ))
}

pub fn handle_artifact_read<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&super::repository_authority::RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let selection = resolve_tree_selection(args, store, repository_authority)?;
    let artifact = select_artifact(args, &selection.tree)?;
    let mut result = serde_json::json!({
        "source_change_id": source_change_id_hex(selection.source_change_id),
        "artifact": ArtifactWire::from(artifact),
    });

    match artifact.entry {
        TreeEntry::Gitlink { target } => {
            result["content_kind"] = serde_json::json!("gitlink_reference");
            // The tagged object stays: it names the hash algorithm, and a
            // repository may be sha1 or sha256. The hex rides beside it so the
            // pointer can be compared against what Git prints without
            // reassembling the bytes by hand.
            result["git_object_id"] = serde_json::to_value(target).map_err(McpError::Json)?;
            result["git_object_id_hex"] = serde_json::json!(target.to_string());
        }
        TreeEntry::Blob { hash, .. } | TreeEntry::Symlink { target_blob: hash } => {
            let authority = require_repository_authority(repository_authority)?;
            let bytes = authority.load_source_blob(hash).map_err(|error| {
                McpError::Context(format!(
                    "graph authority gap: blob {} for artifact {:?} at {} is unavailable or \
                     corrupt: {error}",
                    hash, artifact.artifact_id, artifact.path
                ))
            })?;
            result["content_kind"] = serde_json::json!(match artifact.entry {
                TreeEntry::Blob { .. } => "blob",
                TreeEntry::Symlink { .. } => "symlink_target",
                TreeEntry::Gitlink { .. } => unreachable!(),
            });
            result["content_length"] = serde_json::json!(bytes.len());
            result["content_base64"] =
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(&bytes));
            if let Ok(text) = std::str::from_utf8(&bytes) {
                result["text_utf8"] = serde_json::json!(text);
            }
        }
    }

    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&result).map_err(McpError::Json)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::ids::Hash256;

    fn artifact_with(entry: TreeEntry) -> ResolvedArtifact {
        ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("AGENTS.md").expect("a utf8 repo path"),
            entry,
        )
    }

    fn wire_of(entry: TreeEntry) -> serde_json::Value {
        serde_json::to_value(ArtifactWire::from(&artifact_with(entry)))
            .expect("the wire artifact serializes")
    }

    fn is_lowercase_hex(value: &serde_json::Value, nibbles: usize) -> bool {
        value.as_str().is_some_and(|text| {
            text.len() == nibbles
                && text
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
        })
    }

    /// FIR-2219. Every content-addressed id on this surface reached an agent as
    /// an array of 32 decimal integers, roughly four times the size of the hex it
    /// stood for and not the form any Kin surface accepts back.
    #[test]
    fn a_blob_hash_is_hex_that_parses_back_to_the_same_hash() {
        let hash = Hash256::from_bytes([0xab; 32]);
        let wire = wire_of(TreeEntry::Blob {
            hash,
            executable: true,
        });

        assert_eq!(wire["entry"]["type"], serde_json::json!("blob"));
        assert!(
            is_lowercase_hex(&wire["entry"]["hash"], 64),
            "a blob hash must be 64 lowercase hex characters: {}",
            wire["entry"]["hash"]
        );
        // The round trip is the point: what this prints must parse back through
        // the same hex reader the surface's own inputs use.
        assert_eq!(
            Hash256::from_hex(wire["entry"]["hash"].as_str().unwrap()).unwrap(),
            hash
        );
        // The bit that had to change: no longer an array of integers.
        assert!(
            !wire["entry"]["hash"].is_array(),
            "the byte-array encoding must be gone: {}",
            wire["entry"]["hash"]
        );
        // The rest of the entry is untouched, which is what makes this an
        // encoding change rather than a schema change.
        assert_eq!(wire["entry"]["executable"], serde_json::json!(true));
    }

    #[test]
    fn a_symlink_target_and_a_gitlink_target_are_hex_too() {
        let target_blob = Hash256::from_bytes([0x3c; 32]);
        let wire = wire_of(TreeEntry::Symlink { target_blob });
        assert_eq!(wire["entry"]["type"], serde_json::json!("symlink"));
        assert!(is_lowercase_hex(&wire["entry"]["target_blob"], 64));
        assert_eq!(
            Hash256::from_hex(wire["entry"]["target_blob"].as_str().unwrap()).unwrap(),
            target_blob
        );

        // A gitlink keeps its algorithm discriminator and gains the printable
        // form beside it. Rendering the target as hex ALONE would drop the
        // algorithm, which a bare 40-character string cannot carry back, and a
        // repository may be sha1 or sha256. An existing test caught exactly that
        // when this first collapsed the object to a string.
        let target = GitObjectId::sha1([0x43; 20]);
        let wire = wire_of(TreeEntry::Gitlink { target });
        assert_eq!(wire["entry"]["type"], serde_json::json!("gitlink"));
        assert_eq!(
            wire["entry"]["target"],
            serde_json::to_value(target).unwrap(),
            "the algorithm-tagged object must survive: {}",
            wire["entry"]["target"]
        );
        assert_eq!(
            wire["entry"]["target"]["algorithm"],
            serde_json::json!("sha1")
        );
        // Git prints a sha1 object id as 40 hex characters.
        assert!(is_lowercase_hex(&wire["entry"]["target_hex"], 40));
        assert_eq!(
            wire["entry"]["target_hex"],
            serde_json::json!(target.to_string())
        );
    }

    /// The wire mirror must not rename, retag, or DROP what the model
    /// serializes, or a consumer parsing one shape breaks on the other. Only a
    /// hash may change encoding, and only additive fields may appear.
    ///
    /// The first version of this guard compared top-level key names alone, which
    /// is why it passed while the gitlink target had been collapsed from an
    /// algorithm-tagged object to a bare hex string. A guard that cannot see a
    /// dropped discriminator is not a guard, so it now asserts every model field
    /// survives byte-for-byte unless it is a hash rendered as hex.
    #[test]
    fn the_wire_entry_keeps_every_field_the_model_serializes() {
        for (entry, hex_rendered) in [
            (
                TreeEntry::Blob {
                    hash: Hash256::from_bytes([1; 32]),
                    executable: false,
                },
                vec!["hash"],
            ),
            (
                TreeEntry::Symlink {
                    target_blob: Hash256::from_bytes([2; 32]),
                },
                vec!["target_blob"],
            ),
            (
                TreeEntry::Gitlink {
                    target: GitObjectId::sha1([3; 20]),
                },
                vec![],
            ),
        ] {
            let model = serde_json::to_value(entry).expect("the model entry serializes");
            let wire = serde_json::to_value(TreeEntryWire::from(entry))
                .expect("the wire entry serializes");
            let model_fields = model.as_object().expect("an object");
            let wire_fields = wire.as_object().expect("an object");

            for (field, model_value) in model_fields {
                let wire_value = wire_fields
                    .get(field)
                    .unwrap_or_else(|| panic!("the wire entry dropped {field}: {wire}"));
                if hex_rendered.contains(&field.as_str()) {
                    assert!(
                        wire_value.is_string(),
                        "{field} must be rendered as hex: {wire_value}"
                    );
                } else {
                    assert_eq!(
                        model_value, wire_value,
                        "{field} must be carried through unchanged: {wire}"
                    );
                }
            }
            assert_eq!(
                model["type"], wire["type"],
                "the variant tag must be unchanged: {model} vs {wire}"
            );
        }
    }

    /// The defect the ticket leads with: `kin_artifact_read`'s own
    /// `source_change_id` input demands 64-char hex while the response serialized
    /// the same id as 32 integers, so a returned change id could not be fed back.
    #[test]
    fn a_returned_source_change_id_parses_as_this_surface_s_own_input() {
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x7e; 32]));
        let rendered = source_change_id_hex(Some(change_id)).expect("a present id renders");
        assert_eq!(rendered.len(), 64);

        // Parsed by the exact function `explicit_source_change_id` uses on the way
        // in, so this closes the loop rather than asserting a look-alike.
        let args = HashMap::from([(
            "source_change_id".to_string(),
            serde_json::json!(rendered.clone()),
        )]);
        assert_eq!(
            explicit_source_change_id(&args).expect("the rendered id is accepted"),
            Some(change_id)
        );

        // Negative control: the encoding this replaces is refused by that same
        // input, which is why the old output could not round-trip.
        let byte_array = HashMap::from([(
            "source_change_id".to_string(),
            serde_json::to_value(change_id).expect("the model encoding serializes"),
        )]);
        assert!(
            explicit_source_change_id(&byte_array).is_err(),
            "the byte-array encoding must not be accepted as input"
        );

        // An absent id stays absent rather than becoming an empty string.
        assert_eq!(source_change_id_hex(None), None);
    }
}
