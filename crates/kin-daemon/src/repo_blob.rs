// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `GET /repos/{repo_id}/blob` — one file's exact bytes, for a repository and a ref.
//!
//! The daemon could already list a repository's files and could already export
//! every byte of a change as one archive. It could not answer the question in
//! between, which is the one a reader actually asks: show me this file. A
//! hosted surface that wants to render a file therefore had nothing to call,
//! and the honest thing it could do was say so.
//!
//! The answer comes from the repository read view and the content-addressed
//! store and from nowhere else. The path is looked up in the tree the requested
//! ref resolves to, the bytes come back under the digest that tree recorded,
//! and the digest is checked against the bytes before they are served. A path
//! the ref's tree does not carry is a refusal naming both, never a walk of a
//! working copy that might happen to hold it.
//!
//! The digest check is not ceremony. `Ok(None)` from the store already means
//! the bytes were never persisted, and the store verifies its own read, but
//! this route serves those bytes to a browser under a ref and a path, and the
//! response says which digest they were verified against. A claim that specific
//! is worth re-establishing at the point that makes it.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use kin_model::RepoPath;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::{
    default_repository_ref, parse_semantic_change_id, repository_read_view,
    repository_source_blob_loader, short_ref_name, RepositorySourceBlobLoader,
};
use crate::state::DaemonState;

/// The largest single file this route will materialize into a JSON response.
///
/// A code view renders source, and the response holds the whole body in memory
/// on both sides of the wire. The exact-source archive's own ceiling is two
/// orders of magnitude larger because it is a download; this is a read. Over
/// this, the route refuses and names the size rather than sending it.
pub const MAX_REPO_BLOB_BYTES: u64 = 8 * 1024 * 1024;

/// The header every refusal from this route carries, naming which refusal it is.
pub const REPO_BLOB_REFUSAL_HEADER: &str = "x-kin-blob-refusal";

/// Which refusal, in a closed set a caller can branch on without reading English.
///
/// The status code alone cannot carry this and the sentence must not be asked
/// to. `path-not-found` and `unknown-ref` are both 404 and mean opposite things
/// to a caller assembling a comparison: the first says this ref's tree does not
/// carry that path, which is what an added or a deleted file looks like from one
/// side; the second says nothing was read at all, and treating it as an absent
/// side manufactures a change that never happened. So the kind travels in a
/// header, in a fixed vocabulary, and every refusal this route emits carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoBlobRefusal {
    /// The request itself could not be understood, so nothing was resolved.
    BadRequest,
    /// This daemon does not serve a repository by that id.
    UnknownRepository,
    /// It serves the id and could not read it as a repository.
    RepositoryUnreadable,
    /// The read point named neither a ref this repository carries nor a
    /// canonical change id, so no tree was resolved and no path was looked up.
    UnknownRef,
    /// The read point is a short alias more than one ref answers to, and this
    /// route will not pick one of them.
    AmbiguousRef,
    /// The ref resolved and its tree carries no such path.
    PathNotFound,
    /// The path resolved and its bytes could not be served.
    SourceUnavailable,
}

impl RepoBlobRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::UnknownRepository => "unknown-repository",
            Self::RepositoryUnreadable => "repository-unreadable",
            Self::UnknownRef => "unknown-ref",
            Self::AmbiguousRef => "ambiguous-ref",
            Self::PathNotFound => "path-not-found",
            Self::SourceUnavailable => "source-unavailable",
        }
    }
}

/// A refusal from this route: a status, a kind, and a sentence for a person.
#[derive(Debug)]
pub struct RepoBlobError {
    pub status: StatusCode,
    pub kind: RepoBlobRefusal,
    pub message: String,
}

impl RepoBlobError {
    fn new(status: StatusCode, kind: RepoBlobRefusal, message: impl Into<String>) -> Self {
        Self {
            status,
            kind,
            message: message.into(),
        }
    }

    /// Carry a helper's `(status, message)` refusal out under an explicit kind.
    ///
    /// The kind is named at the call site rather than guessed from the status,
    /// because two of them share a status and the whole point of the header is
    /// that a caller does not have to guess.
    fn from_parts(kind: RepoBlobRefusal, parts: (StatusCode, String)) -> Self {
        Self::new(parts.0, kind, parts.1)
    }
}

impl IntoResponse for RepoBlobError {
    fn into_response(self) -> axum::response::Response {
        let mut response = (self.status, self.message).into_response();
        response.headers_mut().insert(
            HeaderName::from_static(REPO_BLOB_REFUSAL_HEADER),
            HeaderValue::from_static(self.kind.as_str()),
        );
        response
    }
}

#[derive(Debug, Deserialize)]
pub struct RepoBlobQuery {
    /// The repository-relative path, exactly as `/repos/{repo_id}/files` spells it.
    path: String,
    /// A ref name or a canonical change id. Absent means the default ref.
    #[serde(default, rename = "ref")]
    reference: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoBlobResponse {
    pub repo_id: String,
    pub path: RepoPath,
    pub display_path: String,
    /// What the caller asked for, echoed so a cache can key on it.
    pub requested_ref: Option<String>,
    /// The ref this actually read, or `None` when a change id was named directly.
    pub resolved_ref: Option<String>,
    /// The change the ref resolved to.
    pub change_id: String,
    /// The digest the bytes below were verified against, before they were sent.
    pub content_sha256: String,
    pub byte_len: u64,
    /// False for bytes that are not UTF-8, where `content` is `null`.
    pub is_utf8: bool,
    pub content: Option<String>,
}

/// The bytes one path resolves to, and the digest they were checked against.
#[derive(Debug)]
pub(crate) struct VerifiedBlob {
    pub(crate) digest: kin_model::Hash256,
    pub(crate) bytes: Vec<u8>,
}

/// Read one path out of a resolved tree, and verify what the store returns.
///
/// `describe_ref` appears in every refusal, because "this repository holds no
/// file at that path" is not actionable and "the tree at main holds no file at
/// that path" is.
pub(crate) fn read_verified_blob(
    tree: &kin_model::ResolvedTree,
    path: &RepoPath,
    describe_ref: &str,
    load_blob: &mut RepositorySourceBlobLoader,
) -> Result<VerifiedBlob, RepoBlobError> {
    let artifact = tree.artifact_at_path(path).ok_or_else(|| {
        RepoBlobError::new(
            StatusCode::NOT_FOUND,
            RepoBlobRefusal::PathNotFound,
            format!(
                "the repository tree at {describe_ref} holds no file at {path}; \
                 GET /repos/{{repo_id}}/files lists what it does hold"
            ),
        )
    })?;
    let digest = artifact.entry.blob_identity().ok_or_else(|| {
        RepoBlobError::new(
            StatusCode::FAILED_DEPENDENCY,
            RepoBlobRefusal::SourceUnavailable,
            format!("{path} at {describe_ref} is a gitlink and has no source body of its own"),
        )
    })?;
    let bytes = load_blob(path, digest, MAX_REPO_BLOB_BYTES)
        .map_err(|parts| RepoBlobError::from_parts(RepoBlobRefusal::SourceUnavailable, parts))?
        .ok_or_else(|| {
            RepoBlobError::new(
                StatusCode::FAILED_DEPENDENCY,
                RepoBlobRefusal::SourceUnavailable,
                format!(
                    "exact source bytes are unavailable for {path} at {digest}; \
                     no fallback was attempted"
                ),
            )
        })?;
    let byte_len = u64::try_from(bytes.len()).map_err(|_| {
        RepoBlobError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            RepoBlobRefusal::SourceUnavailable,
            format!("source blob length for {path} does not fit the allocation limit"),
        )
    })?;
    if byte_len > MAX_REPO_BLOB_BYTES {
        return Err(RepoBlobError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            RepoBlobRefusal::SourceUnavailable,
            format!(
                "{path} at {describe_ref} is {byte_len} bytes, over this route's \
                 {MAX_REPO_BLOB_BYTES}-byte ceiling"
            ),
        ));
    }
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != *digest.as_bytes() {
        return Err(RepoBlobError::new(
            StatusCode::FAILED_DEPENDENCY,
            RepoBlobRefusal::SourceUnavailable,
            format!(
                "source blob digest mismatch for {path} at {describe_ref}: \
                 tree records {digest}, store returned {}",
                hex::encode(actual)
            ),
        ));
    }
    Ok(VerifiedBlob { digest, bytes })
}

/// GET /repos/{repo_id}/blob — one file's exact bytes at one ref.
pub async fn repo_blob(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    // Fallible on purpose. `Query<T>` rejects a missing or repeated parameter
    // before a handler body runs, and an axum rejection carries no
    // `x-kin-blob-refusal`. A caller that branches on the header would read a
    // malformed request as a header this route forgot to set, which is the one
    // reading the header exists to prevent. Taking the rejection means every
    // refusal from this route, including the ones it never got to think about,
    // is named.
    query: Result<Query<RepoBlobQuery>, QueryRejection>,
) -> Result<impl IntoResponse, RepoBlobError> {
    let Query(query) = query.map_err(|rejection| {
        RepoBlobError::new(
            rejection.status(),
            RepoBlobRefusal::BadRequest,
            rejection.body_text(),
        )
    })?;
    let requested_path = RepoPath::from_utf8(query.path.clone()).map_err(|error| {
        RepoBlobError::new(
            StatusCode::BAD_REQUEST,
            RepoBlobRefusal::BadRequest,
            format!(
                "path {:?} is not a usable repository path: {error}",
                query.path
            ),
        )
    })?;
    let view = repository_read_view(&state, &repo_id)
        .await
        .map_err(|parts| {
            // Addressability and readability are different facts about the same
            // repository, and the status the shared helper already chose is what
            // separates them: it refuses an id this daemon does not serve with a
            // 404 before it attempts any load.
            let kind = if parts.0 == StatusCode::NOT_FOUND {
                RepoBlobRefusal::UnknownRepository
            } else {
                RepoBlobRefusal::RepositoryUnreadable
            };
            RepoBlobError::from_parts(kind, parts)
        })?;
    let (change_id, resolved_ref) =
        resolve_read_point(&view, query.reference.as_deref(), &repo_id)?;
    let describe_ref = resolved_ref
        .clone()
        .unwrap_or_else(|| change_id.to_string());
    let tree = view
        .resolve_tree_at(&state, &change_id)
        .map_err(|parts| RepoBlobError::from_parts(RepoBlobRefusal::RepositoryUnreadable, parts))?;

    let repo_for_load = repo_id.clone();
    let path_for_load = requested_path.clone();
    let describe_for_load = describe_ref.clone();
    let state_for_load = Arc::clone(&state);
    // The store read is blocking and the digest check runs over the whole body,
    // so neither belongs on the request's own thread.
    let blob = tokio::task::spawn_blocking(move || {
        let mut load_blob = repository_source_blob_loader(&state_for_load, &repo_for_load)
            .map_err(|parts| {
                RepoBlobError::from_parts(RepoBlobRefusal::SourceUnavailable, parts)
            })?;
        read_verified_blob(&tree, &path_for_load, &describe_for_load, &mut load_blob)
    })
    .await
    .map_err(|error| {
        RepoBlobError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            RepoBlobRefusal::SourceUnavailable,
            format!("repository blob worker failed: {error}"),
        )
    })??;

    let byte_len = blob.bytes.len() as u64;
    let content = String::from_utf8(blob.bytes).ok();
    Ok(Json(RepoBlobResponse {
        repo_id,
        display_path: requested_path
            .as_utf8()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| query.path.clone()),
        path: requested_path,
        requested_ref: query.reference,
        resolved_ref,
        change_id: change_id.to_string(),
        content_sha256: hex::encode(blob.digest.as_bytes()),
        byte_len,
        is_utf8: content.is_some(),
        content,
    }))
}

/// Turn the caller's `ref` into the change to read, and the ref name to say.
///
/// Three inputs, one answer. Nothing names a ref: the repository's own default,
/// which is what `/repos/{repo_id}/files` already reads. A name the authority
/// carries: that ref. A canonical change id: that change, with no ref name to
/// report, because none was involved. Anything else is `unknown-ref`, which is a
/// 404 about the read point and never about the path, since no tree was resolved
/// and nothing was looked up in one.
pub(crate) fn resolve_read_point(
    view: &crate::api::RepositoryReadView,
    reference: Option<&str>,
    repo_id: &str,
) -> Result<(kin_model::SemanticChangeId, Option<String>), RepoBlobError> {
    let authority = view
        .authority()
        .map_err(|parts| RepoBlobError::from_parts(RepoBlobRefusal::RepositoryUnreadable, parts))?;
    let resolve = |target: &kin_model::RefTarget| {
        view.resolve_target(target).map_err(|parts| {
            RepoBlobError::from_parts(RepoBlobRefusal::RepositoryUnreadable, parts)
        })
    };
    let Some(reference) = reference.map(str::trim).filter(|value| !value.is_empty()) else {
        let default_ref = default_repository_ref(authority)
            .map_err(|parts| {
                RepoBlobError::from_parts(RepoBlobRefusal::RepositoryUnreadable, parts)
            })?
            .ok_or_else(|| {
                RepoBlobError::new(
                    StatusCode::FAILED_DEPENDENCY,
                    RepoBlobRefusal::UnknownRef,
                    format!(
                        "repository {repo_id} carries no refs, so it has no default ref to read"
                    ),
                )
            })?;
        let name = short_ref_name(&default_ref.name);
        return Ok((resolve(&default_ref.target)?, Some(name)));
    };

    // A ref's full name wins outright, and only then its short alias, because a
    // repository may hold a branch whose full name IS another ref's short alias:
    // `refs/heads/refs/tags/v1` shortens to `refs/tags/v1`, which is the tag
    // `refs/tags/v1`'s own full name. One pass matching either spelling answers
    // whichever of the two the ref list happens to hold first, so an explicit
    // full name could resolve to a different ref than the one it names.
    if let Some(repository_ref) = authority
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| repository_ref.name.to_string() == reference)
    {
        let name = short_ref_name(&repository_ref.name);
        return Ok((resolve(&repository_ref.target)?, Some(name)));
    }

    // Then the short alias, and only when exactly one ref answers to it. Two
    // refs sharing an alias is a question this route cannot answer, and picking
    // either one silently serves bytes from a ref the caller did not ask for.
    let mut by_alias = authority
        .ref_state
        .refs
        .iter()
        .filter(|repository_ref| short_ref_name(&repository_ref.name) == reference);
    if let Some(repository_ref) = by_alias.next() {
        if by_alias.next().is_some() {
            let names: Vec<String> = authority
                .ref_state
                .refs
                .iter()
                .filter(|candidate| short_ref_name(&candidate.name) == reference)
                .map(|candidate| candidate.name.to_string())
                .collect();
            return Err(RepoBlobError::new(
                StatusCode::CONFLICT,
                RepoBlobRefusal::AmbiguousRef,
                format!(
                    "repository {repo_id} holds more than one ref answering to {reference}: {}; \
                     name the one you mean in full",
                    names.join(", ")
                ),
            ));
        }
        let name = short_ref_name(&repository_ref.name);
        return Ok((resolve(&repository_ref.target)?, Some(name)));
    }

    // Not a ref this repository carries. A canonical change id is the only
    // other thing this route accepts, and its own refusal names the field.
    let change_id = parse_semantic_change_id("ref", reference).map_err(|(_, message)| {
        RepoBlobError::new(
            StatusCode::NOT_FOUND,
            RepoBlobRefusal::UnknownRef,
            format!("repository {repo_id} carries no ref named {reference}, and {message}"),
        )
    })?;
    Ok((change_id, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(bytes: &[u8]) -> kin_model::Hash256 {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        kin_model::Hash256::from_bytes(digest)
    }

    fn tree_with(path: &str, entry: kin_model::TreeEntry) -> kin_model::ResolvedTree {
        kin_model::ResolvedTree::from_artifacts([kin_model::ResolvedArtifact::new(
            kin_model::ArtifactId::new(),
            RepoPath::from_utf8(path).unwrap(),
            entry,
        )])
        .unwrap()
    }

    fn loader_returning(
        answer: Result<Option<Vec<u8>>, (StatusCode, String)>,
    ) -> RepositorySourceBlobLoader {
        Box::new(move |_path, _digest, _remaining| answer.clone())
    }

    #[test]
    fn a_verified_blob_carries_the_digest_its_bytes_were_checked_against() {
        let bytes = b"fn main() {}\n".to_vec();
        let hash = hash_of(&bytes);
        let tree = tree_with("src/main.rs", kin_model::TreeEntry::blob(hash, false));
        let path = RepoPath::from_utf8("src/main.rs").unwrap();
        let mut load = loader_returning(Ok(Some(bytes.clone())));

        let blob = read_verified_blob(&tree, &path, "main", &mut load).unwrap();

        assert_eq!(blob.bytes, bytes);
        assert_eq!(blob.digest, hash);
    }

    #[test]
    fn every_refusal_kind_has_a_distinct_stable_spelling() {
        // A caller branches on these strings, so a collision or a rename is a
        // silent behaviour change on the other side of the wire.
        let kinds = [
            RepoBlobRefusal::BadRequest,
            RepoBlobRefusal::UnknownRepository,
            RepoBlobRefusal::RepositoryUnreadable,
            RepoBlobRefusal::UnknownRef,
            RepoBlobRefusal::AmbiguousRef,
            RepoBlobRefusal::PathNotFound,
            RepoBlobRefusal::SourceUnavailable,
        ];
        let spellings: std::collections::BTreeSet<&str> =
            kinds.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(spellings.len(), kinds.len(), "two kinds share a spelling");
        assert_eq!(
            RepoBlobRefusal::PathNotFound.as_str(),
            "path-not-found",
            "the one kind a caller may read as an absent side is pinned by name"
        );
        assert_eq!(RepoBlobRefusal::UnknownRef.as_str(), "unknown-ref");
        assert_eq!(RepoBlobRefusal::AmbiguousRef.as_str(), "ambiguous-ref");
        assert!(
            spellings
                .iter()
                .all(|spelling| HeaderValue::from_str(spelling).is_ok()),
            "every spelling has to survive the header it travels in"
        );
    }

    #[test]
    fn bytes_that_do_not_match_the_tree_digest_are_refused_rather_than_served() {
        // The falsification target. Delete the digest comparison in
        // `read_verified_blob` and this is the assertion that goes red: the
        // route would answer 200 with bytes the tree never recorded, under a
        // `content_sha256` naming the digest it did record.
        let recorded = b"fn main() {}\n".to_vec();
        let hash = hash_of(&recorded);
        let tree = tree_with("src/main.rs", kin_model::TreeEntry::blob(hash, false));
        let path = RepoPath::from_utf8("src/main.rs").unwrap();
        let mut load = loader_returning(Ok(Some(b"corrupt source bytes".to_vec())));

        let refusal = read_verified_blob(&tree, &path, "main", &mut load).unwrap_err();
        let (status, message, kind) = (refusal.status, refusal.message, refusal.kind);

        assert_eq!(status, StatusCode::FAILED_DEPENDENCY);
        assert_eq!(kind, RepoBlobRefusal::SourceUnavailable);
        assert!(
            message.contains("digest mismatch"),
            "the refusal must name the mismatch: {message}"
        );
        assert!(
            message.contains("src/main.rs") && message.contains("main"),
            "the refusal must name the path and the ref: {message}"
        );
    }

    #[test]
    fn a_path_the_ref_does_not_carry_is_a_refusal_naming_the_ref() {
        let bytes = b"fn main() {}\n".to_vec();
        let tree = tree_with(
            "src/main.rs",
            kin_model::TreeEntry::blob(hash_of(&bytes), false),
        );
        let path = RepoPath::from_utf8("src/absent.rs").unwrap();
        let mut load = loader_returning(Ok(Some(bytes)));

        let refusal = read_verified_blob(&tree, &path, "main", &mut load).unwrap_err();
        let (status, message, kind) = (refusal.status, refusal.message, refusal.kind);

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            kind,
            RepoBlobRefusal::PathNotFound,
            "an absent path is the one refusal a caller may read as an absent side"
        );
        assert!(
            message.contains("src/absent.rs") && message.contains("main"),
            "the refusal must name the path and the ref it was not in: {message}"
        );
    }

    #[test]
    fn bytes_the_store_never_persisted_are_refused_without_a_fallback() {
        let bytes = b"fn main() {}\n".to_vec();
        let tree = tree_with(
            "src/main.rs",
            kin_model::TreeEntry::blob(hash_of(&bytes), false),
        );
        let path = RepoPath::from_utf8("src/main.rs").unwrap();
        let mut load = loader_returning(Ok(None));

        let refusal = read_verified_blob(&tree, &path, "main", &mut load).unwrap_err();
        let (status, message, kind) = (refusal.status, refusal.message, refusal.kind);

        assert_eq!(status, StatusCode::FAILED_DEPENDENCY);
        assert_eq!(kind, RepoBlobRefusal::SourceUnavailable);
        assert!(
            message.contains("no fallback was attempted"),
            "an absent body must say so rather than leave the reader guessing: {message}"
        );
    }

    #[test]
    fn the_store_refusal_is_passed_through_rather_than_reclassified() {
        // A control for the test above. Both arms end in an error, and only
        // this one proves the route does not flatten every store outcome into
        // one shape.
        let bytes = b"fn main() {}\n".to_vec();
        let tree = tree_with(
            "src/main.rs",
            kin_model::TreeEntry::blob(hash_of(&bytes), false),
        );
        let path = RepoPath::from_utf8("src/main.rs").unwrap();
        let mut load = loader_returning(Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "immutable backend source storage is not configured".to_string(),
        )));

        let refusal = read_verified_blob(&tree, &path, "main", &mut load).unwrap_err();
        let (status, message, kind) = (refusal.status, refusal.message, refusal.kind);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(kind, RepoBlobRefusal::SourceUnavailable);
        assert!(message.contains("immutable backend source storage"));
    }

    #[test]
    fn a_body_over_the_route_ceiling_is_refused_and_names_its_size() {
        let bytes = vec![b'x'; (MAX_REPO_BLOB_BYTES + 1) as usize];
        let tree = tree_with(
            "src/huge.rs",
            kin_model::TreeEntry::blob(hash_of(&bytes), false),
        );
        let path = RepoPath::from_utf8("src/huge.rs").unwrap();
        let mut load = loader_returning(Ok(Some(bytes)));

        let refusal = read_verified_blob(&tree, &path, "main", &mut load).unwrap_err();
        let (status, message, kind) = (refusal.status, refusal.message, refusal.kind);

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(kind, RepoBlobRefusal::SourceUnavailable);
        assert!(
            message.contains(&MAX_REPO_BLOB_BYTES.to_string()),
            "the refusal must name the ceiling it hit: {message}"
        );
    }
}
