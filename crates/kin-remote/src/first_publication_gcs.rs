// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Validated object-store destination for [`crate::first_publication`].
//!
//! A first publication into a hosted bucket already works: `kin_db::GcsBackend`
//! implements `StorageBackend`, and publishing a complete authority through one
//! and reopening it through a second handle is exercised elsewhere in this
//! workspace. What did not exist is the step before that, turning an
//! operation-bound `{bucket, prefix}` into a backend, and every way that step
//! can go quietly wrong. This module is that step and nothing else.
//!
//! ## What is refused, and why each refusal is not cosmetic
//!
//! * A **bucket** outside the object-store naming grammar builds a request that
//!   is nonsense rather than one that fails cleanly. Google's full naming policy
//!   stays Google's to enforce; refused here is only what would corrupt the
//!   request or the key.
//! * A **prefix** that is not already in normal form names a different object
//!   than it appears to. `object_store` drops empty path segments while
//!   building a key, so `a//b`, `/a/b/` and `a/b` are one object, while the
//!   destination scope this module renders keeps whatever was written. The
//!   receipt would then name a location that is not the key. Refuse rather than
//!   normalize, so the operator sees which value to fix.
//! * The **artifact identifier budget** is checked before anything is written.
//!   The hosted control plane stores that identifier as bounded text, and it is
//!   composed from the destination scope after a publication has already
//!   committed, so an over-long prefix otherwise produces a publication that
//!   succeeded and a receipt that cannot be composed. The check here uses the
//!   widest generation a `u64` can print, because a bucket assigns generations
//!   itself and the value is not known until after the write.
//!
//! ## What the write is fenced by, stated exactly
//!
//! The object key is derived from the reserved repository id, and the
//! publication primitive refuses a source that does not own that id. The install
//! is create-if-absent, so a second first publication against the same key does
//! not overwrite the first. Those are **generation-conditional** writes: the
//! store compares object generations and nothing else.
//!
//! They are **not lease-conditional**. A hosted operation's fencing token and
//! holder identity are carried alongside a publication and enforced by the
//! control plane, never by the object store, which has no conditional-on-lease
//! primitive and is handed no token. Nothing in this module makes a lease
//! stronger than it is.
//!
//! ## Where the endpoint comes from
//!
//! It is passed in, already resolved, as trusted operator input. This module
//! reads no environment variable and holds no precedence rule, so the one place
//! that decides between a production endpoint and an emulator stays the one
//! place. Production is ordinary application default credentials with no
//! override at all.
//!
//! Opening a destination therefore names its [`GcsEndpointClass`], and
//! [`OpenedGcsDestination`] carries that class back out with the backend. The
//! class is an input, not something inferred from a handle afterwards, so an
//! emulator cannot be recorded as production by a caller that forgot to ask.

/// Longest artifact identifier a hosted control plane stores as bounded text.
///
/// Restated here rather than imported because the composing code lives above
/// this crate in the dependency graph. The caller passes its own identifier
/// prefix into [`GcsDestination::check_artifact_id_budget`], so the two halves
/// of the format meet at one call site.
pub const ARTIFACT_ID_MAX_BYTES: usize = 256;

/// Shortest bucket name the object-store naming grammar accepts.
const MIN_BUCKET_BYTES: usize = 3;

/// Longest single-label bucket name the object-store naming grammar accepts.
const MAX_BUCKET_BYTES: usize = 63;

/// Longest prefix segment accepted here.
///
/// The store's own key limit is far higher; this bounds one segment so a
/// pathological prefix is refused by a rule an operator can read rather than by
/// an artifact-identifier budget failure that names the wrong cause.
const MAX_PREFIX_SEGMENT_BYTES: usize = 200;

/// Every way a hosted object-store destination is refused before it exists.
///
/// One variant per rule rather than one opaque string, so a caller can tell a
/// misconfigured bucket from a misconfigured prefix without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GcsDestinationError {
    #[error("hosted object-store destination refused: bucket {bucket:?} {reason}")]
    Bucket { bucket: String, reason: String },
    #[error("hosted object-store destination refused: prefix {prefix:?} {reason}")]
    Prefix { prefix: String, reason: String },
    #[error(
        "hosted object-store destination refused: the longest artifact identifier this \
         destination can produce is {length} bytes, over the {ARTIFACT_ID_MAX_BYTES} a hosted \
         record accepts; shorten the bucket or prefix. Longest identifier: {longest:?}"
    )]
    ArtifactIdBudget { length: usize, longest: String },
    #[error("hosted object-store endpoint refused: {source_name} is {value:?} but {reason}")]
    Endpoint {
        source_name: String,
        value: String,
        reason: String,
    },
    #[error("hosted object-store destination could not be opened: {0}")]
    Backend(String),
}

/// A validated hosted object-store destination.
///
/// Construction is the validation. A value of this type has a bucket and a
/// prefix that name exactly one object per repository, and that name the same
/// object a reader configured with the same pair will look for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsDestination {
    bucket: String,
    prefix: String,
}

impl GcsDestination {
    /// Validate a bucket and prefix, or refuse and name which one failed.
    ///
    /// An empty prefix is accepted, because publishing at the root of a bucket
    /// is a real configuration and is what an unset prefix means.
    pub fn new(bucket: &str, prefix: &str) -> Result<Self, GcsDestinationError> {
        validate_bucket(bucket)?;
        validate_prefix(prefix)?;
        Ok(Self {
            bucket: bucket.to_owned(),
            prefix: prefix.to_owned(),
        })
    }

    /// The validated bucket.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The validated prefix, empty when publishing at the bucket root.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The destination scope, as it appears inside an artifact identifier.
    pub fn scope(&self) -> String {
        format!("gcs:{}/{}", self.bucket, self.prefix)
    }

    /// The object key one repository's authority occupies under this
    /// destination.
    ///
    /// This mirrors the backend's own key composition rather than owning it. A
    /// drift between the two would make every message here name the wrong
    /// object, so a test puts an object at the key this returns and asks a real
    /// backend to find it, which fails if either side has moved.
    pub fn snapshot_object_key(&self, repository_id: &str) -> String {
        if self.prefix.is_empty() {
            format!("{repository_id}/graph.kndb")
        } else {
            format!("{}/{repository_id}/graph.kndb", self.prefix)
        }
    }

    /// The longest artifact identifier this destination can ever compose.
    ///
    /// `artifact_id_prefix` is the caller's own schema literal, and the rest of
    /// the format is `:<scope>/<repository id>@<generation>`. The generation is
    /// the widest a `u64` can print, because a bucket assigns generations itself
    /// and a first publication does not get to pick a small one.
    pub fn longest_artifact_id(&self, artifact_id_prefix: &str, repository_id: &str) -> String {
        format!(
            "{artifact_id_prefix}:{}/{repository_id}@{}",
            self.scope(),
            u64::MAX
        )
    }

    /// Refuse a destination whose artifact identifier cannot fit a hosted
    /// record, before anything is written rather than after.
    pub fn check_artifact_id_budget(
        &self,
        artifact_id_prefix: &str,
        repository_id: &str,
    ) -> Result<(), GcsDestinationError> {
        let longest = self.longest_artifact_id(artifact_id_prefix, repository_id);
        if longest.len() > ARTIFACT_ID_MAX_BYTES {
            return Err(GcsDestinationError::ArtifactIdBudget {
                length: longest.len(),
                longest,
            });
        }
        Ok(())
    }
}

/// Which service a destination was opened against.
///
/// Carried rather than inferred. A backend handle cannot be asked afterwards
/// whether it is talking to production or to an emulator, so the answer travels
/// with the value that built it and reaches whatever record the caller writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcsEndpointClass {
    /// The real service, reached with application default credentials.
    ProductionAdc,
    /// A local or test endpoint standing in for the real service.
    Emulator,
}

impl GcsEndpointClass {
    /// A stable name for a record, never a display string that may be reworded.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProductionAdc => "production-adc",
            Self::Emulator => "emulator",
        }
    }
}

/// Where a destination's requests go.
///
/// The caller names this. Resolving an operator's configuration into it is the
/// caller's job and deliberately not this module's, so the precedence between
/// whatever variables a deployment uses stays defined in exactly one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcsEndpoint {
    /// The real service with application default credentials and no override.
    ProductionAdc,
    /// A validated override standing in for the real service.
    Emulator(GcsEndpointOverride),
}

impl GcsEndpoint {
    /// Which service this endpoint names.
    pub fn class(&self) -> GcsEndpointClass {
        match self {
            Self::ProductionAdc => GcsEndpointClass::ProductionAdc,
            Self::Emulator(_) => GcsEndpointClass::Emulator,
        }
    }

    /// The override's normalized base URL, or `None` for production.
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::ProductionAdc => None,
            Self::Emulator(override_) => Some(override_.url()),
        }
    }
}

/// A validated base URL for an endpoint override.
///
/// Validation here is about shape, not about which variable supplied the value.
/// It matters because a client builder accepts a base URL with a path and then
/// silently prepends it to every key, which would put a publication somewhere no
/// reader looks while every message still named the bucket the operator expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsEndpointOverride {
    url: String,
    source_name: String,
}

impl GcsEndpointOverride {
    /// Parse and normalize one endpoint value.
    ///
    /// Accepts `http://host:port`, `https://host:port` and a bare `host:port`,
    /// defaulting a missing scheme to `http` and a missing port to the scheme's
    /// own. `source_name` names where the value came from, so every refusal says
    /// what to fix rather than only that something was wrong.
    pub fn parse(value: &str, source_name: &str) -> Result<Self, GcsDestinationError> {
        let refuse = |reason: &str| GcsDestinationError::Endpoint {
            source_name: source_name.to_owned(),
            value: value.to_owned(),
            reason: reason.to_owned(),
        };

        let (scheme, rest) = match value.split_once("://") {
            None => ("http", value),
            Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
                "http" => ("http", rest),
                "https" => ("https", rest),
                other => {
                    return Err(refuse(&format!(
                        "its scheme {other:?} is not supported (expected http or https)"
                    )))
                }
            },
        };

        // A base URL is an origin. A path past the authority would be prepended
        // to every key by the client, so refuse it here where the value can
        // still be named.
        let authority = match rest.split_once('/') {
            None => rest,
            Some((authority, "")) => authority,
            Some((_, path)) => {
                return Err(refuse(&format!(
                    "it carries a path (/{path}); an endpoint must be scheme, host and port only"
                )))
            }
        };

        if authority.is_empty() {
            return Err(refuse("it has no host"));
        }

        let (host, port) = match authority.rsplit_once(':') {
            None => (authority, if scheme == "https" { 443_u16 } else { 80 }),
            Some((host, port_text)) => {
                let port = port_text
                    .parse::<u16>()
                    .map_err(|_| refuse(&format!("its port {port_text:?} is not in 1..=65535")))?;
                if port == 0 {
                    return Err(refuse("its port is 0, which cannot be connected to"));
                }
                (host, port)
            }
        };

        if host.is_empty() {
            return Err(refuse("it has no host"));
        }

        Ok(Self {
            url: format!("{scheme}://{host}:{port}"),
            source_name: source_name.to_owned(),
        })
    }

    /// The normalized base URL: scheme, host and port, with no trailing slash.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Where the value came from, for a record or a message.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }
}

/// A bucket name that would build a nonsense request is refused.
///
/// This is not a reimplementation of the provider's naming policy, which the
/// provider enforces and which changes without this crate hearing about it. It
/// refuses the shapes that would corrupt a URL or an object key while still
/// looking like a configured destination.
fn validate_bucket(bucket: &str) -> Result<(), GcsDestinationError> {
    let refuse = |reason: &str| GcsDestinationError::Bucket {
        bucket: bucket.to_owned(),
        reason: reason.to_owned(),
    };

    if bucket.len() < MIN_BUCKET_BYTES || bucket.len() > MAX_BUCKET_BYTES {
        return Err(refuse(&format!(
            "is {} bytes, outside the {MIN_BUCKET_BYTES} to {MAX_BUCKET_BYTES} a bucket name may be",
            bucket.len()
        )));
    }
    if let Some(bad) = bucket
        .chars()
        .find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
    {
        return Err(refuse(&format!(
            "carries {bad:?}; a bucket name is lowercase letters, digits, and the characters . _ -"
        )));
    }
    let first_last_ok = |c: Option<char>| matches!(c, Some('a'..='z' | '0'..='9'));
    if !first_last_ok(bucket.chars().next()) || !first_last_ok(bucket.chars().last()) {
        return Err(refuse(
            "must begin and end with a lowercase letter or a digit",
        ));
    }
    if bucket.contains("..") {
        return Err(refuse("carries an empty label (\"..\")"));
    }
    Ok(())
}

/// A prefix that is not already in normal form is refused rather than repaired.
///
/// The alphabet is deliberately narrower than what the store would accept. A
/// hosted prefix is fleet configuration, not user input, and a narrow alphabet
/// is what makes "the key equals the prefix" provable rather than argued: every
/// character accepted here is one the store's path encoder passes through
/// unchanged, and the whole-segment forms it would rewrite are refused by name.
fn validate_prefix(prefix: &str) -> Result<(), GcsDestinationError> {
    let refuse = |reason: &str| GcsDestinationError::Prefix {
        prefix: prefix.to_owned(),
        reason: reason.to_owned(),
    };

    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.starts_with('/') {
        return Err(refuse(
            "begins with a separator, which the store would drop",
        ));
    }
    if prefix.ends_with('/') {
        return Err(refuse("ends with a separator, which the store would drop"));
    }
    for segment in prefix.split('/') {
        if segment.is_empty() {
            return Err(refuse(
                "carries an empty segment, which the store would drop, so two different \
                 prefixes would name one object",
            ));
        }
        if segment.len() > MAX_PREFIX_SEGMENT_BYTES {
            return Err(refuse(&format!(
                "carries a {}-byte segment, over the {MAX_PREFIX_SEGMENT_BYTES} accepted here",
                segment.len()
            )));
        }
        if segment == "." || segment == ".." {
            return Err(refuse(&format!(
                "carries the segment {segment:?}, which the store rewrites rather than stores"
            )));
        }
        if let Some(bad) = segment
            .chars()
            .find(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
        {
            return Err(refuse(&format!(
                "carries {bad:?}; a prefix segment is letters, digits, and the characters . _ -"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "gcs")]
mod backend {
    use std::sync::Arc;

    use kin_db::StorageBackend;
    use object_store::gcp::GoogleCloudStorageBuilder;
    use object_store::ObjectStore;

    use super::{GcsDestination, GcsDestinationError, GcsEndpoint, GcsEndpointClass};

    /// A destination that has been opened, with the class it was opened against.
    ///
    /// `#[must_use]` on purpose. Dropping this and keeping only the backend
    /// would throw away the one fact that distinguishes an emulator run from a
    /// production one, which is exactly the confusion the class exists to stop.
    #[must_use]
    pub struct OpenedGcsDestination {
        /// The backend a publication is handed.
        pub backend: Arc<dyn StorageBackend>,
        /// Which service it talks to.
        pub endpoint_class: GcsEndpointClass,
        /// The override's base URL, present only for an emulator.
        pub endpoint_url: Option<String>,
    }

    impl std::fmt::Debug for OpenedGcsDestination {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("OpenedGcsDestination")
                .field("endpoint_class", &self.endpoint_class)
                .field("endpoint_url", &self.endpoint_url)
                .finish_non_exhaustive()
        }
    }

    impl GcsDestination {
        /// Open this destination against `endpoint`.
        ///
        /// One construction path for both classes: the client is always built
        /// from the same builder, and an override adds exactly two calls to it.
        /// An override also skips request signing, because an emulator has no
        /// credentials to sign with and because an unsigned request that reaches
        /// the real service is rejected by it rather than quietly authorized by
        /// whatever credentials the host happens to carry.
        pub fn open(
            &self,
            endpoint: &GcsEndpoint,
        ) -> Result<OpenedGcsDestination, GcsDestinationError> {
            let mut builder = GoogleCloudStorageBuilder::new().with_bucket_name(&self.bucket);
            if let GcsEndpoint::Emulator(override_) = endpoint {
                builder = builder
                    .with_base_url(override_.url())
                    .with_skip_signature(true);
            }
            let store = builder.build().map_err(|error| {
                GcsDestinationError::Backend(match endpoint.url() {
                    Some(url) => format!("bucket {} through {url}: {error}", self.bucket),
                    None => format!("bucket {}: {error}", self.bucket),
                })
            })?;
            Ok(self.opened(Box::new(store), endpoint.class(), endpoint.url()))
        }

        /// Open this destination over a store the caller already holds.
        ///
        /// The class is still named rather than guessed, for the same reason it
        /// is named in [`GcsDestination::open`].
        pub fn open_with_store(
            &self,
            store: Box<dyn ObjectStore>,
            endpoint_class: GcsEndpointClass,
            endpoint_url: Option<&str>,
        ) -> OpenedGcsDestination {
            self.opened(store, endpoint_class, endpoint_url)
        }

        fn opened(
            &self,
            store: Box<dyn ObjectStore>,
            endpoint_class: GcsEndpointClass,
            endpoint_url: Option<&str>,
        ) -> OpenedGcsDestination {
            OpenedGcsDestination {
                backend: Arc::new(kin_db::GcsBackend::from_store(store, self.prefix.clone())),
                endpoint_class,
                endpoint_url: endpoint_url.map(ToOwned::to_owned),
            }
        }
    }
}

#[cfg(feature = "gcs")]
pub use backend::OpenedGcsDestination;

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "kin.first-publication.v1";
    const REPOSITORY: &str = "9f1c2e04-3b7a-4d21-9c55-0ab61d7e8f30";

    fn destination(bucket: &str, prefix: &str) -> GcsDestination {
        GcsDestination::new(bucket, prefix).expect("fixture destination must validate")
    }

    #[test]
    fn an_ordinary_bucket_and_prefix_validate() {
        let destination = destination("kin-hosted-prod", "publications/v1");
        assert_eq!(destination.bucket(), "kin-hosted-prod");
        assert_eq!(destination.prefix(), "publications/v1");
        assert_eq!(destination.scope(), "gcs:kin-hosted-prod/publications/v1");
    }

    #[test]
    fn an_empty_prefix_publishes_at_the_bucket_root() {
        let destination = destination("kin-hosted-prod", "");
        assert_eq!(
            destination.snapshot_object_key(REPOSITORY),
            format!("{REPOSITORY}/graph.kndb")
        );
    }

    #[test]
    fn a_prefixed_destination_names_the_key_under_its_prefix() {
        let destination = destination("kin-hosted-prod", "publications/v1");
        assert_eq!(
            destination.snapshot_object_key(REPOSITORY),
            format!("publications/v1/{REPOSITORY}/graph.kndb")
        );
    }

    #[test]
    fn a_bucket_outside_the_grammar_is_refused_by_name() {
        for (bucket, expected) in [
            ("ab", "outside the 3 to 63"),
            ("Kin-Hosted", "carries 'K'"),
            ("kin/hosted-prod", "carries '/'"),
            ("-kin-hosted", "must begin and end"),
            ("kin-hosted-", "must begin and end"),
            ("kin..hosted", "carries an empty label"),
        ] {
            let Err(error) = GcsDestination::new(bucket, "publications") else {
                panic!("bucket {bucket:?} must be refused");
            };
            assert!(
                error.to_string().contains(expected),
                "bucket {bucket:?} refused with {error}, expected a message containing {expected:?}"
            );
        }
    }

    #[test]
    fn a_bucket_at_the_grammar_boundary_is_accepted() {
        // The positive control for the length rule. Without it, a refusal that
        // rejected every bucket would still satisfy the test above.
        assert!(GcsDestination::new("abc", "publications").is_ok());
        let longest = "a".repeat(MAX_BUCKET_BYTES);
        assert!(GcsDestination::new(&longest, "publications").is_ok());
        let overlong = "a".repeat(MAX_BUCKET_BYTES + 1);
        assert!(GcsDestination::new(&overlong, "publications").is_err());
    }

    #[test]
    fn a_prefix_the_store_would_rewrite_is_refused_rather_than_normalized() {
        // Each of these names the same object as "a/b" once the store has
        // dropped what it drops, so accepting them would let two manifests
        // publish to one key while every message named a different location.
        for (prefix, expected) in [
            ("/a/b", "begins with a separator"),
            ("a/b/", "ends with a separator"),
            ("a//b", "carries an empty segment"),
            ("a/./b", "carries the segment \".\""),
            ("a/../b", "carries the segment \"..\""),
            ("a/b%c", "carries '%'"),
            ("a/b c", "carries ' '"),
        ] {
            let Err(error) = GcsDestination::new("kin-hosted-prod", prefix) else {
                panic!("prefix {prefix:?} must be refused");
            };
            assert!(
                error.to_string().contains(expected),
                "prefix {prefix:?} refused with {error}, expected a message containing {expected:?}"
            );
        }
    }

    #[test]
    fn a_prefix_already_in_normal_form_is_accepted() {
        // The positive control for the rule above.
        for prefix in ["", "a", "a/b", "a/b/c", "pub-1_2.v3/tenant-a"] {
            assert!(
                GcsDestination::new("kin-hosted-prod", prefix).is_ok(),
                "prefix {prefix:?} is in normal form and must be accepted"
            );
        }
    }

    #[test]
    fn an_oversized_prefix_segment_is_refused_before_the_artifact_budget() {
        let segment = "a".repeat(MAX_PREFIX_SEGMENT_BYTES + 1);
        let error = GcsDestination::new("kin-hosted-prod", &segment)
            .expect_err("an oversized segment must be refused");
        assert!(
            error.to_string().contains("over the 200 accepted here"),
            "{error}"
        );
        let accepted = "a".repeat(MAX_PREFIX_SEGMENT_BYTES);
        assert!(GcsDestination::new("kin-hosted-prod", &accepted).is_ok());
    }

    #[test]
    fn an_ordinary_destination_fits_the_artifact_identifier_budget() {
        destination("kin-hosted-prod", "publications/v1")
            .check_artifact_id_budget(SCHEMA, REPOSITORY)
            .expect("an ordinary destination must fit");
    }

    #[test]
    fn a_long_prefix_is_refused_before_a_publication_rather_than_after_one() {
        let destination = destination("kin-hosted-prod", &"a".repeat(180));
        let error = destination
            .check_artifact_id_budget(SCHEMA, REPOSITORY)
            .expect_err("an over-long destination must be refused");
        assert!(
            error.to_string().contains("over the 256 a hosted record"),
            "{error}"
        );
    }

    #[test]
    fn the_budget_is_measured_against_the_widest_generation_a_bucket_can_assign() {
        // A first publication on a bucket does not get generation 1: the store
        // assigns it. So a destination that fits only while the generation is
        // small is not a destination that fits.
        let prefix_length = ARTIFACT_ID_MAX_BYTES
            - SCHEMA.len()
            - ":gcs:".len()
            - "kin-hosted-prod".len()
            - "/".len()
            - "/".len()
            - REPOSITORY.len()
            - "@".len()
            - 1;
        let destination = destination("kin-hosted-prod", &"a".repeat(prefix_length));
        let with_one_digit = format!("{SCHEMA}:{}/{REPOSITORY}@1", destination.scope());
        assert_eq!(
            with_one_digit.len(),
            ARTIFACT_ID_MAX_BYTES,
            "this destination fits exactly at a one-digit generation"
        );
        let error = destination
            .check_artifact_id_budget(SCHEMA, REPOSITORY)
            .expect_err("a destination that fits only at generation 1 must be refused");
        assert!(
            error.to_string().contains("over the 256 a hosted record"),
            "{error}"
        );
    }

    #[test]
    fn the_longest_artifact_identifier_bounds_every_shorter_one() {
        let destination = destination("kin-hosted-prod", "publications/v1");
        let longest = destination.longest_artifact_id(SCHEMA, REPOSITORY);
        for generation in [1_u64, 42, 1_699_999_999_999_999, u64::MAX] {
            let composed = format!("{SCHEMA}:{}/{REPOSITORY}@{generation}", destination.scope());
            assert!(
                composed.len() <= longest.len(),
                "generation {generation} composed {} bytes, over the {} the bound claims",
                composed.len(),
                longest.len()
            );
        }
    }

    #[test]
    fn an_endpoint_override_is_normalized_to_an_origin() {
        for (value, expected) in [
            ("http://localhost:4443", "http://localhost:4443"),
            ("localhost:4443", "http://localhost:4443"),
            (
                "https://storage.example.test",
                "https://storage.example.test:443",
            ),
            (
                "http://storage.example.test",
                "http://storage.example.test:80",
            ),
            ("HTTP://localhost:4443", "http://localhost:4443"),
            ("http://localhost:4443/", "http://localhost:4443"),
        ] {
            let parsed = GcsEndpointOverride::parse(value, "OPERATOR_ENDPOINT")
                .unwrap_or_else(|error| panic!("{value:?} must parse: {error}"));
            assert_eq!(parsed.url(), expected, "for {value:?}");
            assert_eq!(parsed.source_name(), "OPERATOR_ENDPOINT");
        }
    }

    #[test]
    fn an_endpoint_that_would_move_every_key_is_refused() {
        for (value, expected) in [
            (
                "http://localhost:4443/storage",
                "it carries a path (/storage)",
            ),
            ("ftp://localhost:4443", "is not supported"),
            ("http://", "it has no host"),
            ("http://localhost:0", "its port is 0"),
            ("http://localhost:70000", "is not in 1..=65535"),
            ("http://:4443", "it has no host"),
        ] {
            let Err(error) = GcsEndpointOverride::parse(value, "OPERATOR_ENDPOINT") else {
                panic!("endpoint {value:?} must be refused");
            };
            assert!(
                error.to_string().contains(expected),
                "endpoint {value:?} refused with {error}, expected {expected:?}"
            );
            assert!(
                error.to_string().contains("OPERATOR_ENDPOINT"),
                "every endpoint refusal must name where the value came from: {error}"
            );
        }
    }

    #[test]
    fn the_endpoint_class_is_carried_rather_than_inferred() {
        assert_eq!(
            GcsEndpoint::ProductionAdc.class(),
            GcsEndpointClass::ProductionAdc
        );
        assert_eq!(GcsEndpoint::ProductionAdc.url(), None);
        assert_eq!(GcsEndpointClass::ProductionAdc.as_str(), "production-adc");

        let emulator = GcsEndpoint::Emulator(
            GcsEndpointOverride::parse("localhost:4443", "OPERATOR_ENDPOINT").expect("parses"),
        );
        assert_eq!(emulator.class(), GcsEndpointClass::Emulator);
        assert_eq!(emulator.url(), Some("http://localhost:4443"));
        assert_eq!(GcsEndpointClass::Emulator.as_str(), "emulator");
    }
}

#[cfg(all(test, feature = "gcs"))]
mod gcs_tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use futures_util::stream::BoxStream;
    use object_store::memory::InMemory;
    use object_store::path::Path as ObjectPath;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
        ObjectStoreExt, PutMultipartOptions, PutOptions, PutPayload, PutResult,
        Result as ObjectStoreResult,
    };

    use super::{GcsDestination, GcsEndpointClass};

    const BUCKET: &str = "kin-hosted-prod";
    const PREFIX: &str = "publications/v1";
    const REPOSITORY: &str = "9f1c2e04-3b7a-4d21-9c55-0ab61d7e8f30";
    const EMULATOR_URL: &str = "http://localhost:4443";

    /// Where the double starts assigning generations.
    ///
    /// Not 1. A bucket assigns generations itself and they are large, which is
    /// the whole reason the artifact-identifier budget is measured against the
    /// widest a `u64` can print rather than against the 1 a local file backend
    /// hands out.
    const FIRST_GENERATION: u64 = 1_699_000_000_000_000;

    #[derive(Debug)]
    struct GenerationState {
        next: u64,
        assigned: HashMap<String, u64>,
    }

    impl Default for GenerationState {
        fn default() -> Self {
            Self {
                next: FIRST_GENERATION,
                assigned: HashMap::new(),
            }
        }
    }

    /// An object store that assigns numeric generations the way a bucket does.
    ///
    /// The ordinary in-memory store has ETags and no generations, and the
    /// backend under test refuses a missing generation rather than falling back
    /// to an ETag, so the ordinary store cannot stand in for a bucket at all.
    /// One of the tests below asserts exactly that refusal, so the reason this
    /// double exists is itself checked rather than remembered.
    ///
    /// It deliberately mirrors the fixture the daemon's own object-store tests
    /// use. Collapsing the two into one shared fixture is a follow-up, and it
    /// cannot happen from here: the daemon depends on the CLI, so nothing below
    /// the CLI can borrow from it.
    #[derive(Debug, Default)]
    struct GenerationStampedStore {
        inner: InMemory,
        state: Mutex<GenerationState>,
    }

    impl GenerationStampedStore {
        fn assign(&self, location: &ObjectPath) -> u64 {
            let mut state = self.state.lock().expect("generation state");
            let generation = state.next;
            state.next += 1;
            state.assigned.insert(location.to_string(), generation);
            generation
        }

        fn assigned(&self, location: &ObjectPath) -> Option<u64> {
            self.state
                .lock()
                .expect("generation state")
                .assigned
                .get(location.as_ref())
                .copied()
        }
    }

    impl std::fmt::Display for GenerationStampedStore {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("GenerationStampedStore")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for GenerationStampedStore {
        async fn put_opts(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            opts: PutOptions,
        ) -> ObjectStoreResult<PutResult> {
            let mut result = self.inner.put_opts(location, payload, opts).await?;
            result.version = Some(self.assign(location).to_string());
            Ok(result)
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjectPath,
            opts: PutMultipartOptions,
        ) -> ObjectStoreResult<Box<dyn MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> ObjectStoreResult<GetResult> {
            let mut result = self.inner.get_opts(location, options).await?;
            result.meta.version = self.assigned(location).map(|g| g.to_string());
            Ok(result)
        }

        fn list(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, ObjectStoreResult<ObjectMeta>> {
            self.inner.list(prefix)
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, ObjectStoreResult<ObjectPath>>,
        ) -> BoxStream<'static, ObjectStoreResult<ObjectPath>> {
            self.inner.delete_stream(locations)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> ObjectStoreResult<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> ObjectStoreResult<()> {
            self.inner.copy_opts(from, to, options).await
        }
    }

    fn destination(prefix: &str) -> GcsDestination {
        GcsDestination::new(BUCKET, prefix).expect("fixture destination must validate")
    }

    async fn seed(store: &Arc<GenerationStampedStore>, key: &str) {
        store
            .put(
                &ObjectPath::from(key.to_owned()),
                PutPayload::from_static(b"authority"),
            )
            .await
            .expect("the double must accept a seeded object");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_publication_is_found_at_the_key_this_destination_names() {
        // The key this module composes is a mirror of the backend's own. This
        // is what stops the two from drifting: the object is seeded at the
        // mirrored key and the real backend is asked to find it.
        let raw = Arc::new(GenerationStampedStore::default());
        let destination = destination(PREFIX);
        seed(&raw, &destination.snapshot_object_key(REPOSITORY)).await;

        let opened = destination.open_with_store(
            Box::new(Arc::clone(&raw)),
            GcsEndpointClass::Emulator,
            Some(EMULATOR_URL),
        );
        let cursor = opened
            .backend
            .load_snapshot_cursor(REPOSITORY)
            .expect("the destination must answer")
            .expect("the seeded object is the publication this destination names");
        assert!(
            cursor.backend_generation() >= FIRST_GENERATION,
            "a bucket's generation is large; got {}",
            cursor.backend_generation()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_destination_under_a_different_prefix_sees_nothing() {
        // The negative control for the test above, and the reason the prefix is
        // load-bearing: a publication written under one prefix is invisible to a
        // reader configured with another, however well-formed both are.
        let raw = Arc::new(GenerationStampedStore::default());
        seed(&raw, &destination(PREFIX).snapshot_object_key(REPOSITORY)).await;

        let elsewhere = destination("publications/v2");
        let opened = elsewhere.open_with_store(
            Box::new(Arc::clone(&raw)),
            GcsEndpointClass::Emulator,
            Some(EMULATOR_URL),
        );
        assert!(
            opened
                .backend
                .load_snapshot_cursor(REPOSITORY)
                .expect("the destination must answer")
                .is_none(),
            "a different prefix must not resolve another prefix's publication"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_independently_opened_destination_reads_the_same_publication() {
        // Reader identity is the bucket and prefix pair, not the handle. A
        // reader that never saw the writer must resolve the same object from
        // the same pair, which is what makes a hosted publication readable at
        // all.
        let raw = Arc::new(GenerationStampedStore::default());
        seed(&raw, &destination(PREFIX).snapshot_object_key(REPOSITORY)).await;

        let writer = GcsDestination::new(BUCKET, PREFIX).expect("validates");
        let written = writer
            .open_with_store(
                Box::new(Arc::clone(&raw)),
                GcsEndpointClass::Emulator,
                Some(EMULATOR_URL),
            )
            .backend
            .load_snapshot_cursor(REPOSITORY)
            .expect("the destination must answer")
            .expect("present");

        let reader = GcsDestination::new(BUCKET, PREFIX).expect("validates");
        let read = reader
            .open_with_store(
                Box::new(Arc::clone(&raw)),
                GcsEndpointClass::Emulator,
                Some(EMULATOR_URL),
            )
            .backend
            .load_snapshot_cursor(REPOSITORY)
            .expect("the destination must answer")
            .expect("present");

        assert_eq!(written.backend_generation(), read.backend_generation());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_ordinary_memory_store_cannot_stand_in_for_a_bucket() {
        // The justification for the double above, kept as a test so it goes red
        // rather than stale if the memory store ever starts reporting versions.
        let raw = Arc::new(InMemory::new());
        let destination = destination(PREFIX);
        raw.put(
            &ObjectPath::from(destination.snapshot_object_key(REPOSITORY)),
            PutPayload::from_static(b"authority"),
        )
        .await
        .expect("the memory store must accept a seeded object");

        let opened = destination.open_with_store(
            Box::new(Arc::clone(&raw)),
            GcsEndpointClass::Emulator,
            Some(EMULATOR_URL),
        );
        let error = opened
            .backend
            .load_snapshot_cursor(REPOSITORY)
            .expect_err("a store with no object generations cannot answer a cursor");
        assert!(
            error.to_string().contains("missing object meta.version"),
            "expected a refusal naming the missing generation, got {error}"
        );
    }

    #[test]
    fn the_endpoint_class_travels_with_the_opened_destination() {
        // An emulator must never be recorded as production. The class is an
        // input to opening, so it cannot be lost between building a handle and
        // writing down what the handle talked to.
        let emulator = destination(PREFIX).open_with_store(
            Box::new(InMemory::new()),
            GcsEndpointClass::Emulator,
            Some(EMULATOR_URL),
        );
        assert_eq!(emulator.endpoint_class, GcsEndpointClass::Emulator);
        assert_eq!(emulator.endpoint_url.as_deref(), Some(EMULATOR_URL));

        let production = destination(PREFIX).open_with_store(
            Box::new(InMemory::new()),
            GcsEndpointClass::ProductionAdc,
            None,
        );
        assert_eq!(production.endpoint_class, GcsEndpointClass::ProductionAdc);
        assert_eq!(production.endpoint_url, None);
    }
}
