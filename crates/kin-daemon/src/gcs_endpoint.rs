// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Custom storage endpoint for the GCS backend, so a local stack can run the
//! hosted graph-snapshot path against an emulator instead of real GCP.
//!
//! The daemon's GCS backend is `kin_db::GcsBackend`, which builds an
//! `object_store` `GoogleCloudStorageBuilder` and talks to the real service via
//! Application Default Credentials. `object_store` supports a custom base URL
//! (`with_base_url`), and `GcsBackend::from_store` accepts an already-built
//! store, so the override is expressible here without changing kin-db.
//!
//! Two variables feed it, in precedence order:
//!
//! * `KIN_GCS_ENDPOINT` is Kin's own lever and wins.
//! * `STORAGE_EMULATOR_HOST` is the Google-client convention that kinlab's Node
//!   side already follows, honored so one exported variable points both halves
//!   of a local stack at the same emulator.
//!
//! `STORAGE_EMULATOR_HOST` is deliberately absent from `kin-core`'s env
//! registry: that registry is the `KIN_*` surface by construction, and its
//! `registry_is_well_formed` test rejects any name without the prefix. Both
//! names are in `BEHAVIOR_ENV_VARS` instead, because the daemon bakes this
//! choice in at process start and reporting one without the other would let a
//! health payload show an unset `KIN_GCS_ENDPOINT` while
//! `STORAGE_EMULATOR_HOST` silently supplied the endpoint.
//!
//! ## Nothing here falls back
//!
//! An endpoint that is set but unusable fails the daemon's startup. A malformed
//! value is refused rather than ignored, and a resolved endpoint is probed for
//! reachability before the daemon serves, so an emulator that is not running
//! stops the daemon instead of letting it reach for real GCP or quietly serve
//! from somewhere else. Requests are also unsigned (`with_skip_signature`),
//! which an emulator needs and which means a lever pointed at real GCS by
//! mistake is rejected by Google rather than silently authorized by whatever
//! ambient credentials the host happens to carry.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Kin's own endpoint lever. Registered in `kin-core`'s env registry.
pub const KIN_ENDPOINT_VAR: &str = "KIN_GCS_ENDPOINT";

/// The Google-client convention, honored for parity with the Node side.
pub const EMULATOR_HOST_VAR: &str = "STORAGE_EMULATOR_HOST";

/// How long the startup reachability probe waits for a TCP connection.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A validated storage endpoint override, carrying both the base URL the
/// object store needs and the authority the reachability probe needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    /// Normalized base URL, scheme included and no trailing slash.
    pub url: String,
    /// Host as written, for the probe and for error messages.
    pub host: String,
    /// Port, defaulted from the scheme when the value omitted one.
    pub port: u16,
    /// Which variable supplied the value, so every message names it.
    pub source: &'static str,
}

/// Resolve the endpoint override from the two raw values, without touching the
/// process environment. Pure, so precedence and parsing are unit-testable.
///
/// Returns `Ok(None)` when neither is set, which is the real-GCP path. An empty
/// or whitespace-only value counts as unset, matching how Kin's other read
/// sites treat one. A value that is present but unparseable is an error, never
/// a silent fall-through to real GCP.
pub fn resolve(
    kin_endpoint: Option<&str>,
    emulator_host: Option<&str>,
) -> Result<Option<ResolvedEndpoint>, String> {
    let candidate = [
        (KIN_ENDPOINT_VAR, kin_endpoint),
        (EMULATOR_HOST_VAR, emulator_host),
    ]
    .into_iter()
    .find_map(|(source, raw)| {
        let value = raw.map(str::trim).filter(|v| !v.is_empty())?;
        Some((source, value))
    });

    match candidate {
        None => Ok(None),
        Some((source, value)) => parse_endpoint(value, source)
            .map(Some)
            .map_err(|reason| format!("{source} is set to {value:?} but {reason}")),
    }
}

/// Parse one endpoint value into its normalized form.
///
/// Accepts `http://host:port`, `https://host:port`, and the bare `host:port`
/// that the Google clients also accept for `STORAGE_EMULATOR_HOST`, defaulting
/// a missing scheme to `http` and a missing port to the scheme's own.
fn parse_endpoint(value: &str, source: &'static str) -> Result<ResolvedEndpoint, String> {
    let (scheme, rest) = match value.split_once("://") {
        None => ("http", value),
        Some((scheme, rest)) => {
            let scheme = match scheme.to_ascii_lowercase().as_str() {
                "http" => "http",
                "https" => "https",
                other => {
                    return Err(format!(
                        "its scheme {other:?} is not supported (expected http or https)"
                    ))
                }
            };
            (scheme, rest)
        }
    };

    // A base URL is an origin. Anything past the authority would be silently
    // dropped or silently prepended depending on the caller, so refuse it here
    // where the operator can still see which variable to fix.
    let authority = match rest.split_once('/') {
        None => rest,
        Some((authority, "")) => authority,
        Some((_, path)) => {
            return Err(format!(
                "it carries a path (/{path}); an endpoint must be scheme, host and port only"
            ))
        }
    };

    if authority.is_empty() {
        return Err("it has no host".to_string());
    }

    let (host, port) = match authority.rsplit_once(':') {
        None => (authority, if scheme == "https" { 443_u16 } else { 80_u16 }),
        Some((host, port_text)) => {
            let port = port_text
                .parse::<u16>()
                .map_err(|_| format!("its port {port_text:?} is not a number in 1..=65535"))?;
            if port == 0 {
                return Err("its port is 0, which cannot be connected to".to_string());
            }
            (host, port)
        }
    };

    if host.is_empty() {
        return Err("it has no host".to_string());
    }

    Ok(ResolvedEndpoint {
        url: format!("{scheme}://{host}:{port}"),
        host: host.to_string(),
        port,
        source,
    })
}

impl ResolvedEndpoint {
    /// Refuse to start unless the endpoint accepts a TCP connection.
    ///
    /// This is the loud half of the contract. Without it a stopped emulator is
    /// invisible until the first snapshot read or write, which is long after
    /// the daemon has advertised itself as serving. A TCP connect is the right
    /// granularity for "is it up": it proves something is listening at the
    /// address the store will use, and it deliberately does not claim the
    /// listener speaks the GCS API. What guarantees no real-GCP traffic is the
    /// base URL itself, not this probe.
    ///
    /// `timeout` bounds the whole probe, not each address. A hostname commonly
    /// resolves to several addresses, and the ordinary container shape is one
    /// blackholed IPv6 alongside a working IPv4, so a per-address timeout would
    /// have charged every start the full wait before reaching the address that
    /// works, and a fully dead hostname would have cost the timeout N times over
    /// with nothing naming where the time went.
    pub fn probe_reachable(&self, timeout: Duration) -> Result<(), String> {
        let addrs = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|error| self.refusal(&format!("the host could not be resolved: {error}")))?
            .collect::<Vec<_>>();

        if addrs.is_empty() {
            return Err(self.refusal("the host resolved to no addresses"));
        }

        let deadline = Instant::now() + timeout;
        let mut last_failure = None;
        for addr in &addrs {
            // Never hand connect_timeout a zero or negative duration: it treats
            // that as an error rather than as an instant attempt, which would
            // report "nothing is listening" for an endpoint never actually
            // tried. Stop and report instead, naming the budget.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                last_failure = Some(format!(
                    "gave up after {timeout:?} with {addr} not yet tried"
                ));
                break;
            }
            match TcpStream::connect_timeout(addr, remaining) {
                Ok(_) => return Ok(()),
                Err(error) => last_failure = Some(format!("{addr}: {error}")),
            }
        }

        Err(self.refusal(&format!(
            "nothing is listening there ({})",
            last_failure.unwrap_or_else(|| "connection failed".to_string())
        )))
    }

    /// One shape for every startup refusal, so an operator and a scripted check
    /// both see the same contract whatever went wrong.
    ///
    /// The causes differ in ways that matter for debugging (an unresolvable
    /// host, no addresses, a closed port) and not at all in what happens next,
    /// which is that the daemon stops. Building each message separately meant
    /// only the closed-port one said so, so an emulator container that was
    /// removed rather than stopped refused with a message that never mentioned
    /// refusing, and an acceptance check asserting on that clause could pass or
    /// fail on which kind of outage it happened to produce.
    fn refusal(&self, cause: &str) -> String {
        format!(
            "{} points at {} but {cause}. \
             Start the storage emulator, or unset {} to use real Google Cloud Storage. \
             Refusing to start rather than reaching for a different backend.",
            self.source, self.url, self.source,
        )
    }
}

/// Build a `GcsBackend` whose object store talks to `endpoint` instead of the
/// real service.
///
/// `kin_db::GcsBackend::from_store` is the seam that makes this possible
/// without a kin-db change: it takes an already-built `ObjectStore` and is
/// otherwise identical to `GcsBackend::new`, which builds the same store with
/// no base-URL override.
#[cfg(feature = "gcs")]
pub fn backend_for(
    endpoint: &ResolvedEndpoint,
    bucket: &str,
    prefix: String,
) -> Result<kin_db::GcsBackend, String> {
    use object_store::gcp::GoogleCloudStorageBuilder;

    let store = GoogleCloudStorageBuilder::new()
        .with_bucket_name(bucket)
        .with_base_url(&endpoint.url)
        // An emulator has no credentials to sign with, and unsigned requests to
        // the real service are rejected rather than silently authorized.
        .with_skip_signature(true)
        .build()
        .map_err(|error| {
            format!(
                "failed to create a GCS client for {} (from {}): {error}",
                endpoint.url, endpoint.source
            )
        })?;

    Ok(kin_db::GcsBackend::from_store(Box::new(store), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn neither_variable_set_is_the_real_gcp_path() {
        assert_eq!(resolve(None, None), Ok(None));
    }

    #[test]
    fn empty_and_whitespace_values_count_as_unset() {
        // Matching every other Kin read site: an exported-but-empty variable is
        // not an override, so it must not be parsed and must not error.
        assert_eq!(resolve(Some(""), Some("   ")), Ok(None));
    }

    #[test]
    fn the_emulator_convention_is_honored() {
        let resolved = resolve(None, Some("http://localhost:4443"))
            .expect("parses")
            .expect("resolves");
        assert_eq!(resolved.url, "http://localhost:4443");
        assert_eq!(resolved.host, "localhost");
        assert_eq!(resolved.port, 4443);
        assert_eq!(resolved.source, EMULATOR_HOST_VAR);
    }

    #[test]
    fn kins_own_lever_wins_over_the_convention() {
        // Precedence has to be decided, not incidental: a developer with
        // STORAGE_EMULATOR_HOST exported for the Node side must still be able to
        // point the daemon somewhere else without unexporting it.
        let resolved = resolve(Some("http://kin-emulator:4443"), Some("http://node:9199"))
            .expect("parses")
            .expect("resolves");
        assert_eq!(resolved.url, "http://kin-emulator:4443");
        assert_eq!(resolved.source, KIN_ENDPOINT_VAR);
    }

    #[test]
    fn an_empty_kin_lever_falls_through_to_the_convention() {
        let resolved = resolve(Some("  "), Some("fake-gcs:4443"))
            .expect("parses")
            .expect("resolves");
        assert_eq!(resolved.source, EMULATOR_HOST_VAR);
        assert_eq!(resolved.url, "http://fake-gcs:4443");
    }

    #[test]
    fn a_bare_host_port_gets_the_http_scheme() {
        // The Google clients accept STORAGE_EMULATOR_HOST without a scheme, and
        // `with_base_url` requires one, so the normalization has to happen here.
        let resolved = resolve(None, Some("localhost:4443"))
            .expect("parses")
            .expect("resolves");
        assert_eq!(resolved.url, "http://localhost:4443");
        assert_eq!(resolved.port, 4443);
    }

    #[test]
    fn a_missing_port_defaults_from_the_scheme() {
        let plain = resolve(Some("http://fake-gcs"), None)
            .expect("parses")
            .expect("resolves");
        assert_eq!(plain.url, "http://fake-gcs:80");
        assert_eq!(plain.port, 80);

        let tls = resolve(Some("https://fake-gcs"), None)
            .expect("parses")
            .expect("resolves");
        assert_eq!(tls.url, "https://fake-gcs:443");
        assert_eq!(tls.port, 443);
    }

    #[test]
    fn a_trailing_slash_is_accepted_and_dropped() {
        let resolved = resolve(Some("http://localhost:4443/"), None)
            .expect("parses")
            .expect("resolves");
        assert_eq!(resolved.url, "http://localhost:4443");
    }

    #[test]
    fn https_is_preserved() {
        let resolved = resolve(Some("https://storage.example:8443"), None)
            .expect("parses")
            .expect("resolves");
        assert_eq!(resolved.url, "https://storage.example:8443");
    }

    #[test]
    fn a_malformed_value_is_refused_not_ignored() {
        // The whole point: every one of these used to be a silent fall-through
        // to real Google Cloud Storage, which is the worst possible reading of
        // "the operator asked for an emulator".
        for bad in [
            "ftp://localhost:4443",
            "http://localhost:notaport",
            "http://localhost:0",
            "http://",
            "http://localhost:4443/some/path",
            "http://:4443",
        ] {
            let error = resolve(Some(bad), None)
                .expect_err(&format!("{bad:?} must be refused, not ignored"));
            assert!(
                error.contains(KIN_ENDPOINT_VAR),
                "the refusal must name the variable to fix, got {error:?}"
            );
            assert!(
                error.contains(bad),
                "the refusal must quote the offending value, got {error:?}"
            );
        }
    }

    #[test]
    fn a_malformed_convention_value_names_its_own_variable() {
        let error = resolve(None, Some("ftp://nope:1")).expect_err("must be refused");
        assert!(error.contains(EMULATOR_HOST_VAR), "got {error:?}",);
        assert!(!error.contains(KIN_ENDPOINT_VAR), "got {error:?}");
    }

    #[test]
    fn a_listening_endpoint_probes_reachable() {
        // Positive control for the probe below. Without it, a probe that always
        // returned Err would pass the unreachable test and prove nothing.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let endpoint = ResolvedEndpoint {
            url: format!("http://127.0.0.1:{port}"),
            host: "127.0.0.1".to_string(),
            port,
            source: KIN_ENDPOINT_VAR,
        };
        assert_eq!(endpoint.probe_reachable(Duration::from_secs(2)), Ok(()));
    }

    /// Round-trip a snapshot through a real emulator, proving the redirected
    /// store is not merely constructible but actually serves reads and writes.
    ///
    /// Ignored because it needs a container, and the tests above are the ones
    /// that run everywhere: they cover resolution, refusal and the loud
    /// unreachable failure, none of which need a server.
    ///
    /// This is not where the acceptance is proven. FIR-2668's acceptance runs in
    /// CI, on every push and pull request, as the "GCS emulator endpoint
    /// acceptance" step of `.github/workflows/docker.yml`, which drives
    /// `scripts/test-gcs-emulator-endpoint.sh`: a real daemon in `KIN_STORAGE=gcs`
    /// mode against a real fake-gcs-server, plus the ticket's own falsification
    /// where the emulator is stopped and the daemon must exit loud. That script
    /// exercises the shipped image, so it covers the operator's path rather than
    /// this crate's view of it. This test stays as the narrower, faster probe of
    /// the store seam itself.
    ///
    /// Run it with:
    ///
    /// ```text
    /// docker network create kin-gcs-test
    /// docker run -d --name fake-gcs --network kin-gcs-test -p 4443:4443 \
    ///   fsouza/fake-gcs-server -scheme http -port 4443 -backend memory
    /// # Seed through the JSON API. Creating a directory inside a running
    /// # container does NOT register a bucket: fake-gcs-server reads its data
    /// # directory at process start, and under -backend memory that tree is not
    /// # the authority at all.
    /// curl -X POST 'http://localhost:4443/storage/v1/b?project=kin-test' \
    ///   -H 'Content-Type: application/json' -d '{"name":"kin-test-bucket"}'
    /// STORAGE_EMULATOR_HOST=http://localhost:4443 \
    ///   KIN_GCS_TEST_BUCKET=kin-test-bucket \
    ///   cargo test -p kin-daemon --features gcs \
    ///     gcs_endpoint::tests::a_seeded_emulator_serves_a_snapshot_round_trip -- --ignored --nocapture
    /// ```
    ///
    /// One expectation worth naming: the CAS path in `GcsBackend::save_snapshot`
    /// reads a NUMERIC object generation and refuses an ETag or synthetic
    /// fallback (kin-db `storage/gcs.rs`, `numeric_version`). If this fails on
    /// the version rather than on connectivity, that is the reason, and it is a
    /// property of the emulator rather than of the endpoint lever.
    #[cfg(feature = "gcs")]
    #[test]
    #[ignore = "needs a running fake-gcs-server; see the doc comment for the command"]
    fn a_seeded_emulator_serves_a_snapshot_round_trip() {
        use kin_db::{StorageBackend, GENERATION_INIT};

        let bucket = std::env::var("KIN_GCS_TEST_BUCKET")
            .expect("set KIN_GCS_TEST_BUCKET to a bucket the emulator already holds");
        let endpoint = resolve(
            std::env::var(KIN_ENDPOINT_VAR).ok().as_deref(),
            std::env::var(EMULATOR_HOST_VAR).ok().as_deref(),
        )
        .expect("endpoint parses")
        .expect("set KIN_GCS_ENDPOINT or STORAGE_EMULATOR_HOST to the emulator");

        // The same refusal the daemon performs at startup. Running it here means
        // a failure below is a storage failure, never a "was it even up" one.
        endpoint
            .probe_reachable(DEFAULT_PROBE_TIMEOUT)
            .expect("emulator must be reachable");

        let backend = backend_for(&endpoint, &bucket, String::new()).expect("backend builds");

        // Prove the bucket exists before writing to it. A missing bucket
        // otherwise surfaces as a storage error on save, which looks exactly
        // like a broken base URL or the numeric-generation caveat the doc
        // comment above primes a reader to suspect, and sends the debugging
        // budget to the endpoint lever instead of to the seeding step.
        backend.list_repos().unwrap_or_else(|error| {
            panic!(
                "bucket {bucket:?} is not readable at {} ({error}). Seed it first:\n  \
                 curl -X POST '{}/storage/v1/b?project=kin-test' \
                 -H 'Content-Type: application/json' -d '{{\"name\":\"{bucket}\"}}'",
                endpoint.url, endpoint.url
            )
        });

        let repo_id = format!("kin-endpoint-roundtrip-{}", std::process::id());
        let payload = b"kin gcs endpoint round trip".to_vec();

        backend
            .save_snapshot(&repo_id, &payload, GENERATION_INIT)
            .expect("save reaches the emulator");
        let (loaded, _generation) = backend
            .load_snapshot(&repo_id)
            .expect("load reaches the emulator")
            .expect("the snapshot just written must be there");
        assert_eq!(loaded, payload, "round trip must preserve the bytes");
    }

    #[test]
    fn a_stopped_emulator_fails_loud() {
        // Bind to claim a free port, then drop the listener so the port is
        // closed but almost certainly still unclaimed: a stopped emulator.
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr").port()
        };
        let endpoint = ResolvedEndpoint {
            url: format!("http://127.0.0.1:{port}"),
            host: "127.0.0.1".to_string(),
            port,
            source: EMULATOR_HOST_VAR,
        };
        let error = endpoint
            .probe_reachable(Duration::from_secs(2))
            .expect_err("a closed port must not read as reachable");
        assert!(error.contains(EMULATOR_HOST_VAR), "got {error:?}");
        assert!(error.contains("nothing is listening"), "got {error:?}");
        assert!(
            error.contains("Refusing to start"),
            "the operator must be told the daemon stopped rather than fell back, got {error:?}"
        );
    }
}
