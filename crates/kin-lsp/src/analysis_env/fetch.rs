// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Downloads for analysis environments: every byte hashed as it arrives, and
//! nothing kept that does not match the digest the lock names.
//!
//! The HTTP client honours the proxy variables every package tool reads
//! (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`), a proxy named in the
//! user's own package-tool configuration, and a CA bundle named there or in
//! `SSL_CERT_FILE`, so a host behind a re-signing proxy fetches what its
//! package manager fetches.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::Digest;

use crate::adapters::contract::hex;

/// How one fetch failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The request got no usable answer: no connection or a refused request.
    /// The reason names the URL with any credentials removed.
    Network(String),
    /// The server answered with an error status. Package tools read some
    /// statuses (a 404 or 410 from a module proxy) as "not here, ask the next
    /// source", so the status is kept.
    Status { url: String, status: u16 },
    /// The bytes arrived and do not hash to the digest the lock names.
    Mismatch {
        url: String,
        expected: String,
        actual: String,
    },
    /// The bytes could not be written where they belong.
    Io(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Network(reason) | FetchError::Io(reason) => f.write_str(reason),
            FetchError::Status { url, status } => write!(f, "{url} answered {status}"),
            FetchError::Mismatch {
                url,
                expected,
                actual,
            } => {
                // A digest named without its algorithm is sha256.
                let named = |digest: &str| {
                    if digest.contains(' ') {
                        digest.to_string()
                    } else {
                        format!("sha256 {digest}")
                    }
                };
                write!(
                    f,
                    "{url} served bytes that hash to {}, and the lock pins {}; nothing was \
                     unpacked",
                    named(actual),
                    named(expected)
                )
            }
        }
    }
}

/// What a download wrote and what it hashed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    pub sha256: String,
    pub bytes: u64,
}

/// The network, as analysis environments use it. A trait so every path is
/// testable without one.
pub trait Fetcher: Sync {
    /// A small document, such as an index page: its content type and bytes.
    fn document(&self, url: &str, accept: &str) -> Result<(String, Vec<u8>), FetchError>;

    /// Stream `url` into `destination`, hashing as it goes, and stop past
    /// `max_bytes`. The caller compares the digest before trusting the file.
    fn download(
        &self,
        url: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<Downloaded, FetchError>;
}

/// Download `url` to `destination` and keep it only when it hashes to
/// `expected` (lowercase hex sha256). A mismatch removes the file.
pub fn download_verified(
    fetcher: &dyn Fetcher,
    url: &str,
    destination: &Path,
    expected: &str,
    max_bytes: u64,
) -> Result<Downloaded, FetchError> {
    let downloaded = fetcher.download(url, destination, max_bytes)?;
    if !downloaded.sha256.eq_ignore_ascii_case(expected) {
        let _ = std::fs::remove_file(destination);
        return Err(FetchError::Mismatch {
            url: redact(url),
            expected: expected.to_ascii_lowercase(),
            actual: downloaded.sha256,
        });
    }
    Ok(downloaded)
}

/// A digest algorithm a lock may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
        }
    }
}

/// The digest of a file's bytes under `algorithm`.
pub fn digest_file(path: &Path, algorithm: HashAlgorithm) -> Result<Vec<u8>, String> {
    fn stream<D: sha2::Digest>(path: &Path, mut hasher: D) -> Result<Vec<u8>, String> {
        let mut file =
            std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hasher.finalize().to_vec())
    }
    match algorithm {
        HashAlgorithm::Sha1 => stream(path, sha1::Sha1::new()),
        HashAlgorithm::Sha256 => stream(path, sha2::Sha256::new()),
        HashAlgorithm::Sha384 => stream(path, sha2::Sha384::new()),
        HashAlgorithm::Sha512 => stream(path, sha2::Sha512::new()),
    }
}

/// Download `url` to `destination` and keep it only when its bytes hash to
/// one of `expected`, each a digest under its algorithm. The strongest
/// algorithm the lock names decides; a mismatch removes the file.
pub fn download_verified_any(
    fetcher: &dyn Fetcher,
    url: &str,
    destination: &Path,
    expected: &[(HashAlgorithm, Vec<u8>)],
    max_bytes: u64,
) -> Result<Downloaded, FetchError> {
    let Some((algorithm, digest)) = expected
        .iter()
        .max_by_key(|(algorithm, _)| *algorithm as u8)
    else {
        return Err(FetchError::Io(format!(
            "{} has no digest to check it against",
            redact(url)
        )));
    };
    let downloaded = fetcher.download(url, destination, max_bytes)?;
    let actual = match digest_file(destination, *algorithm) {
        Ok(actual) => actual,
        Err(reason) => {
            let _ = std::fs::remove_file(destination);
            return Err(FetchError::Io(reason));
        }
    };
    if actual != *digest {
        let _ = std::fs::remove_file(destination);
        return Err(FetchError::Mismatch {
            url: redact(url),
            expected: format!("{} {}", algorithm.name(), hex(digest)),
            actual: format!("{} {}", algorithm.name(), hex(&actual)),
        });
    }
    Ok(downloaded)
}

/// `url` without the credentials an index URL may carry, for logs and
/// reasons.
pub fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// Network settings from the user's package-tool configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkConfig {
    /// A proxy for every request, when the configuration names one beside
    /// the environment's proxy variables, which the client reads itself.
    pub proxy: Option<String>,
    /// PEM bundles of extra certificate authorities to trust.
    pub ca_bundles: Vec<PathBuf>,
}

/// Requests every [`HttpFetcher`] in this process has sent.
static REQUESTS_SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many requests analysis environments have sent over the network in this
/// process, for the test that proves the test harness sends none.
pub fn requests_sent() -> usize {
    REQUESTS_SENT.load(std::sync::atomic::Ordering::Relaxed)
}

/// The HTTP client analysis environments fetch with.
pub struct HttpFetcher {
    client: reqwest::blocking::Client,
    /// `Authorization` values for URLs under a prefix, as the user's package
    /// tool configuration names them (an npm `_authToken`, a Cargo registry
    /// token). The longest matching prefix wins. The client drops the header
    /// when a redirect leaves the host.
    authorizations: Vec<(String, String)>,
}

impl HttpFetcher {
    pub fn new(config: &NetworkConfig) -> Result<Self, String> {
        let mut builder = reqwest::blocking::Client::builder()
            .user_agent(concat!("kin/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(600));
        if let Some(proxy) = &config.proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy)
                    .map_err(|error| format!("the proxy {}: {error}", redact(proxy)))?,
            );
        }
        for bundle in &config.ca_bundles {
            let pem =
                std::fs::read(bundle).map_err(|error| format!("{}: {error}", bundle.display()))?;
            for certificate in reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|error| format!("{}: {error}", bundle.display()))?
            {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder
            .build()
            .map_err(|error| format!("could not build the HTTP client: {error}"))?;
        Ok(Self {
            client,
            authorizations: Vec::new(),
        })
    }

    /// Send `value` as the `Authorization` header of every request whose URL
    /// starts with `prefix`.
    pub fn with_authorization(
        mut self,
        prefix: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.authorizations.push((prefix.into(), value.into()));
        self
    }

    fn authorization(&self, url: &str) -> Option<&str> {
        self.authorizations
            .iter()
            .filter(|(prefix, _)| url.starts_with(prefix.as_str()))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, value)| value.as_str())
    }

    fn get(&self, url: &str, accept: &str) -> Result<reqwest::blocking::Response, FetchError> {
        REQUESTS_SENT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut request = self.client.get(url).header(reqwest::header::ACCEPT, accept);
        if let Some(value) = self.authorization(url) {
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        let response = request.send().map_err(|error| {
            FetchError::Network(format!(
                "could not fetch {}: {}",
                redact(url),
                with_causes(&error)
            ))
        })?;
        if !response.status().is_success() {
            return Err(FetchError::Status {
                url: redact(url),
                status: response.status().as_u16(),
            });
        }
        Ok(response)
    }
}

/// An error with the causes under it, since a transport error's own words
/// name only the URL.
fn with_causes(error: &dyn std::error::Error) -> String {
    let mut rendered = error.to_string();
    let mut next = error.source();
    while let Some(cause) = next {
        let text = cause.to_string();
        if !rendered.contains(&text) {
            rendered.push_str(": ");
            rendered.push_str(&text);
        }
        next = cause.source();
    }
    rendered
}

/// The most bytes one index document may be.
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

impl Fetcher for HttpFetcher {
    fn document(&self, url: &str, accept: &str) -> Result<(String, Vec<u8>), FetchError> {
        let response = self.get(url, accept)?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut bytes = Vec::new();
        response
            .take(MAX_DOCUMENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| FetchError::Network(format!("{}: {error}", redact(url))))?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            return Err(FetchError::Network(format!(
                "{} is larger than {MAX_DOCUMENT_BYTES} bytes",
                redact(url)
            )));
        }
        Ok((content_type, bytes))
    }

    fn download(
        &self,
        url: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<Downloaded, FetchError> {
        let mut response = self.get(url, "*/*")?;
        write_hashed(&mut response, destination, max_bytes, url)
    }
}

/// Copy `reader` into `destination`, hashing as it goes, and remove the file
/// on any failure.
pub fn write_hashed(
    reader: &mut dyn Read,
    destination: &Path,
    max_bytes: u64,
    url: &str,
) -> Result<Downloaded, FetchError> {
    if let Some(dir) = destination.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|error| FetchError::Io(format!("{}: {error}", dir.display())))?;
    }
    let mut file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| FetchError::Io(format!("{}: {error}", destination.display())))?;
    let mut hasher = sha2::Sha256::new();
    let mut total: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    let result = loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break Ok(()),
            Ok(read) => read,
            Err(error) => {
                break Err(FetchError::Network(format!("{}: {error}", redact(url))));
            }
        };
        total += read as u64;
        if total > max_bytes {
            break Err(FetchError::Network(format!(
                "{} passed {max_bytes} bytes and was abandoned",
                redact(url)
            )));
        }
        hasher.update(&buffer[..read]);
        if let Err(error) = file.write_all(&buffer[..read]) {
            break Err(FetchError::Io(format!(
                "{}: {error}",
                destination.display()
            )));
        }
    };
    let result = result.and_then(|()| {
        file.flush()
            .map_err(|error| FetchError::Io(format!("{}: {error}", destination.display())))
    });
    drop(file);
    match result {
        Ok(()) => Ok(Downloaded {
            sha256: hex(&hasher.finalize()),
            bytes: total,
        }),
        Err(error) => {
            let _ = std::fs::remove_file(destination);
            Err(error)
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A fetcher that serves fixed bytes, for tests.

    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex;

    use super::{write_hashed, Downloaded, FetchError, Fetcher};

    #[derive(Default)]
    pub(crate) struct FixedFetcher {
        pub(crate) documents: HashMap<String, (String, Vec<u8>)>,
        pub(crate) files: HashMap<String, Vec<u8>>,
        pub(crate) requests: Mutex<Vec<String>>,
    }

    impl Fetcher for FixedFetcher {
        fn document(&self, url: &str, _accept: &str) -> Result<(String, Vec<u8>), FetchError> {
            self.requests.lock().unwrap().push(url.to_string());
            self.documents
                .get(url)
                .cloned()
                .ok_or_else(|| FetchError::Status {
                    url: url.to_string(),
                    status: 404,
                })
        }

        fn download(
            &self,
            url: &str,
            destination: &Path,
            max_bytes: u64,
        ) -> Result<Downloaded, FetchError> {
            self.requests.lock().unwrap().push(url.to_string());
            let bytes = self.files.get(url).ok_or_else(|| FetchError::Status {
                url: url.to_string(),
                status: 404,
            })?;
            write_hashed(&mut bytes.as_slice(), destination, max_bytes, url)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FixedFetcher;
    use super::*;

    #[test]
    fn credentials_never_reach_a_reason() {
        assert_eq!(
            redact("https://user:secret@pypi.example/simple/x/"),
            "https://***@pypi.example/simple/x/"
        );
        assert_eq!(
            redact("https://pypi.org/simple/"),
            "https://pypi.org/simple/"
        );
    }

    /// Bytes that do not hash to the lock's digest are refused, and nothing
    /// of them is left where an unpack could find it.
    #[test]
    fn a_hash_mismatch_is_refused_and_removed() {
        let dir = crate::adapters::repo_scan::Fixture::new("fetch-mismatch");
        let mut fetcher = FixedFetcher::default();
        fetcher.files.insert(
            "https://files.example/x.whl".to_string(),
            b"tampered".to_vec(),
        );
        let destination = dir.root.join("x.whl.part");
        let expected = hex(&sha2::Sha256::digest(b"original"));
        let error = download_verified(
            &fetcher,
            "https://files.example/x.whl",
            &destination,
            &expected,
            1024,
        )
        .unwrap_err();
        assert!(matches!(error, FetchError::Mismatch { .. }), "{error}");
        assert!(!destination.exists());

        let good = hex(&sha2::Sha256::digest(b"tampered"));
        let downloaded = download_verified(
            &fetcher,
            "https://files.example/x.whl",
            &destination,
            &good,
            1024,
        )
        .unwrap();
        assert_eq!(downloaded.bytes, 8);
        assert!(destination.is_file());
    }

    #[test]
    fn a_download_never_truncates_or_removes_another_attempt() {
        let dir = crate::adapters::repo_scan::Fixture::new("fetch-owned");
        let destination = dir.root.join("archive.part");
        std::fs::write(&destination, b"other owner").unwrap();
        let error =
            write_hashed(&mut b"replacement".as_slice(), &destination, 1024, "u").unwrap_err();
        assert!(matches!(error, FetchError::Io(_)));
        assert_eq!(std::fs::read(&destination).unwrap(), b"other owner");
    }

    #[test]
    fn a_body_past_its_ceiling_is_abandoned() {
        let dir = crate::adapters::repo_scan::Fixture::new("fetch-ceiling");
        let destination = dir.root.join("big");
        let error = write_hashed(&mut [0u8; 100].as_slice(), &destination, 10, "u").unwrap_err();
        assert!(error.to_string().contains("abandoned"), "{error}");
        assert!(!destination.exists());
    }
}
