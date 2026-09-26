// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A Go module cache, in the layout the `go` command reads with `GOMODCACHE`,
//! filled from a module proxy one verified module at a time.
//!
//! ```text
//! <modcache>/
//!   cache/download/<escaped path>/@v/<escaped version>.mod      verified against go.sum
//!   cache/download/<escaped path>/@v/<escaped version>.zip      verified against go.sum
//!   cache/download/<escaped path>/@v/<escaped version>.ziphash  the zip's go.sum hash
//!   cache/download/<escaped path>/@v/<escaped version>.info     the proxy's version metadata
//!   <escaped path>@<escaped version>/                            the zip, unpacked
//! ```
//!
//! This is the layout the `go` command itself writes, so gopls runs with this
//! directory as `GOMODCACHE` and `GOPROXY=off` and finds every module the
//! lock pins without asking the network. A module's files are unpacked only
//! after the zip hashes to the `h1:` hash `go.sum` names, the way
//! `go mod download` checks them, and the unpacked directory appears only
//! once complete, so a directory that exists can be trusted. Nothing in a
//! module is run: not `go generate`, not cgo, not a test.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::Digest;

use super::super::fetch::{FetchError, Fetcher};
use super::super::{base64_encode, python::store as shared, unpack, write_atomically};
use crate::adapters::contract::hex;

/// The most bytes a module zip may be. The `go` command refuses larger ones.
pub const MAX_ZIP_BYTES: u64 = 500 * 1024 * 1024;

/// The most bytes a `go.mod` or `.info` document may be.
pub const MAX_MOD_BYTES: u64 = 16 * 1024 * 1024;

/// A module path or version escaped for the module proxy protocol and the
/// module cache: each uppercase letter becomes `!` and its lowercase.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The `h1:` hash of a list of named files, as `go.sum` records it: the
/// sha256 of a summary line per file, `<sha256 hex>  <name>\n`, sorted by
/// name, in standard base64.
pub fn hash1(files: &mut [(String, [u8; 32])]) -> Result<String, String> {
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut summary = sha2::Sha256::new();
    for (name, digest) in files.iter() {
        if name.contains('\n') {
            return Err(format!("the file name {name:?} holds a newline"));
        }
        summary.update(format!("{}  {name}\n", hex(digest)).as_bytes());
    }
    Ok(format!("h1:{}", base64_encode(&summary.finalize())))
}

/// The `h1:` hash of a `go.mod` file's bytes, as `go.sum`'s `/go.mod` lines
/// record it.
pub fn hash_go_mod(bytes: &[u8]) -> String {
    let digest: [u8; 32] = sha2::Sha256::digest(bytes).into();
    hash1(&mut [("go.mod".to_string(), digest)]).unwrap_or_default()
}

/// The `h1:` hash of a module zip, over every entry it holds.
pub fn hash_zip(zip_path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(zip_path)
        .map_err(|error| format!("{}: {error}", zip_path.display()))?;
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(file))
        .map_err(|error| format!("{} is not a zip archive: {error}", zip_path.display()))?;
    let mut files = Vec::with_capacity(zip.len());
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|error| format!("{}: {error}", zip_path.display()))?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = entry
                .read(&mut buffer)
                .map_err(|error| format!("{}: {error}", zip_path.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        files.push((entry.name().to_string(), hasher.finalize().into()));
    }
    hash1(&mut files)
}

/// Where the module cache keeps one module version's files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePaths {
    /// `cache/download/<path>/@v/`.
    pub download_dir: PathBuf,
    /// The file stem inside it, the escaped version.
    pub stem: String,
    /// The unpacked module, `<path>@<version>`.
    pub extracted: PathBuf,
}

impl CachePaths {
    pub fn new(modcache: &Path, module: &str, version: &str) -> Self {
        let stem = escape(version);
        Self {
            download_dir: modcache
                .join("cache/download")
                .join(escape(module))
                .join("@v"),
            extracted: modcache.join(format!("{}@{stem}", escape(module))),
            stem,
        }
    }

    pub fn file(&self, extension: &str) -> PathBuf {
        self.download_dir.join(format!("{}.{extension}", self.stem))
    }
}

/// Whether the cache holds this module's `go.mod`, matching `expected`.
pub fn has_go_mod(modcache: &Path, module: &str, version: &str, expected: &str) -> bool {
    std::fs::read(CachePaths::new(modcache, module, version).file("mod"))
        .is_ok_and(|bytes| hash_go_mod(&bytes) == expected)
}

/// Whether the cache holds this module unpacked, recorded with `expected` as
/// its zip's hash. The `go` command trusts an unpacked directory whose
/// `.ziphash` matches `go.sum`, and so does this check.
pub fn has_module(modcache: &Path, module: &str, version: &str, expected: &str) -> bool {
    let paths = CachePaths::new(modcache, module, version);
    paths.extracted.is_dir()
        && std::fs::read_to_string(paths.file("ziphash")).is_ok_and(|hash| hash.trim() == expected)
}

/// One module proxy, as `GOPROXY` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEntry {
    /// A proxy URL, and whether any error (`|`) rather than only a 404 or 410
    /// (`,`) passes the request to the next entry.
    Url { url: String, any_error: bool },
    /// `direct`: the module's version control repository. Kin does not fetch
    /// from version control, so a module that reaches this entry is left out.
    Direct,
    /// `off`: no network.
    Off,
}

/// Parse a `GOPROXY` value.
pub fn parse_goproxy(value: &str) -> Vec<ProxyEntry> {
    let mut entries = Vec::new();
    let mut rest = value.trim();
    while !rest.is_empty() {
        let end = rest.find([',', '|']).unwrap_or(rest.len());
        let item = rest[..end].trim();
        let any_error = rest[end..].starts_with('|');
        rest = rest.get(end + 1..).unwrap_or("");
        match item {
            "" => {}
            "direct" => entries.push(ProxyEntry::Direct),
            "off" => entries.push(ProxyEntry::Off),
            url => entries.push(ProxyEntry::Url {
                url: url.trim_end_matches('/').to_string(),
                any_error,
            }),
        }
    }
    entries
}

/// Ask each proxy in turn for one file of a module, the way the `go` command
/// walks `GOPROXY`, and run `fetch` against the first that has it.
fn from_proxies<T>(
    proxies: &[ProxyEntry],
    module: &str,
    mut fetch: impl FnMut(&str) -> Result<T, FetchError>,
) -> Result<T, String> {
    let mut tried = Vec::new();
    for entry in proxies {
        match entry {
            ProxyEntry::Off => {
                tried.push("GOPROXY=off".to_string());
                break;
            }
            ProxyEntry::Direct => {
                tried.push(format!(
                    "GOPROXY reaches `direct` for {module}, and Kin does not fetch from version \
                     control"
                ));
                break;
            }
            ProxyEntry::Url { url, any_error } => {
                let base = format!("{url}/{}/@v/", escape(module));
                match fetch(&base) {
                    Ok(value) => return Ok(value),
                    Err(FetchError::Status { status, url }) if status == 404 || status == 410 => {
                        tried.push(format!("{url} answered {status}"));
                    }
                    Err(error @ FetchError::Mismatch { .. }) => return Err(error.to_string()),
                    Err(error) if *any_error => tried.push(error.to_string()),
                    Err(error) => {
                        tried.push(error.to_string());
                        break;
                    }
                }
            }
        }
    }
    if tried.is_empty() {
        tried.push("GOPROXY names no proxy".to_string());
    }
    Err(tried.join("; "))
}

/// Put one module's `go.mod` in the cache, verified against `expected`.
/// Returns the bytes downloaded, zero when the cache held it.
pub fn ensure_go_mod(
    fetcher: &dyn Fetcher,
    proxies: &[ProxyEntry],
    modcache: &Path,
    module: &str,
    version: &str,
    expected: &str,
) -> Result<u64, String> {
    if has_go_mod(modcache, module, version, expected) {
        return Ok(0);
    }
    let paths = CachePaths::new(modcache, module, version);
    let bytes = from_proxies(proxies, module, |base| {
        let url = format!("{base}{}.mod", paths.stem);
        let (_, bytes) = fetcher.document(&url, "text/plain")?;
        let actual = hash_go_mod(&bytes);
        if actual != expected {
            return Err(FetchError::Mismatch {
                url,
                expected: format!("go.sum {expected}"),
                actual: format!("go.sum {actual}"),
            });
        }
        Ok(bytes)
    })?;
    if bytes.len() as u64 > MAX_MOD_BYTES {
        return Err(format!("{module} {version}: its go.mod is too large"));
    }
    write_atomically(&paths.file("mod"), &bytes)?;
    Ok(bytes.len() as u64)
}

/// Put one module in the cache: its zip fetched, verified against
/// `expected` before anything is unpacked, then unpacked. Returns the bytes
/// downloaded, zero when the cache held it.
pub fn ensure_module(
    fetcher: &dyn Fetcher,
    proxies: &[ProxyEntry],
    modcache: &Path,
    module: &str,
    version: &str,
    expected: &str,
) -> Result<u64, String> {
    if has_module(modcache, module, version, expected) {
        return Ok(0);
    }
    let paths = CachePaths::new(modcache, module, version);
    let unique = shared::unique_suffix();
    let staged_zip = paths
        .download_dir
        .join(format!(".{}.{unique}.zip", paths.stem));
    let downloaded = from_proxies(proxies, module, |base| {
        let url = format!("{base}{}.zip", paths.stem);
        let downloaded = fetcher.download(&url, &staged_zip, MAX_ZIP_BYTES)?;
        let actual = match hash_zip(&staged_zip) {
            Ok(actual) => actual,
            Err(reason) => {
                let _ = std::fs::remove_file(&staged_zip);
                return Err(FetchError::Io(format!("{module} {version}: {reason}")));
            }
        };
        if actual != expected {
            let _ = std::fs::remove_file(&staged_zip);
            return Err(FetchError::Mismatch {
                url,
                expected: format!("go.sum {expected}"),
                actual: format!("go.sum {actual}"),
            });
        }
        Ok(downloaded)
    })?;
    let result = unpack_module(&staged_zip, &paths, module, version, expected, &unique);
    if result.is_err() {
        let _ = std::fs::remove_file(&staged_zip);
    }
    result?;
    // The version metadata the `go` command keeps beside the zip. It is not
    // hashed by any lock, so it is read only for its version and time, and a
    // proxy that has none gets the version alone.
    if !paths.file("info").is_file() {
        let info = from_proxies(proxies, module, |base| {
            fetcher
                .document(&format!("{base}{}.info", paths.stem), "application/json")
                .map(|(_, bytes)| bytes)
        })
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .filter(|info| info.get("Version").and_then(|v| v.as_str()) == Some(version))
        .map(|info| {
            serde_json::json!({
                "Version": version,
                "Time": info.get("Time").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .unwrap_or_else(|| serde_json::json!({ "Version": version }));
        let _ = write_atomically(&paths.file("info"), info.to_string().as_bytes());
    }
    Ok(downloaded.bytes)
}

/// Unpack a verified zip into the cache: every entry must sit under
/// `<module>@<version>/`, and the directory appears whole, after its
/// `.ziphash`, as the `go` command orders them.
fn unpack_module(
    staged_zip: &Path,
    paths: &CachePaths,
    module: &str,
    version: &str,
    expected: &str,
    unique: &str,
) -> Result<(), String> {
    let staging = paths
        .extracted
        .with_file_name(format!(".unpack.{unique}.tmp"));
    let outcome = (|| {
        unpack::unzip(staged_zip, &staging)
            .map_err(|reason| format!("{module} {version}: {reason}"))?;
        let prefix = format!("{module}@{version}");
        let top = staging.join(&prefix);
        let only_the_prefix = std::fs::read_dir(&staging)
            .map_err(|error| error.to_string())?
            .filter_map(Result::ok)
            .all(|entry| prefix.starts_with(&*entry.file_name().to_string_lossy()));
        if !top.is_dir() || !only_the_prefix {
            return Err(format!(
                "{module} {version}: the zip holds files outside {prefix}/"
            ));
        }
        write_atomically(&paths.file("ziphash"), expected.as_bytes())?;
        shared::publish_dir(&top, &paths.extracted)?;
        std::fs::rename(staged_zip, paths.file("zip"))
            .map_err(|error| format!("{}: {error}", paths.file("zip").display()))
    })();
    let _ = std::fs::remove_dir_all(&staging);
    outcome
}

#[cfg(test)]
pub(crate) mod testing {
    //! Module zips built in memory, for tests.

    use std::io::Write;

    /// A module zip holding `files` under `<module>@<version>/`.
    pub(crate) fn module_zip(module: &str, version: &str, files: &[(&str, &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
            for (name, text) in files {
                zip.start_file(
                    format!("{module}@{version}/{name}"),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
                zip.write_all(text.as_bytes()).unwrap();
            }
            zip.finish().unwrap();
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::testing::module_zip;
    use super::*;
    use crate::adapters::repo_scan::Fixture;
    use crate::analysis_env::fetch::testing::FixedFetcher;

    /// A known answer: `github.com/davecgh/go-spew v1.1.1` has no go.mod of
    /// its own, so the proxy serves the one line below, and every go.sum that
    /// needs it records this hash.
    #[test]
    fn go_mod_hashes_match_go_sum() {
        assert_eq!(
            hash_go_mod(b"module github.com/davecgh/go-spew\n"),
            "h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38="
        );
    }

    #[test]
    fn escaping_marks_uppercase() {
        assert_eq!(
            escape("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        assert_eq!(escape("v1.0.0-RC1"), "v1.0.0-!r!c1");
    }

    #[test]
    fn goproxy_lists_keep_their_fallthrough_rules() {
        assert_eq!(
            parse_goproxy("https://a.example/,https://b.example|direct"),
            vec![
                ProxyEntry::Url {
                    url: "https://a.example".to_string(),
                    any_error: false
                },
                ProxyEntry::Url {
                    url: "https://b.example".to_string(),
                    any_error: true
                },
                ProxyEntry::Direct,
            ]
        );
        assert_eq!(parse_goproxy("off"), vec![ProxyEntry::Off]);
    }

    fn proxy() -> Vec<ProxyEntry> {
        parse_goproxy("https://proxy.example,direct")
    }

    /// A module verified against its hash is unpacked where the `go` command
    /// looks, with its `.ziphash`, `.zip` and `.info` beside it; a second
    /// call downloads nothing.
    #[test]
    fn a_verified_module_lands_in_the_go_command_layout() {
        let cache = Fixture::new("gomod-cache");
        let zip = module_zip(
            "example.com/Lib",
            "v1.2.0",
            &[
                ("go.mod", "module example.com/Lib\n"),
                ("lib.go", "package lib\n"),
            ],
        );
        let zip_path = cache.root.join("probe.zip");
        std::fs::write(&zip_path, &zip).unwrap();
        let expected = hash_zip(&zip_path).unwrap();
        let mut fetcher = FixedFetcher::default();
        fetcher.files.insert(
            "https://proxy.example/example.com/!lib/@v/v1.2.0.zip".to_string(),
            zip,
        );
        fetcher.documents.insert(
            "https://proxy.example/example.com/!lib/@v/v1.2.0.info".to_string(),
            (
                "application/json".to_string(),
                br#"{"Version":"v1.2.0","Time":"2024-01-01T00:00:00Z"}"#.to_vec(),
            ),
        );
        let modcache = cache.root.join("modcache");
        let bytes = ensure_module(
            &fetcher,
            &proxy(),
            &modcache,
            "example.com/Lib",
            "v1.2.0",
            &expected,
        )
        .unwrap();
        assert!(bytes > 0);
        let paths = CachePaths::new(&modcache, "example.com/Lib", "v1.2.0");
        assert!(paths.extracted.join("lib.go").is_file());
        assert_eq!(
            std::fs::read_to_string(paths.file("ziphash")).unwrap(),
            expected
        );
        assert!(paths.file("zip").is_file());
        assert!(std::fs::read_to_string(paths.file("info"))
            .unwrap()
            .contains("2024-01-01"));
        assert!(has_module(
            &modcache,
            "example.com/Lib",
            "v1.2.0",
            &expected
        ));
        let requests = fetcher.requests.lock().unwrap().len();
        assert_eq!(
            ensure_module(
                &fetcher,
                &proxy(),
                &modcache,
                "example.com/Lib",
                "v1.2.0",
                &expected
            ),
            Ok(0)
        );
        assert_eq!(fetcher.requests.lock().unwrap().len(), requests);
    }

    /// A zip whose hash differs from go.sum's is refused, and nothing of it
    /// is unpacked or left behind.
    #[test]
    fn a_module_that_does_not_match_go_sum_is_refused() {
        let cache = Fixture::new("gomod-mismatch");
        let mut fetcher = FixedFetcher::default();
        fetcher.files.insert(
            "https://proxy.example/example.com/x/@v/v1.0.0.zip".to_string(),
            module_zip("example.com/x", "v1.0.0", &[("x.go", "package x\n")]),
        );
        let modcache = cache.root.join("modcache");
        let error = ensure_module(
            &fetcher,
            &proxy(),
            &modcache,
            "example.com/x",
            "v1.0.0",
            "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .unwrap_err();
        assert!(error.contains("nothing was unpacked"), "{error}");
        let paths = CachePaths::new(&modcache, "example.com/x", "v1.0.0");
        assert!(!paths.extracted.exists());
        let leftovers: Vec<_> = std::fs::read_dir(&paths.download_dir)
            .map(|entries| entries.filter_map(Result::ok).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// A zip that puts a file outside `<module>@<version>/` is refused even
    /// when go.sum names its hash.
    #[test]
    fn a_zip_with_files_outside_its_module_is_refused() {
        let cache = Fixture::new("gomod-outside");
        let zip = module_zip("example.com/other", "v1.0.0", &[("x.go", "package x\n")]);
        let zip_path = cache.root.join("probe.zip");
        std::fs::write(&zip_path, &zip).unwrap();
        let expected = hash_zip(&zip_path).unwrap();
        let mut fetcher = FixedFetcher::default();
        fetcher.files.insert(
            "https://proxy.example/example.com/x/@v/v1.0.0.zip".to_string(),
            zip,
        );
        let modcache = cache.root.join("modcache");
        let error = ensure_module(
            &fetcher,
            &proxy(),
            &modcache,
            "example.com/x",
            "v1.0.0",
            &expected,
        )
        .unwrap_err();
        assert!(error.contains("outside"), "{error}");
    }

    /// A proxy's 404 passes the request on; `direct` stops it with a reason.
    #[test]
    fn proxies_are_walked_in_order() {
        let cache = Fixture::new("gomod-walk");
        let go_mod = b"module example.com/y\n".to_vec();
        let expected = hash_go_mod(&go_mod);
        let mut fetcher = FixedFetcher::default();
        fetcher.documents.insert(
            "https://second.example/example.com/y/@v/v1.0.0.mod".to_string(),
            ("text/plain".to_string(), go_mod),
        );
        let modcache = cache.root.join("modcache");
        let proxies = parse_goproxy("https://first.example,https://second.example");
        ensure_go_mod(
            &fetcher,
            &proxies,
            &modcache,
            "example.com/y",
            "v1.0.0",
            &expected,
        )
        .unwrap();
        assert!(has_go_mod(&modcache, "example.com/y", "v1.0.0", &expected));

        let error = ensure_go_mod(
            &fetcher,
            &parse_goproxy("https://first.example,direct"),
            &modcache,
            "example.com/z",
            "v1.0.0",
            &expected,
        )
        .unwrap_err();
        assert!(error.contains("version control"), "{error}");
    }
}
