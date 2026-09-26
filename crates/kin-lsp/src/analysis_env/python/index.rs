// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which package index to fetch from, read from the user's own configuration,
//! and how to find a locked file on it.
//!
//! The index is chosen the way the user's own tools choose it: uv's and pip's
//! environment variables first, then `uv.toml`, then `pip.conf`, then PyPI.
//! A lock that names files by digest alone (Pipfile.lock, a requirements file
//! with hashes) is matched against the index's listing for the package: the
//! file whose digest the lock names is the one fetched.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::super::fetch::{redact, FetchError, Fetcher, NetworkConfig};
use super::lockfile::normalize_name;

/// PyPI's simple index.
pub const PYPI: &str = "https://pypi.org/simple";

/// The index configuration in force for one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexConfig {
    /// The primary index.
    pub index_url: String,
    /// Further indexes to look in, in order.
    pub extra_index_urls: Vec<String>,
    /// Where the primary index was named, for the report.
    pub source: String,
    /// Proxy and certificate settings the configuration names.
    pub network: NetworkConfig,
}

impl IndexConfig {
    /// Whether the primary index is PyPI itself.
    pub fn is_pypi(&self) -> bool {
        let trimmed = self.index_url.trim_end_matches('/');
        trimmed == PYPI || trimmed == "https://pypi.python.org/simple"
    }

    /// Every index, the primary first.
    pub fn all(&self) -> Vec<&str> {
        std::iter::once(self.index_url.as_str())
            .chain(self.extra_index_urls.iter().map(String::as_str))
            .collect()
    }
}

/// A minimal INI reader for `pip.conf`: `[section]` headers, `key = value`
/// lines, and indented continuation lines, which `extra-index-url` uses for a
/// list.
fn ini(text: &str) -> HashMap<(String, String), String> {
    let mut values: HashMap<(String, String), String> = HashMap::new();
    let mut section = String::new();
    let mut last: Option<(String, String)> = None;
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some(key) = &last {
                let value = values.entry(key.clone()).or_default();
                value.push('\n');
                value.push_str(line.trim());
            }
            continue;
        }
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            last = None;
        } else if let Some((key, value)) = line.split_once(['=', ':']) {
            let key = (section.clone(), key.trim().to_ascii_lowercase());
            values.insert(key.clone(), value.trim().to_string());
            last = Some(key);
        }
    }
    values
}

fn words(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_string).collect()
}

/// The configuration files pip reads, in the order it reads them; later
/// files override earlier ones.
fn pip_config_files(vars: &HashMap<String, String>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/pip.conf")];
    files.push(PathBuf::from("/etc/xdg/pip/pip.conf"));
    if let Some(home) = home {
        files.push(home.join(".pip/pip.conf"));
        if cfg!(target_os = "macos") {
            files.push(home.join("Library/Application Support/pip/pip.conf"));
        }
        let config = vars
            .get("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        files.push(config.join("pip/pip.conf"));
    }
    if let Some(file) = vars.get("PIP_CONFIG_FILE").filter(|v| !v.is_empty()) {
        files.push(PathBuf::from(file));
    }
    files
}

fn uv_config_files(vars: &HashMap<String, String>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/uv/uv.toml")];
    if let Some(home) = home {
        let config = vars
            .get("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        files.push(config.join("uv/uv.toml"));
    }
    if let Some(file) = vars.get("UV_CONFIG_FILE").filter(|v| !v.is_empty()) {
        files.push(PathBuf::from(file));
    }
    files
}

/// The default index a `uv.toml` names: `[[index]]` with `default = true`,
/// then `index-url`, then `[pip] index-url`; and its extra indexes.
fn uv_indexes(table: &toml::Table) -> (Option<String>, Vec<String>) {
    let mut default = None;
    let mut extra = Vec::new();
    if let Some(indexes) = table.get("index").and_then(toml::Value::as_array) {
        for index in indexes {
            let Some(url) = index.get("url").and_then(toml::Value::as_str) else {
                continue;
            };
            if index.get("default").and_then(toml::Value::as_bool) == Some(true) {
                default = Some(url.to_string());
            } else {
                extra.push(url.to_string());
            }
        }
    }
    let string = |table: &toml::Table, key: &str| {
        table
            .get(key)
            .and_then(toml::Value::as_str)
            .map(str::to_string)
    };
    let pip = table.get("pip").and_then(toml::Value::as_table);
    default = default
        .or_else(|| string(table, "index-url"))
        .or_else(|| pip.and_then(|pip| string(pip, "index-url")));
    for key in ["extra-index-url"] {
        for source in [Some(table), pip].into_iter().flatten() {
            if let Some(urls) = source.get(key).and_then(toml::Value::as_array) {
                extra.extend(
                    urls.iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_string),
                );
            }
        }
    }
    (default, extra)
}

/// The index configuration for a host with these variables and this home.
pub fn index_config(vars: &HashMap<String, String>, home: Option<&Path>) -> IndexConfig {
    let var = |name: &str| vars.get(name).filter(|value| !value.trim().is_empty());
    let mut config = IndexConfig {
        index_url: PYPI.to_string(),
        extra_index_urls: Vec::new(),
        source: "PyPI, since no configuration names an index".to_string(),
        network: NetworkConfig::default(),
    };

    // Lowest precedence first, so each later source overrides.
    for file in pip_config_files(vars, home) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let values = ini(&text);
        for section in ["global", "install", "download"] {
            let get = |key: &str| values.get(&(section.to_string(), key.to_string()));
            if let Some(url) = get("index-url") {
                config.index_url = url.clone();
                config.source = file.display().to_string();
            }
            if let Some(urls) = get("extra-index-url") {
                config.extra_index_urls = words(urls);
            }
            if let Some(proxy) = get("proxy") {
                config.network.proxy = Some(proxy.clone());
            }
            if let Some(cert) = get("cert") {
                config.network.ca_bundles = vec![PathBuf::from(cert)];
            }
        }
    }
    for file in uv_config_files(vars, home) {
        let Some(table) = std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
        else {
            continue;
        };
        let (default, extra) = uv_indexes(&table);
        if let Some(url) = default {
            config.index_url = url;
            config.source = file.display().to_string();
        }
        if !extra.is_empty() {
            config.extra_index_urls = extra;
        }
    }
    for (name, is_default) in [
        ("PIP_INDEX_URL", true),
        ("PIP_EXTRA_INDEX_URL", false),
        ("UV_INDEX_URL", true),
        ("UV_EXTRA_INDEX_URL", false),
        ("UV_DEFAULT_INDEX", true),
        ("UV_INDEX", false),
    ] {
        if let Some(value) = var(name) {
            if is_default {
                config.index_url = value.trim().to_string();
                config.source = format!("${name}");
            } else {
                config.extra_index_urls = words(value);
            }
        }
    }
    if let Some(proxy) = var("PIP_PROXY") {
        config.network.proxy = Some(proxy.clone());
    }
    for name in ["PIP_CERT", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"] {
        if let Some(bundle) = var(name) {
            config.network.ca_bundles = vec![PathBuf::from(bundle)];
            break;
        }
    }
    config.network.ca_bundles.retain(|bundle| bundle.is_file());
    config
}

/// One file an index lists for a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexFile {
    pub filename: String,
    pub url: String,
    pub sha256: Option<String>,
    pub yanked: bool,
}

/// Resolve `href` against the page it appeared on.
fn resolve(base: &str, href: &str) -> Option<String> {
    let base = reqwest::Url::parse(base).ok()?;
    base.join(href).ok().map(String::from)
}

/// The files a PEP 691 JSON listing names.
fn parse_json_listing(page: &str, bytes: &[u8]) -> Result<Vec<IndexFile>, String> {
    let document: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("{} is not a JSON listing: {error}", redact(page)))?;
    let files = document
        .get("files")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{} lists no files", redact(page)))?;
    Ok(files
        .iter()
        .filter_map(|file| {
            let filename = file.get("filename")?.as_str()?.to_string();
            let url = resolve(page, file.get("url")?.as_str()?)?;
            let sha256 = file
                .get("hashes")
                .and_then(|hashes| hashes.get("sha256"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_ascii_lowercase);
            let yanked = file
                .get("yanked")
                .is_some_and(|yanked| yanked.as_bool() == Some(true) || yanked.is_string());
            Some(IndexFile {
                filename,
                url,
                sha256,
                yanked,
            })
        })
        .collect())
}

/// The files a PEP 503 HTML listing names: every anchor, its `href` carrying
/// the digest as a `#sha256=` fragment.
fn parse_html_listing(page: &str, text: &str) -> Vec<IndexFile> {
    let mut files = Vec::new();
    let lowered = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(start) = lowered[from..].find("<a ").map(|at| at + from) {
        let Some(tag_end) = lowered[start..].find('>').map(|at| at + start) else {
            break;
        };
        let Some(close) = lowered[tag_end..].find("</a>").map(|at| at + tag_end) else {
            break;
        };
        let tag = &text[start..tag_end];
        let filename = text[tag_end + 1..close].trim().to_string();
        from = close + 4;
        let Some(href_at) = tag.to_ascii_lowercase().find("href=") else {
            continue;
        };
        let rest = &tag[href_at + 5..];
        let quote = rest.chars().next().unwrap_or('"');
        let href = if quote == '"' || quote == '\'' {
            rest[1..].split(quote).next().unwrap_or("")
        } else {
            rest.split(char::is_whitespace).next().unwrap_or("")
        };
        let href = href.replace("&amp;", "&");
        let (link, fragment) = href.split_once('#').unwrap_or((&href, ""));
        let sha256 = fragment
            .strip_prefix("sha256=")
            .map(str::to_ascii_lowercase);
        let Some(url) = resolve(page, link) else {
            continue;
        };
        let yanked = tag.to_ascii_lowercase().contains("data-yanked");
        files.push(IndexFile {
            filename,
            url,
            sha256,
            yanked,
        });
    }
    files
}

/// The files `index` lists for the project `name`.
pub fn project_files(
    fetcher: &dyn Fetcher,
    index: &str,
    name: &str,
) -> Result<Vec<IndexFile>, FetchError> {
    let page = format!("{}/{}/", index.trim_end_matches('/'), normalize_name(name));
    let (content_type, bytes) = fetcher.document(
        &page,
        "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.1",
    )?;
    if content_type.contains("json") {
        parse_json_listing(&page, &bytes).map_err(FetchError::Network)
    } else {
        Ok(parse_html_listing(&page, &String::from_utf8_lossy(&bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;
    use crate::analysis_env::fetch::testing::FixedFetcher;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn with_no_configuration_the_index_is_pypi() {
        let home = Fixture::new("index-none");
        let config = index_config(&vars(&[]), Some(&home.root));
        assert!(config.is_pypi());
        assert_eq!(config.network, NetworkConfig::default());
    }

    /// pip.conf is read, uv.toml overrides it, and the tools' environment
    /// variables override both, as each tool orders them.
    #[test]
    fn configuration_files_and_variables_are_read_in_the_tools_order() {
        let home = Fixture::new("index-files");
        home.write(
            ".config/pip/pip.conf",
            "[global]\nindex-url = https://mirror.example/pip/simple\nextra-index-url =\n    https://a.example/simple\n    https://b.example/simple\nproxy = http://proxy.example:3128\n",
        );
        let config = index_config(&vars(&[]), Some(&home.root));
        assert_eq!(config.index_url, "https://mirror.example/pip/simple");
        assert_eq!(
            config.extra_index_urls,
            vec!["https://a.example/simple", "https://b.example/simple"]
        );
        assert_eq!(
            config.network.proxy.as_deref(),
            Some("http://proxy.example:3128")
        );

        home.write(
            ".config/uv/uv.toml",
            "[[index]]\nurl = \"https://uv.example/simple\"\ndefault = true\n",
        );
        let config = index_config(&vars(&[]), Some(&home.root));
        assert_eq!(config.index_url, "https://uv.example/simple");

        let config = index_config(
            &vars(&[("PIP_INDEX_URL", "https://env.example/simple")]),
            Some(&home.root),
        );
        assert_eq!(config.index_url, "https://env.example/simple");
        assert_eq!(config.source, "$PIP_INDEX_URL");
        let config = index_config(
            &vars(&[
                ("PIP_INDEX_URL", "https://env.example/simple"),
                ("UV_INDEX_URL", "https://uvenv.example/simple"),
            ]),
            Some(&home.root),
        );
        assert_eq!(config.index_url, "https://uvenv.example/simple");
    }

    #[test]
    fn json_and_html_listings_name_files_with_their_digests() {
        let mut fetcher = FixedFetcher::default();
        fetcher.documents.insert(
            "https://pypi.org/simple/py-socks/".to_string(),
            (
                "application/vnd.pypi.simple.v1+json".to_string(),
                br#"{"files": [{"filename": "PySocks-1.7.1-py3-none-any.whl", "url": "https://files.example/p/PySocks-1.7.1-py3-none-any.whl", "hashes": {"sha256": "ABC"}}, {"filename": "PySocks-1.7.0.tar.gz", "url": "../../p/PySocks-1.7.0.tar.gz", "hashes": {}, "yanked": "broken"}]}"#.to_vec(),
            ),
        );
        let files = project_files(&fetcher, PYPI, "Py_Socks").unwrap();
        assert_eq!(files[0].sha256.as_deref(), Some("abc"));
        assert_eq!(files[1].url, "https://pypi.org/p/PySocks-1.7.0.tar.gz");
        assert!(files[1].yanked);

        let html = r#"<html><body><a href="../../packages/x/idna-3.7-py3-none-any.whl#sha256=DEF" data-requires-python="&gt;=3.5">idna-3.7-py3-none-any.whl</a><br/></body></html>"#;
        let files = parse_html_listing("https://mirror.example/simple/idna/", html);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "idna-3.7-py3-none-any.whl");
        assert_eq!(
            files[0].url,
            "https://mirror.example/packages/x/idna-3.7-py3-none-any.whl"
        );
        assert_eq!(files[0].sha256.as_deref(), Some("def"));
    }
}
