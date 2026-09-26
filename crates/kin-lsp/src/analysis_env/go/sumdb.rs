// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Verified lookups in the Go checksum database.
//!
//! The checksum database (`sum.golang.org` unless `GOSUMDB` names another)
//! is a transparency log of go.sum lines. Every module version it has seen
//! is a record in a Merkle tree, and the database signs the size and root
//! hash of that tree. An answer from it counts here only when every check
//! the go command makes passes:
//!
//! - the tree note carries a valid signature by the configured key;
//! - every tile of stored hashes used is authenticated against the signed
//!   root hash before anything in it is believed;
//! - the authenticated tiles hold the served record's hash at its id, and an
//!   inclusion proof built from them leads to the signed root.
//!
//! The formats and proofs follow RFC 6962 and the go command's
//! `golang.org/x/mod/sumdb` packages (`note`, `tlog` and the client), which
//! this module ports. Tiles have height 8, as the go command reads them.
//!
//! One check of the go command is out of reach: it remembers the newest
//! tree it has seen and proves each later tree extends it, which exposes a
//! database that shows different clients different logs. A lookup here keeps
//! no state between calls, so it proves its answer against the tree the
//! database signs now.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use super::super::fetch::{redact, Fetcher};

/// The go command's built-in verifier key for `sum.golang.org`, the
/// database used when `GOSUMDB` is unset.
pub const DEFAULT_GOSUMDB: &str =
    "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";

/// The tile height the go command reads the database with.
const TILE_HEIGHT: u32 = 8;

/// The size of a SHA-256 hash, the log's only hash.
const HASH_SIZE: usize = 32;

type Hash = [u8; HASH_SIZE];

/// The algorithm byte of an ed25519 verifier key.
const ALG_ED25519: u8 = 1;

/// The first line of a signed tree note.
const TREE_PREFIX: &str = "go.sum database tree\n";

/// How a signature line starts: an em dash and a space.
const SIGNATURE_PREFIX: &str = "\u{2014} ";

/// The largest tree size accepted. The go command allows any int64; a bound
/// far past any real log keeps the index arithmetic clear of overflow.
const MAX_TREE_SIZE: u64 = 1 << 62;

/// A checksum database's public key, parsed from verifier key text of the
/// form `<name>+<key hash>+<key>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierKey {
    /// The database's name, which its signatures carry, such as
    /// `sum.golang.org`.
    pub name: String,
    /// The first four bytes, big endian, of SHA-256 over the name, a newline
    /// and the encoded key. Signatures name their key by it.
    pub hash: u32,
    /// The ed25519 public key.
    pub public_key: [u8; 32],
}

/// Parse a verifier key: the database name, eight hex digits of key hash,
/// and the base64 of an algorithm byte (1, ed25519) followed by the 32-byte
/// public key. The key hash must match the name and key.
pub fn parse_verifier_key(text: &str) -> Result<VerifierKey, String> {
    let malformed = || {
        format!(
            "{:?} is not a verifier key of the form <name>+<key hash>+<key>",
            redact(text)
        )
    };
    let (name, rest) = text.split_once('+').unwrap_or((text, ""));
    let (hash16, key64) = rest.split_once('+').unwrap_or((rest, ""));
    let hash = if hash16.len() == 8 && hash16.bytes().all(|b| b.is_ascii_hexdigit()) {
        u32::from_str_radix(hash16, 16).ok()
    } else {
        None
    };
    let (Some(hash), Some(key)) = (hash, base64_decode(key64)) else {
        return Err(malformed());
    };
    if !is_valid_name(name) || key.is_empty() {
        return Err(malformed());
    }
    if key_hash(name, &key) != hash {
        return Err(format!(
            "the verifier key for {name} gives key hash {hash16}, which does not match its \
             name and key"
        ));
    }
    if key[0] != ALG_ED25519 {
        return Err(format!(
            "the verifier key for {name} uses algorithm {}, and only ed25519 (1) is known",
            key[0]
        ));
    }
    let public_key: [u8; 32] = key[1..].try_into().map_err(|_| malformed())?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| format!("the verifier key for {name} is not an ed25519 public key"))?;
    Ok(VerifierKey {
        name: name.to_string(),
        hash,
        public_key,
    })
}

/// A checksum database to ask: the key its tree notes must be signed with,
/// and where it answers.
#[derive(Clone, PartialEq, Eq)]
pub struct SumDb {
    pub key: VerifierKey,
    /// The base URL that serves `/lookup` and `/tile`, such as
    /// `https://sum.golang.org` or a module proxy's `<proxy>/sumdb/<name>`.
    pub url: String,
}

impl std::fmt::Debug for SumDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SumDb")
            .field("key", &self.key)
            .field("url", &redact(&self.url))
            .finish()
    }
}

/// The database a `GOSUMDB` value names, read the way the go command reads
/// it. `off` turns the database off and gives `None`. `sum.golang.org`, or
/// an empty value, is the built-in key at `https://sum.golang.org`.
/// `sum.golang.google.cn` is the same key at `https://sum.golang.google.cn`.
/// A verifier key alone is that database at `https://<name>`, and a verifier
/// key (or `sum.golang.org`) followed by a URL is that database at the URL.
pub fn from_gosumdb(value: &str) -> Result<Option<SumDb>, String> {
    let value = match value.trim() {
        "" => "sum.golang.org",
        "sum.golang.google.cn" => "sum.golang.org https://sum.golang.google.cn",
        value => value,
    };
    if value == "off" {
        return Ok(None);
    }
    let fields: Vec<&str> = value.split_whitespace().collect();
    if fields.len() > 2 {
        return Err(format!(
            "GOSUMDB {:?} has more than a key and a URL",
            redact_words(value)
        ));
    }
    let key_text = match fields[0] {
        "sum.golang.org" => DEFAULT_GOSUMDB,
        key => key,
    };
    let key = parse_verifier_key(key_text).map_err(|reason| format!("GOSUMDB: {reason}"))?;
    check_database_name(&key.name)?;
    let url = match fields.get(1) {
        Some(url) => database_url(url)?,
        None => format!("https://{}", key.name),
    };
    Ok(Some(SumDb { key, url }))
}

/// One go.sum line: a module, a version (with a `/go.mod` suffix for the
/// hash of the module's go.mod file alone) and a hash such as `h1:...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSumLine {
    pub module: String,
    pub version: String,
    pub hash: String,
}

impl std::fmt::Display for GoSumLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.module, self.version, self.hash)
    }
}

/// Ask `db` for `module` at `version` and return the go.sum lines of the
/// record it proves, both the module's and its go.mod file's. A `/go.mod`
/// suffix on `version` is ignored, since the database keeps both lines in
/// one record.
///
/// The answer counts only once the tree note's signature by `db.key` holds,
/// the tiles it took are authenticated against the signed tree hash, and
/// the record's inclusion in that tree is proven. Any failure, including a
/// proven record with no line for the module version, is an error whose
/// reason names the module version and leaves out any credentials in the
/// database URL.
pub fn lookup(
    fetcher: &dyn Fetcher,
    db: &SumDb,
    module: &str,
    version: &str,
) -> Result<Vec<GoSumLine>, String> {
    let version = version.strip_suffix("/go.mod").unwrap_or(version);
    prove_lookup(fetcher, db, module, version).map_err(|reason| {
        scrub(
            format!(
                "the checksum database {} gave no proven answer for {module}@{version}: {reason}",
                db.key.name
            ),
            &db.url,
        )
    })
}

/// The module-path escaping of the module proxy protocol: each uppercase
/// letter becomes `!` and its lowercase form, so that paths stay distinct on
/// case-insensitive file systems. Versions are escaped the same way.
pub fn escape_path(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            escaped.push('!');
            escaped.push(c.to_ascii_lowercase());
        } else {
            escaped.push(c);
        }
    }
    escaped
}

fn prove_lookup(
    fetcher: &dyn Fetcher,
    db: &SumDb,
    module: &str,
    version: &str,
) -> Result<Vec<GoSumLine>, String> {
    check_module_path(module)?;
    check_version(version)?;
    let base = db.url.trim_end_matches('/');
    let url = format!(
        "{base}/lookup/{}@{}",
        escape_path(module),
        escape_path(version)
    );
    let (_, body) = fetcher
        .document(&url, "*/*")
        .map_err(|error| error.to_string())?;
    let (id, text, note) = parse_record(&body)?;
    let tree = parse_tree(open_note(note, &db.key)?)?;
    if id >= tree.n {
        return Err(format!(
            "the answer is record {id}, which the signed tree of size {} does not hold",
            tree.n
        ));
    }

    let tiles = RemoteTiles {
        fetcher,
        base,
        fetched: Mutex::new(HashMap::new()),
    };
    let reader = TileHashReader {
        tree,
        tiles: &tiles,
    };
    let leaf = record_hash(text.as_bytes());
    let stored = reader.read_hashes(&[stored_hash_index(0, id)])?;
    if stored.first() != Some(&leaf) {
        return Err(format!(
            "the record served is not the record the signed log holds at {id}"
        ));
    }
    // Reading the hash through authenticated tiles proves it already. The
    // inclusion proof, built and checked as tlog does, confirms the same fact
    // a second way from the same tiles.
    let proof = prove_record(tree.n, id, &reader)?;
    check_record(&proof, tree.n, &tree.hash, id, &leaf)?;
    go_sum_lines(text, module, version)
}

/// The record's lines for `module` at `version`, as the go command picks
/// them out: by their `<module> <version> ` or `<module> <version>/go.mod `
/// prefix.
fn go_sum_lines(text: &str, module: &str, version: &str) -> Result<Vec<GoSumLine>, String> {
    let prefixes = [
        format!("{module} {version} "),
        format!("{module} {version}/go.mod "),
    ];
    let mut lines = Vec::new();
    for line in text.lines() {
        if !prefixes
            .iter()
            .any(|prefix| line.starts_with(prefix.as_str()))
        {
            continue;
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let [module, version, hash] = fields[..] else {
            return Err(format!("the proven record has a malformed line {line:?}"));
        };
        if hash.is_empty() {
            return Err(format!("the proven record has a malformed line {line:?}"));
        }
        lines.push(GoSumLine {
            module: module.to_string(),
            version: version.to_string(),
            hash: hash.to_string(),
        });
    }
    if lines.is_empty() {
        return Err(format!(
            "the proven record holds no go.sum line for {module}@{version}"
        ));
    }
    Ok(lines)
}

/// `reason` with the credentials of `url`, if it has any, masked wherever
/// they appear, whatever the fetcher put in its error.
fn scrub(reason: String, url: &str) -> String {
    let Some((_, rest)) = url.split_once("://") else {
        return reason;
    };
    let authority = &rest[..rest.find('/').unwrap_or(rest.len())];
    match authority.rfind('@') {
        Some(at) if at > 0 => reason.replace(&authority[..=at], "***@"),
        _ => reason,
    }
}

/// Every URL-looking word of `text` redacted, for echoing a `GOSUMDB` value.
fn redact_words(text: &str) -> String {
    text.split_whitespace()
        .map(redact)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a database name is a host with an optional path, as the go
/// command requires, so that `https://<name>` is the URL it looks like.
fn check_database_name(name: &str) -> Result<(), String> {
    let (host, path) = name.split_once('/').unwrap_or((name, ""));
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    let path_ok = !name.ends_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~' | b'/'));
    if host_ok && path_ok {
        Ok(())
    } else {
        Err(format!(
            "GOSUMDB names the database {name:?}, which is not a host with an optional path"
        ))
    }
}

/// The base URL `GOSUMDB` gives for its database, without a trailing slash.
fn database_url(text: &str) -> Result<String, String> {
    let rest = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"));
    let has_host = rest.is_some_and(|rest| {
        let authority = &rest[..rest.find('/').unwrap_or(rest.len())];
        !authority.is_empty() && !authority.ends_with('@')
    });
    if !has_host || text.contains(['?', '#']) {
        return Err(format!(
            "GOSUMDB gives {} as the database URL, which is not an http or https URL",
            redact(text)
        ));
    }
    Ok(text.trim_end_matches('/').to_string())
}

/// The character rules of the go command's `module.CheckPath`, which it
/// applies before it escapes a path into a lookup URL.
fn check_module_path(path: &str) -> Result<(), String> {
    let invalid = |why: &str| Err(format!("{path:?} is not a module path: {why}"));
    if path.starts_with('-') {
        return invalid("it starts with a dash");
    }
    for element in path.split('/') {
        if element.is_empty() {
            return invalid("it has an empty path element");
        }
        if element.bytes().all(|b| b == b'.') || element.starts_with('.') {
            return invalid("a path element starts with a dot");
        }
        if element.ends_with('.') {
            return invalid("a path element ends with a dot");
        }
        if !element
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            return invalid("it has a character a module path cannot hold");
        }
    }
    let first = path.split('/').next().unwrap_or_default();
    if !first.contains('.') {
        return invalid("its first path element has no dot");
    }
    if !first
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
    {
        return invalid("its first path element has a character a host name cannot hold");
    }
    Ok(())
}

/// Whether `version` is safe to place in a lookup URL. Module versions are
/// semantic versions, so letters, digits and `-._+~` cover every real one.
fn check_version(version: &str) -> Result<(), String> {
    let ok = !version.is_empty()
        && !version.bytes().all(|b| b == b'.')
        && !version.ends_with('.')
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'+' | b'~'));
    if ok {
        Ok(())
    } else {
        Err(format!("{version:?} is not a module version"))
    }
}

// Signed notes, as golang.org/x/mod/sumdb/note defines them.

/// A key's hash: the first four bytes of SHA-256 over the name, a newline
/// and the encoded key (algorithm byte included).
fn key_hash(name: &str, key: &[u8]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update(key);
    let sum = hasher.finalize();
    u32::from_be_bytes([sum[0], sum[1], sum[2], sum[3]])
}

/// A signer name is non-empty, without spaces or `+`.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(char::is_whitespace) && !name.contains('+')
}

/// Open a signed note and return its text once a signature by `key` on it
/// holds. Signatures by other keys, such as witness cosignatures, are
/// skipped; a signature by `key` that does not verify fails the note.
fn open_note<'a>(msg: &'a [u8], key: &VerifierKey) -> Result<&'a str, String> {
    let malformed = || "the signed tree note is malformed".to_string();
    let msg = std::str::from_utf8(msg).map_err(|_| malformed())?;
    if msg.chars().any(|c| c < ' ' && c != '\n') {
        return Err(malformed());
    }
    // The signatures follow the last blank line; the text keeps its final
    // newline.
    let split = msg.rfind("\n\n").ok_or_else(malformed)?;
    let (text, signatures) = (&msg[..split + 1], &msg[split + 2..]);
    let Some(signatures) = signatures.strip_suffix('\n') else {
        return Err(malformed());
    };
    let verifying = VerifyingKey::from_bytes(&key.public_key)
        .map_err(|_| format!("the key for {} is not an ed25519 public key", key.name))?;

    let mut verified = false;
    for (count, line) in signatures.split('\n').enumerate() {
        if count >= 100 {
            return Err(malformed());
        }
        let line = line.strip_prefix(SIGNATURE_PREFIX).ok_or_else(malformed)?;
        let (name, encoded) = line.split_once(' ').unwrap_or((line, ""));
        let signature = base64_decode(encoded).ok_or_else(malformed)?;
        if !is_valid_name(name) || encoded.is_empty() || signature.len() < 5 {
            return Err(malformed());
        }
        let hash = u32::from_be_bytes([signature[0], signature[1], signature[2], signature[3]]);
        if name != key.name || hash != key.hash || verified {
            continue;
        }
        let bytes: [u8; 64] = signature[4..]
            .try_into()
            .map_err(|_| format!("the signature by {} on the tree note is invalid", key.name))?;
        // Cofactorless verification with a canonical S, as Go's
        // crypto/ed25519 verifies.
        verifying
            .verify(text.as_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| format!("the signature by {} on the tree note is invalid", key.name))?;
        verified = true;
    }
    if !verified {
        return Err(format!(
            "the tree note carries no signature by {}'s key {:08x}",
            key.name, key.hash
        ));
    }
    Ok(text)
}

// Records and trees, as golang.org/x/mod/sumdb/tlog formats them.

/// A signed tree: its size and root hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tree {
    n: u64,
    hash: Hash,
}

/// Parse `go.sum database tree\n<N>\n<base64 hash>\n`. Lines after those
/// three are allowed for forward compatibility and ignored.
fn parse_tree(text: &str) -> Result<Tree, String> {
    let malformed = || "the signed tree note is not a go.sum database tree".to_string();
    if !text.starts_with(TREE_PREFIX) || text.matches('\n').count() < 3 || text.len() > 1_000_000 {
        return Err(malformed());
    }
    let mut lines = text.splitn(4, '\n').skip(1);
    let n = lines
        .next()
        .and_then(parse_decimal)
        .filter(|&n| n <= MAX_TREE_SIZE)
        .ok_or_else(malformed)?;
    let hash = lines
        .next()
        .and_then(base64_decode)
        .and_then(|bytes| Hash::try_from(bytes.as_slice()).ok())
        .ok_or_else(malformed)?;
    Ok(Tree { n, hash })
}

/// Split a lookup answer into its record id, the record text (with its final
/// newline) and the signed tree note after the blank line that ends it.
fn parse_record(msg: &[u8]) -> Result<(u64, &str, &[u8]), String> {
    let malformed = || "the answer is not a record followed by a signed tree".to_string();
    let newline = msg.iter().position(|&b| b == b'\n').ok_or_else(malformed)?;
    let id = std::str::from_utf8(&msg[..newline])
        .ok()
        .and_then(parse_decimal)
        .ok_or_else(malformed)?;
    let msg = &msg[newline + 1..];
    let end = msg
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or_else(malformed)?;
    let (text, rest) = (&msg[..end + 1], &msg[end + 2..]);
    let text = std::str::from_utf8(text).map_err(|_| malformed())?;
    if !is_valid_record_text(text) {
        return Err(malformed());
    }
    Ok((id, text, rest))
}

/// Record text is lines of printable text, each ending in a newline, with no
/// blank line.
fn is_valid_record_text(text: &str) -> bool {
    text.ends_with('\n') && !text.contains("\n\n") && !text.chars().any(|c| c < ' ' && c != '\n')
}

/// A canonical decimal number: digits only, no sign, no leading zero.
fn parse_decimal(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    canonical.then(|| text.parse().ok()).flatten()
}

// The tree, as RFC 6962 and golang.org/x/mod/sumdb/tlog hash it.

/// A record's hash: SHA-256 of a zero byte and the record.
fn record_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&hasher.finalize());
    hash
}

/// An interior node's hash: SHA-256 of a one byte and its children.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&hasher.finalize());
    hash
}

/// The largest power of two smaller than `n`, and its logarithm (1 and 0
/// when `n` is 1 or less).
fn max_pow2(n: u64) -> (u64, u32) {
    let mut level = 0;
    while 1u64 << (level + 1) < n {
        level += 1;
    }
    (1 << level, level)
}

/// Where the hash of node `n` at `level` sits in the log's dense storage
/// order, in which level L's n'th hash follows level L+1's (2n+1)'th.
fn stored_hash_index(level: u32, n: u64) -> u64 {
    let mut n = n;
    for _ in 0..level {
        n = 2 * n + 1;
    }
    let mut index = 0;
    while n > 0 {
        index += n;
        n >>= 1;
    }
    index + u64::from(level)
}

/// The inverse of [`stored_hash_index`]: the level and node a storage index
/// holds.
fn split_stored_hash_index(index: u64) -> (u32, u64) {
    // Record n's hashes start below 2n, so the record that wrote this index
    // is at most log2(index) past index/2.
    let mut n = index / 2;
    let mut index_n = stored_hash_index(0, n);
    loop {
        // Each record n adds 1 + trailing_zeros(n + 1) hashes.
        let next = index_n + 1 + u64::from((n + 1).trailing_zeros());
        if next > index {
            break;
        }
        n += 1;
        index_n = next;
    }
    let level = (index - index_n) as u32;
    (level, n >> level)
}

/// Read access to stored hashes by storage index.
trait HashReader {
    /// The hashes at `indexes`, one for each, in order.
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, String>;
}

/// Append the storage indexes of the complete subtrees that make up records
/// `[lo, hi)`, largest first.
fn sub_tree_index(lo: u64, hi: u64, need: &mut Vec<u64>) {
    let mut lo = lo;
    while lo < hi {
        let (k, level) = max_pow2(hi - lo + 1);
        need.push(stored_hash_index(level, lo >> level));
        lo += k;
    }
}

/// The hash of records `[lo, hi)` from the hashes of the subtrees
/// [`sub_tree_index`] names, and the hashes left over.
fn sub_tree_hash(lo: u64, hi: u64, hashes: &[Hash]) -> Result<(Hash, &[Hash]), String> {
    let mut count = 0;
    let mut at = lo;
    while at < hi {
        at += max_pow2(hi - at + 1).0;
        count += 1;
    }
    if count == 0 || hashes.len() < count {
        return Err(format!("too few hashes for the subtree [{lo}, {hi})"));
    }
    let mut hash = hashes[count - 1];
    for left in hashes[..count - 1].iter().rev() {
        hash = node_hash(left, &hash);
    }
    Ok((hash, &hashes[count..]))
}

/// The storage indexes needed to prove record `n` is in records `[lo, hi)`.
fn leaf_proof_index(lo: u64, hi: u64, n: u64, need: &mut Vec<u64>) {
    if lo + 1 == hi {
        return;
    }
    let (k, _) = max_pow2(hi - lo);
    if n < lo + k {
        leaf_proof_index(lo, lo + k, n, need);
        sub_tree_index(lo + k, hi, need);
    } else {
        sub_tree_index(lo, lo + k, need);
        leaf_proof_index(lo + k, hi, n, need);
    }
}

/// The proof that record `n` is in records `[lo, hi)`, from the hashes
/// [`leaf_proof_index`] names, and the hashes left over.
fn leaf_proof(lo: u64, hi: u64, n: u64, hashes: &[Hash]) -> Result<(Vec<Hash>, &[Hash]), String> {
    if lo + 1 == hi {
        return Ok((Vec::new(), hashes));
    }
    let (k, _) = max_pow2(hi - lo);
    let (mut proof, sibling, rest) = if n < lo + k {
        let (proof, rest) = leaf_proof(lo, lo + k, n, hashes)?;
        let (sibling, rest) = sub_tree_hash(lo + k, hi, rest)?;
        (proof, sibling, rest)
    } else {
        let (sibling, rest) = sub_tree_hash(lo, lo + k, hashes)?;
        let (proof, rest) = leaf_proof(lo + k, hi, n, rest)?;
        (proof, sibling, rest)
    };
    proof.push(sibling);
    Ok((proof, rest))
}

/// The inclusion proof (RFC 6962's audit path) that the tree of size `t`
/// holds record `n`.
fn prove_record(t: u64, n: u64, reader: &dyn HashReader) -> Result<Vec<Hash>, String> {
    if n >= t {
        return Err(format!("record {n} is not in a tree of size {t}"));
    }
    let mut indexes = Vec::new();
    leaf_proof_index(0, t, n, &mut indexes);
    if indexes.is_empty() {
        return Ok(Vec::new());
    }
    let hashes = reader.read_hashes(&indexes)?;
    if hashes.len() != indexes.len() {
        return Err(format!(
            "read {} hashes for {} indexes",
            hashes.len(),
            indexes.len()
        ));
    }
    let (proof, rest) = leaf_proof(0, t, n, &hashes)?;
    if !rest.is_empty() {
        return Err("the proof left hashes unused".to_string());
    }
    Ok(proof)
}

/// Check that `proof` shows the tree of size `t` with root `root` holds a
/// record `n` with hash `leaf`.
fn check_record(proof: &[Hash], t: u64, root: &Hash, n: u64, leaf: &Hash) -> Result<(), String> {
    if n >= t {
        return Err(format!("record {n} is not in a tree of size {t}"));
    }
    if run_record_proof(proof, 0, t, n, leaf)? == *root {
        Ok(())
    } else {
        Err(format!(
            "the inclusion proof of record {n} does not lead to the signed tree hash"
        ))
    }
}

/// The hash of records `[lo, hi)` that `proof` implies for record `n` with
/// hash `leaf`.
fn run_record_proof(proof: &[Hash], lo: u64, hi: u64, n: u64, leaf: &Hash) -> Result<Hash, String> {
    let failed = || format!("the inclusion proof of record {n} is malformed");
    if lo + 1 == hi {
        return if proof.is_empty() {
            Ok(*leaf)
        } else {
            Err(failed())
        };
    }
    let (sibling, rest) = proof.split_last().ok_or_else(failed)?;
    let (k, _) = max_pow2(hi - lo);
    if n < lo + k {
        let left = run_record_proof(rest, lo, lo + k, n, leaf)?;
        Ok(node_hash(&left, sibling))
    } else {
        let right = run_record_proof(rest, lo + k, hi, n, leaf)?;
        Ok(node_hash(sibling, &right))
    }
}

// Tiles, as golang.org/x/mod/sumdb/tlog lays them out.

/// A tile of height `h` at level `l`, number `n`: `w` consecutive hashes at
/// tree level `h * l`, starting at node `n << h`. A complete tile has
/// `1 << h` hashes; a partial one has fewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Tile {
    h: u32,
    l: u32,
    n: u64,
    w: u64,
}

impl Tile {
    /// The tile's path, `tile/<H>/<L>/<N>` with `N` in groups of three
    /// digits (`x001/x234/067`) and `.p/<W>` after a partial tile.
    fn path(&self) -> String {
        let mut n = self.n;
        let mut number = format!("{:03}", n % 1000);
        while n >= 1000 {
            n /= 1000;
            number = format!("x{:03}/{number}", n % 1000);
        }
        let partial = if self.w == 1 << self.h {
            String::new()
        } else {
            format!(".p/{}", self.w)
        };
        format!("tile/{}/{}/{number}{partial}", self.h, self.l)
    }
}

/// The narrowest tile of height `h` that stores hash `index`, and the byte
/// range within its data whose tile hash is that hash.
fn tile_for_index(h: u32, index: u64) -> (Tile, usize, usize) {
    let (level, n) = split_stored_hash_index(index);
    let l = level / h;
    let level = level - l * h;
    let tile_n = (n << level) >> h;
    let within = n - ((tile_n << h) >> level);
    let tile = Tile {
        h,
        l,
        n: tile_n,
        w: (within + 1) << level,
    };
    let start = (within << level) as usize * HASH_SIZE;
    let end = ((within + 1) << level) as usize * HASH_SIZE;
    (tile, start, end)
}

/// The hash at `index`, from the data of tile `t`, which must be the tile
/// [`tile_for_index`] names or a wider one.
fn hash_from_tile(t: &Tile, data: &[u8], index: u64) -> Result<Hash, String> {
    if t.h < 1 || t.h > 30 || t.l >= 64 || t.w < 1 || t.w > 1 << t.h {
        return Err(format!("{} is not a valid tile", t.path()));
    }
    if data.len() < t.w as usize * HASH_SIZE {
        return Err(format!("{} is too short", t.path()));
    }
    let (wanted, start, end) = tile_for_index(t.h, index);
    if t.l != wanted.l || t.n != wanted.n || t.w < wanted.w {
        return Err(format!(
            "hash {index} is in {}, not {}",
            wanted.path(),
            t.path()
        ));
    }
    Ok(tile_hash(&data[start..end]))
}

/// The hash of the subtree whose leaves are the hashes in `data`, a power
/// of two of them.
fn tile_hash(data: &[u8]) -> Hash {
    if data.len() <= HASH_SIZE {
        let mut hash = [0u8; HASH_SIZE];
        hash[..data.len()].copy_from_slice(data);
        return hash;
    }
    let half = data.len() / 2;
    node_hash(&tile_hash(&data[..half]), &tile_hash(&data[half..]))
}

/// Tile `t`'s `k`th parent among the tiles of a tree of size `size`, with
/// the width the tree gives it, or `None` past the top of the tree.
fn tile_parent(t: Tile, k: u32, size: u64) -> Option<Tile> {
    let l = t.l + k;
    let n = t.n.checked_shr(k * t.h).unwrap_or(0);
    let mut w = 1u64 << t.h;
    let max = size.checked_shr(l * t.h).unwrap_or(0);
    if (n << t.h) + w >= max {
        if n << t.h >= max {
            return None;
        }
        w = max - (n << t.h);
    }
    Some(Tile { h: t.h, l, n, w })
}

/// A source of tile data, trusted for nothing.
trait TileReader {
    fn height(&self) -> u32;

    /// The data of each tile, in order.
    fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, String>;
}

/// Hashes read from tiles, each tile authenticated against a signed tree
/// before any hash in it is returned, as `tlog.TileHashReader` does.
struct TileHashReader<'a> {
    tree: Tree,
    tiles: &'a dyn TileReader,
}

impl HashReader for TileHashReader<'_> {
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, String> {
        let h = self.tiles.height();
        let size = self.tree.n;
        let lost = |what: String| format!("internal error in the tiles of tree {size}: {what}");

        let mut tile_order: HashMap<Tile, usize> = HashMap::new();
        let mut tiles: Vec<Tile> = Vec::new();

        // First the tiles holding the hashes the tree hash is computed from.
        // When the tree hash they give is the signed one, they are authentic.
        let mut stx = Vec::new();
        sub_tree_index(0, size, &mut stx);
        if stx.is_empty() {
            return Err("the signed tree is empty".to_string());
        }
        let mut stx_tile_order = Vec::with_capacity(stx.len());
        for &x in &stx {
            let tile = tile_parent(tile_for_index(h, x).0, 0, size)
                .ok_or_else(|| lost(format!("no tile holds hash {x}")))?;
            let position = *tile_order.entry(tile).or_insert_with(|| {
                tiles.push(tile);
                tiles.len() - 1
            });
            stx_tile_order.push(position);
        }
        let stx_tiles = tiles.len();

        // Then the tiles holding the requested hashes, each after the
        // parents that authenticate it, up to one already planned.
        let mut index_tile_order = Vec::with_capacity(indexes.len());
        let limit = stored_hash_index(0, size);
        for &x in indexes {
            if x >= limit {
                return Err(format!("hash {x} is not in a tree of size {size}"));
            }
            let tile = tile_for_index(h, x).0;
            let mut k = 0;
            let mut position = loop {
                let parent = tile_parent(tile, k, size)
                    .ok_or_else(|| lost(format!("hash {x} has no planned ancestor tile")))?;
                if let Some(&j) = tile_order.get(&parent) {
                    break j;
                }
                k += 1;
            };
            while k > 0 {
                k -= 1;
                let parent = tile_parent(tile, k, size)
                    .ok_or_else(|| lost(format!("hash {x} lost a tile")))?;
                if parent.w != 1 << parent.h {
                    // Only complete tiles have parents.
                    return Err(lost(format!("{} is partial", parent.path())));
                }
                tile_order.insert(parent, tiles.len());
                position = tiles.len();
                tiles.push(parent);
            }
            index_tile_order.push(position);
        }

        let data = self.tiles.read_tiles(&tiles)?;
        if data.len() != tiles.len() {
            return Err(lost(format!(
                "read {} tiles of {}",
                data.len(),
                tiles.len()
            )));
        }
        for (tile, bytes) in tiles.iter().zip(&data) {
            if bytes.len() as u64 != tile.w * HASH_SIZE as u64 {
                return Err(format!(
                    "{} is {} bytes, not {}",
                    tile.path(),
                    bytes.len(),
                    tile.w * HASH_SIZE as u64
                ));
            }
        }

        // Authenticate the tiles the tree hash comes from.
        let mut tree_hash: Option<Hash> = None;
        for (&x, &j) in stx.iter().zip(&stx_tile_order).rev() {
            let hash = hash_from_tile(&tiles[j], &data[j], x)?;
            tree_hash = Some(match tree_hash {
                None => hash,
                Some(right) => node_hash(&hash, &right),
            });
        }
        if tree_hash != Some(self.tree.hash) {
            return Err(
                "the tiles served do not add up to the signed tree hash, so at least one \
                 was tampered with"
                    .to_string(),
            );
        }

        // Authenticate every other tile against its parent, which comes
        // before it and so is authenticated already.
        for (tile, bytes) in tiles.iter().zip(&data).skip(stx_tiles) {
            let parent = tile_parent(*tile, 1, size)
                .ok_or_else(|| lost(format!("{} has no parent", tile.path())))?;
            let &j = tile_order
                .get(&parent)
                .ok_or_else(|| lost(format!("{} lost its parent", tile.path())))?;
            let expected = hash_from_tile(
                &parent,
                &data[j],
                stored_hash_index(parent.l * parent.h, tile.n),
            )?;
            if tile_hash(bytes) != expected {
                return Err(format!(
                    "{} as served does not match the hash its parent tile holds for it",
                    tile.path()
                ));
            }
        }

        indexes
            .iter()
            .zip(&index_tile_order)
            .map(|(&x, &j)| hash_from_tile(&tiles[j], &data[j], x))
            .collect()
    }
}

/// Tiles fetched from a database, kept for the rest of one lookup so its
/// proof reuses what authentication fetched. Keeping a tile trusts nothing:
/// every read authenticates the tiles it uses again.
struct RemoteTiles<'a> {
    fetcher: &'a dyn Fetcher,
    base: &'a str,
    fetched: Mutex<HashMap<Tile, Vec<u8>>>,
}

impl RemoteTiles<'_> {
    /// Fetch one tile. A partial tile the database no longer serves is the
    /// start of the complete tile it grew into, so that is tried next, as
    /// the go command does.
    fn read_tile(&self, tile: Tile) -> Result<Vec<u8>, String> {
        let error = match self
            .fetcher
            .document(&format!("{}/{}", self.base, tile.path()), "*/*")
        {
            Ok((_, data)) => return Ok(data),
            Err(error) => error,
        };
        let full = Tile {
            w: 1 << tile.h,
            ..tile
        };
        if full != tile {
            if let Ok((_, mut data)) = self
                .fetcher
                .document(&format!("{}/{}", self.base, full.path()), "*/*")
            {
                if data.len() as u64 == full.w * HASH_SIZE as u64 {
                    data.truncate(tile.w as usize * HASH_SIZE);
                }
                return Ok(data);
            }
        }
        Err(format!("could not fetch {}: {error}", tile.path()))
    }
}

impl TileReader for RemoteTiles<'_> {
    fn height(&self) -> u32 {
        TILE_HEIGHT
    }

    fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, String> {
        let missing: Vec<Tile> = {
            let fetched = self.fetched.lock().unwrap_or_else(|p| p.into_inner());
            tiles
                .iter()
                .filter(|tile| !fetched.contains_key(tile))
                .copied()
                .collect()
        };
        // Fetch in parallel, as the go command does: a lookup needs a few
        // tiles per level of the tree.
        let results: Vec<(Tile, Result<Vec<u8>, String>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = missing
                .iter()
                .map(|&tile| (tile, scope.spawn(move || self.read_tile(tile))))
                .collect();
            handles
                .into_iter()
                .map(|(tile, handle)| {
                    let result = handle
                        .join()
                        .unwrap_or_else(|_| Err(format!("fetching {} failed", tile.path())));
                    (tile, result)
                })
                .collect()
        });
        let mut fetched = self.fetched.lock().unwrap_or_else(|p| p.into_inner());
        for (tile, result) in results {
            fetched.insert(tile, result?);
        }
        tiles
            .iter()
            .map(|tile| {
                fetched
                    .get(tile)
                    .cloned()
                    .ok_or_else(|| format!("{} was not fetched", tile.path()))
            })
            .collect()
    }
}

// Base64, the standard alphabet with padding, decoded as Go's
// base64.StdEncoding decodes it.

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        Some(u32::from(value))
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let groups = bytes.len() / 4;
    let mut out = Vec::with_capacity(groups * 3);
    for (i, group) in bytes.chunks(4).enumerate() {
        let padding = group.iter().rev().take_while(|&&c| c == b'=').count();
        if padding > 2 || (padding > 0 && i + 1 != groups) {
            return None;
        }
        let mut value = 0u32;
        for &c in &group[..4 - padding] {
            value = (value << 6) | sextet(c)?;
        }
        value <<= 6 * padding as u32;
        out.push((value >> 16) as u8);
        if padding < 2 {
            out.push((value >> 8) as u8);
        }
        if padding < 1 {
            out.push(value as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::contract::hex;
    use crate::analysis_env::fetch::testing::FixedFetcher;
    use ed25519_dalek::{Signer, SigningKey};

    // Test support: the writing side of the log, ported from tlog as well.

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn base64_encode(bytes: &[u8]) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let value = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(
                        ALPHABET[((value >> (18 - 6 * i)) & 63) as usize],
                    ));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    impl HashReader for Vec<Hash> {
        fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, String> {
            Ok(indexes.iter().map(|&i| self[i as usize]).collect())
        }
    }

    /// The hashes to store when record `n` is added: its own and those of
    /// the subtrees it completes.
    fn stored_hashes(n: u64, data: &[u8], storage: &[Hash]) -> Vec<Hash> {
        let mut hash = record_hash(data);
        let mut hashes = vec![hash];
        for level in 0..(n + 1).trailing_zeros() {
            let left = storage[stored_hash_index(level, (n >> level) - 1) as usize];
            hash = node_hash(&left, &hash);
            hashes.push(hash);
        }
        hashes
    }

    fn tree_hash(n: u64, reader: &dyn HashReader) -> Hash {
        if n == 0 {
            let mut empty = [0u8; HASH_SIZE];
            empty.copy_from_slice(&Sha256::digest(b""));
            return empty;
        }
        let mut indexes = Vec::new();
        sub_tree_index(0, n, &mut indexes);
        let hashes = reader.read_hashes(&indexes).unwrap();
        let (hash, rest) = sub_tree_hash(0, n, &hashes).unwrap();
        assert!(rest.is_empty());
        hash
    }

    fn read_tile_data(tile: Tile, storage: &[Hash]) -> Vec<u8> {
        let start = tile.n << tile.h;
        (0..tile.w)
            .flat_map(|i| storage[stored_hash_index(tile.h * tile.l, start + i) as usize])
            .collect()
    }

    /// Every tile a database of `size` records publishes: the complete ones
    /// and the partial one at the end of each level.
    fn published_tiles(h: u32, size: u64) -> Vec<Tile> {
        let mut tiles = Vec::new();
        let mut l = 0;
        while size >> (h * l) > 0 {
            let count = size >> (h * l);
            for n in 0..count >> h {
                tiles.push(Tile { h, l, n, w: 1 << h });
            }
            let w = count - ((count >> h) << h);
            if w > 0 {
                tiles.push(Tile {
                    h,
                    l,
                    n: count >> h,
                    w,
                });
            }
            l += 1;
        }
        tiles
    }

    #[derive(Default)]
    struct Log {
        hashes: Vec<Hash>,
        size: u64,
    }

    impl Log {
        fn add(&mut self, data: &[u8]) {
            let new = stored_hashes(self.size, data, &self.hashes);
            self.hashes.extend(new);
            self.size += 1;
        }

        fn tree(&self) -> Tree {
            Tree {
                n: self.size,
                hash: tree_hash(self.size, &self.hashes),
            }
        }
    }

    /// Tiles served from memory, optionally with the hash at one storage
    /// index zeroed (or the hashes it is computed from, when it is not in
    /// a tile's bottom row), as tlog's own tests tamper with tiles.
    struct MemoryTiles<'a> {
        h: u32,
        hashes: &'a [Hash],
        zeroed: Option<u64>,
    }

    impl TileReader for MemoryTiles<'_> {
        fn height(&self) -> u32 {
            self.h
        }

        fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, String> {
            Ok(tiles
                .iter()
                .map(|&tile| {
                    let mut data = read_tile_data(tile, self.hashes);
                    if let Some(index) = self.zeroed {
                        let (target, start, end) = tile_for_index(self.h, index);
                        if (tile.h, tile.l, tile.n) == (target.h, target.l, target.n)
                            && end <= data.len()
                        {
                            data[start..end].fill(0);
                        }
                    }
                    data
                })
                .collect())
        }
    }

    fn b64(hash: &Hash) -> String {
        base64_encode(hash)
    }

    fn leaf_log(size: u64) -> Log {
        let mut log = Log::default();
        for i in 0..size {
            log.add(format!("leaf {i}").as_bytes());
        }
        log
    }

    // A synthetic database, signed with a key from a fixed seed.

    const NAME: &str = "sum.example";
    const URL: &str = "https://sum.example";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&std::array::from_fn(|i| i as u8))
    }

    fn encoded_key(signing: &SigningKey) -> Vec<u8> {
        let mut encoded = vec![ALG_ED25519];
        encoded.extend_from_slice(signing.verifying_key().as_bytes());
        encoded
    }

    fn verifier_key_text(name: &str, signing: &SigningKey) -> String {
        let encoded = encoded_key(signing);
        format!(
            "{name}+{:08x}+{}",
            key_hash(name, &encoded),
            base64_encode(&encoded)
        )
    }

    fn signature_line(text: &str, name: &str, signing: &SigningKey) -> String {
        let mut signature = key_hash(name, &encoded_key(signing)).to_be_bytes().to_vec();
        signature.extend_from_slice(&signing.sign(text.as_bytes()).to_bytes());
        format!("{SIGNATURE_PREFIX}{name} {}\n", base64_encode(&signature))
    }

    fn format_tree(tree: &Tree) -> String {
        format!("{TREE_PREFIX}{}\n{}\n", tree.n, b64(&tree.hash))
    }

    struct Record {
        module: String,
        version: String,
        text: String,
    }

    fn record(i: u64) -> Record {
        let module = format!("github.com/Example/m{i}");
        let version = format!("v1.0.{i}");
        let zip = base64_encode(&Sha256::digest(format!("zip {i}")));
        let mod_file = base64_encode(&Sha256::digest(format!("mod {i}")));
        let text =
            format!("{module} {version} h1:{zip}\n{module} {version}/go.mod h1:{mod_file}\n");
        Record {
            module,
            version,
            text,
        }
    }

    fn lookup_url(record: &Record) -> String {
        format!(
            "{URL}/lookup/{}@{}",
            escape_path(&record.module),
            escape_path(&record.version)
        )
    }

    fn tile_url(tile: &Tile) -> String {
        format!("{URL}/{}", tile.path())
    }

    struct Fixture {
        fetcher: FixedFetcher,
        db: SumDb,
        records: Vec<Record>,
        tree: Tree,
        note: String,
    }

    impl Fixture {
        fn new(size: u64) -> Self {
            let signing = signing_key();
            let records: Vec<Record> = (0..size).map(record).collect();
            let mut log = Log::default();
            for record in &records {
                log.add(record.text.as_bytes());
            }
            let tree = log.tree();
            let text = format_tree(&tree);
            let note = format!("{text}\n{}", signature_line(&text, NAME, &signing));
            let mut fixture = Fixture {
                fetcher: FixedFetcher::default(),
                db: SumDb {
                    key: parse_verifier_key(&verifier_key_text(NAME, &signing)).unwrap(),
                    url: URL.to_string(),
                },
                records,
                tree,
                note,
            };
            for id in 0..size {
                let note = fixture.note.clone();
                fixture.serve(id, id, &note);
            }
            for tile in published_tiles(TILE_HEIGHT, size) {
                fixture.fetcher.documents.insert(
                    tile_url(&tile),
                    (
                        "application/octet-stream".to_string(),
                        read_tile_data(tile, &log.hashes),
                    ),
                );
            }
            fixture
        }

        /// Answer the lookup for record `id` with record `claimed_id` and
        /// `note`.
        fn serve(&mut self, id: u64, claimed_id: u64, note: &str) {
            let record = &self.records[id as usize];
            let body = format!("{claimed_id}\n{}\n{note}", record.text);
            self.fetcher.documents.insert(
                lookup_url(record),
                ("text/plain; charset=utf-8".to_string(), body.into_bytes()),
            );
        }

        fn lookup(&self, id: u64) -> Result<Vec<GoSumLine>, String> {
            let record = &self.records[id as usize];
            lookup(&self.fetcher, &self.db, &record.module, &record.version)
        }

        fn tamper_tile(&mut self, path: &str, byte: usize) {
            let (_, data) = self
                .fetcher
                .documents
                .get_mut(&format!("{URL}/{path}"))
                .unwrap_or_else(|| panic!("no tile {path}"));
            data[byte] ^= 1;
        }

        fn requests(&self) -> Vec<String> {
            self.fetcher.requests.lock().unwrap().clone()
        }
    }

    fn assert_proven(fixture: &Fixture, id: u64) {
        let record = &fixture.records[id as usize];
        let lines = fixture
            .lookup(id)
            .unwrap_or_else(|reason| panic!("record {id}: {reason}"));
        let rendered: Vec<String> = lines.iter().map(ToString::to_string).collect();
        let expected: Vec<&str> = record.text.lines().collect();
        assert_eq!(rendered, expected, "record {id}");
        assert_eq!(lines[1].version, format!("{}/go.mod", record.version));
    }

    // Known answers, reproduced with golang.org/x/mod's own sumdb packages.

    #[test]
    fn the_default_key_is_sum_golang_org() {
        let key = parse_verifier_key(DEFAULT_GOSUMDB).unwrap();
        assert_eq!(key.name, "sum.golang.org");
        assert_eq!(key.hash, 0x033de0ae);
        assert_eq!(
            hex(&key.public_key),
            hex(&base64_decode("Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8").unwrap()[1..])
        );
    }

    #[test]
    fn verifier_keys_match_go_for_a_fixed_seed() {
        // note.NewEd25519VerifierKey("sum.example", <key from seed 0..31>).
        let go = "sum.example+da89a45e+AQOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
        let signing = signing_key();
        assert_eq!(verifier_key_text(NAME, &signing), go);
        let key = parse_verifier_key(go).unwrap();
        assert_eq!(key.name, NAME);
        assert_eq!(key.hash, 0xda89a45e);
        assert_eq!(&key.public_key, signing.verifying_key().as_bytes());
    }

    #[test]
    fn malformed_verifier_keys_are_refused() {
        let good = verifier_key_text(NAME, &signing_key());
        let (_, key64) = good.rsplit_once('+').unwrap();
        for bad in [
            String::new(),
            "sum.example".to_string(),
            "sum.example+da89a45e".to_string(),
            format!("sum.example+da89a45+{key64}"),
            format!("sum.example++da89a45e+{key64}"),
            format!("sum.example+da89a45f+{key64}"),
            format!("sum.example+DA89A45E+{key64}x"),
            format!("sum example+da89a45e+{key64}"),
            format!("other.example+da89a45e+{key64}"),
            // A mistyped default key: not base64, so not a key.
            "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ki2V4BN+hG1y0Y".to_string(),
        ] {
            assert!(parse_verifier_key(&bad).is_err(), "{bad:?}");
        }
        // Hex digits in either case, as Go's ParseUint reads them.
        let upper = good.replace("da89a45e", "DA89A45E");
        assert_eq!(
            parse_verifier_key(&upper).unwrap(),
            parse_verifier_key(&good).unwrap()
        );
        // An algorithm other than ed25519.
        let mut encoded = encoded_key(&signing_key());
        encoded[0] = 2;
        let other = format!(
            "{NAME}+{:08x}+{}",
            key_hash(NAME, &encoded),
            base64_encode(&encoded)
        );
        assert!(parse_verifier_key(&other)
            .unwrap_err()
            .contains("algorithm 2"));
    }

    #[test]
    fn a_go_signed_note_matches_and_opens() {
        // note.Sign over tlog.FormatTree for the 600-record "leaf %d" log.
        let go = "go.sum database tree\n600\nYeW3m0rrRtdF0jKp4Z6FF/MaCPW/wHpHSqW4KrWAG9o=\n\n\
                  \u{2014} sum.example 2omkXrz2F9bExaU1k5q4euG4ClCpPnbSOGv02GvyXi0s3/DQuYuNbq1a\
                  iABIrgqFmrp4jTJXpqFn0FcsXKsISl66ggQ=\n";
        let tree = leaf_log(600).tree();
        let text = format_tree(&tree);
        let signed = format!("{text}\n{}", signature_line(&text, NAME, &signing_key()));
        assert_eq!(signed, go);
        let key = parse_verifier_key(&verifier_key_text(NAME, &signing_key())).unwrap();
        let opened = open_note(go.as_bytes(), &key).unwrap();
        assert_eq!(opened, text);
        assert_eq!(parse_tree(opened).unwrap(), tree);
    }

    #[test]
    fn hashes_match_rfc_6962_and_go() {
        assert_eq!(
            b64(&record_hash(b"hello world")),
            "TszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0="
        );
        // The Certificate Transparency reference tree over eight leaves.
        let leaves: [&[u8]; 8] = [
            b"",
            b"\x00",
            b"\x10",
            b"\x20\x21",
            b"\x30\x31",
            b"\x40\x41\x42\x43",
            b"\x50\x51\x52\x53\x54\x55\x56\x57",
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
        ];
        let roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        let mut log = Log::default();
        for (leaf, root) in leaves.iter().zip(roots) {
            log.add(leaf);
            assert_eq!(hex(&log.tree().hash), root, "tree of {}", log.size);
        }
        // tlog.TreeHash over "leaf %d" records.
        let mut log = Log::default();
        let expected = [
            (1, "G7l9zCFjXUfiZj79/QoXRobZjdcBNS3SzQbotD/T0wU="),
            (2, "/F9riP+FVPdbsvnm85wxsZNtRLaSdu33sSBalVuXYeM="),
            (7, "WmH8K1T5z6cXdPJDIUPdQMbLKxGUf69lp9PaXLZRmcg="),
            (100, "E/iJFcVg3JEaHaD7IJ2EoglxBR8pTr60KPs/wpOvJ0M="),
            (256, "z17/2xHQknou31Ow5zx4N/ZZQU4AU32l2Q61xMSf8nQ="),
            (600, "YeW3m0rrRtdF0jKp4Z6FF/MaCPW/wHpHSqW4KrWAG9o="),
            (1000, "L/M/udjxT4nKMGKJYzM2oWj/P0Uy6PdBoAGdy0wdYKE="),
        ];
        for (size, root) in expected {
            while log.size < size {
                log.add(format!("leaf {}", log.size).as_bytes());
            }
            assert_eq!(b64(&log.tree().hash), root, "tree of {size}");
        }
        assert_eq!(hex(&tree_hash(0, &Vec::new())), hex(&Sha256::digest(b"")));
    }

    #[test]
    fn a_record_proof_matches_go() {
        // tlog.ProveRecord(600, 5) over the "leaf %d" log.
        let go = [
            "gxFfiUeVX6/cKifn9MCFS72Nonuxs+NAXbVxya+Nvho=",
            "brzFS2cQ7gYQp/yCzeUXE9soDj3IRRW96WMqGbZaC5M=",
            "T2MQhKFXxU9U/Psj/164ZQxLoWDClbsTqYMrEJ1SZ34=",
            "qACpeGyYjOedMjlqMtlKfqvOMxsyqk2yNxWbv5TFMv4=",
            "hncrWqPa2Rp3YSXlROedrzpUuw14dRMxZfyatvxIabc=",
            "ka6oYUkKTbHEelZcBYKTca6y97uGVdez6xeq4Ytv3OE=",
            "tJHuVzgD1gQxHdw3+NouE6JmRSXkiMbYH4ka4ZtugWY=",
            "TndYvhQHCGQLIOAoJoyUaxKGfXKHvJn6bfGegnsNkAo=",
            "kruC0rsurReb94AeYHEGyOWBjlHRFVk+K9pB7pLVZNw=",
            "YQTZpZbaUOMZ0hyZcg8LmvGI/vrd5Uk7N1YGasKwAzQ=",
        ];
        let log = leaf_log(600);
        let proof = prove_record(600, 5, &log.hashes).unwrap();
        assert_eq!(proof.iter().map(b64).collect::<Vec<_>>(), go);
        // The same proof read through authenticated tiles of height 8.
        let tiles = MemoryTiles {
            h: TILE_HEIGHT,
            hashes: &log.hashes,
            zeroed: None,
        };
        let reader = TileHashReader {
            tree: log.tree(),
            tiles: &tiles,
        };
        assert_eq!(prove_record(600, 5, &reader).unwrap(), proof);
    }

    #[test]
    fn storage_indexes_and_tiles_match_go() {
        for (level, n, index) in [
            (0, 0, 0),
            (0, 1, 1),
            (1, 0, 2),
            (0, 2, 3),
            (0, 3, 4),
            (2, 0, 6),
            (0, 1000, 1994),
            (8, 1, 1021),
            (3, 12345, 197528),
        ] {
            assert_eq!(stored_hash_index(level, n), index, "({level}, {n})");
        }
        for level in 0..10 {
            for n in 0..100 {
                let index = stored_hash_index(level, n);
                assert_eq!(split_stored_hash_index(index), (level, n), "{index}");
            }
        }
        for (index, n, w) in [
            (0, 0, 1),
            (1, 0, 2),
            (2, 0, 2),
            (3, 0, 3),
            (600, 1, 48),
            (1234567, 2411, 73),
        ] {
            let tile = Tile { h: 8, l: 0, n, w };
            assert_eq!(tile_for_index(8, index).0, tile, "{index}");
        }
        for (tile, path) in [
            (
                Tile {
                    h: 4,
                    l: 0,
                    n: 1,
                    w: 16,
                },
                "tile/4/0/001",
            ),
            (
                Tile {
                    h: 4,
                    l: 0,
                    n: 1,
                    w: 5,
                },
                "tile/4/0/001.p/5",
            ),
            (
                Tile {
                    h: 3,
                    l: 5,
                    n: 123456078,
                    w: 8,
                },
                "tile/3/5/x123/x456/078",
            ),
            (
                Tile {
                    h: 3,
                    l: 5,
                    n: 123456078,
                    w: 2,
                },
                "tile/3/5/x123/x456/078.p/2",
            ),
            (
                Tile {
                    h: 1,
                    l: 0,
                    n: 3057500,
                    w: 2,
                },
                "tile/1/0/x003/x057/500",
            ),
            (
                Tile {
                    h: 8,
                    l: 0,
                    n: 0,
                    w: 40,
                },
                "tile/8/0/000.p/40",
            ),
            (
                Tile {
                    h: 8,
                    l: 2,
                    n: 1234067,
                    w: 256,
                },
                "tile/8/2/x001/x234/067",
            ),
            (
                Tile {
                    h: 8,
                    l: 1,
                    n: 1000,
                    w: 3,
                },
                "tile/8/1/x001/000.p/3",
            ),
        ] {
            assert_eq!(tile.path(), path);
        }
    }

    #[test]
    fn record_proofs_hold_and_corrupt_ones_fail() {
        let mut log = Log::default();
        for size in 1..=64u64 {
            log.add(format!("leaf {}", size - 1).as_bytes());
            let tree = log.tree();
            for n in 0..size {
                let leaf = record_hash(format!("leaf {n}").as_bytes());
                let mut proof = prove_record(size, n, &log.hashes).unwrap();
                check_record(&proof, size, &tree.hash, n, &leaf).unwrap();
                for k in 0..proof.len() {
                    proof[k][0] ^= 1;
                    assert!(check_record(&proof, size, &tree.hash, n, &leaf).is_err());
                    proof[k][0] ^= 1;
                }
                let mut longer = proof.clone();
                longer.push(leaf);
                assert!(check_record(&longer, size, &tree.hash, n, &leaf).is_err());
            }
            assert!(prove_record(size, size, &log.hashes).is_err());
            assert!(check_record(&[], size, &tree.hash, size, &tree.hash).is_err());
        }
    }

    /// The port of tlog's TestTileHashReader: every hash of every small tree
    /// reads back through authenticated tiles of height 2, and a tampered
    /// hash anywhere fails the read of it and of everything.
    #[test]
    fn tile_hash_reader_authenticates_every_tile() {
        let mut log = Log::default();
        for size in 1..=48u64 {
            log.add(format!("leaf {}", size - 1).as_bytes());
            let tree = log.tree();
            let honest = MemoryTiles {
                h: 2,
                hashes: &log.hashes,
                zeroed: None,
            };
            let reader = TileHashReader {
                tree,
                tiles: &honest,
            };
            let all: Vec<u64> = (0..stored_hash_index(0, size)).collect();
            for &i in &all {
                assert_eq!(
                    reader.read_hashes(&[i]).unwrap(),
                    vec![log.hashes[i as usize]]
                );
            }
            assert_eq!(reader.read_hashes(&all).unwrap(), log.hashes[..all.len()]);
            assert!(reader.read_hashes(&[all.len() as u64]).is_err());
            for n in 0..size {
                let proof = prove_record(size, n, &reader).unwrap();
                let leaf = record_hash(format!("leaf {n}").as_bytes());
                check_record(&proof, size, &tree.hash, n, &leaf).unwrap();
            }
            for &zeroed in &all {
                let tampered = MemoryTiles {
                    h: 2,
                    hashes: &log.hashes,
                    zeroed: Some(zeroed),
                };
                let reader = TileHashReader {
                    tree,
                    tiles: &tampered,
                };
                assert!(reader.read_hashes(&[zeroed]).is_err(), "{size} {zeroed}");
                assert!(reader.read_hashes(&all).is_err(), "{size} {zeroed}");
            }
        }
    }

    #[test]
    fn trees_and_records_parse_as_go_parses_them() {
        let good =
            "go.sum database tree\n123456789012\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n";
        let tree = parse_tree(good).unwrap();
        assert_eq!(tree.n, 123456789012);
        assert_eq!(tree.hash, record_hash(b"hello world"));
        for extra in ["JOE", "JOE\n", &"JOE\n".repeat(1000)] {
            assert_eq!(parse_tree(&format!("{good}{extra}")).unwrap(), tree);
        }
        for bad in [
            format!("not-{good}"),
            good.replace("123456789012", "0xabcdef"),
            good.replace("123456789012", "+123456789012"),
            good.replace("123456789012", "0123456789012"),
            good.replace("123456789012", "-1"),
            good.replace("123456789012", "9223372036854775807"),
            good.replace("uwBb0=", "uwBTOOBIG="),
            good.trim_end().to_string(),
        ] {
            assert!(parse_tree(&bad).is_err(), "{bad:?}");
        }

        let (id, text, rest) = parse_record(b"123456789012\nhello, world\n\njunk\x01\xff").unwrap();
        assert_eq!(
            (id, text, rest),
            (123456789012, "hello, world\n", &b"junk\x01\xff"[..])
        );
        let (_, _, rest) = parse_record(b"5\nhello\n\n").unwrap();
        assert!(rest.is_empty());
        for bad in [
            &b"not-123\nhello\n\n"[..],
            b"123\nhello\x01world\n\n",
            b"123\nhello\xffworld\n\n",
            b"123\nhello world\n",
            b"0x123\nhello world\n\n",
            b"+5\nhello\n\n",
            b"-5\nhello\n\n",
            b"05\nhello\n\n",
            b"5\n\n",
        ] {
            assert!(
                parse_record(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn base64_round_trips() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(base64_decode(&base64_encode(&bytes)).unwrap(), bytes);
        }
        for bad in ["A", "AB=", "A===", "AB=C", "AB==AAAA", "AB\u{e9}A", "AB C"] {
            assert!(base64_decode(bad).is_none(), "{bad:?}");
        }
    }

    // Lookups against the synthetic database.

    #[test]
    fn a_lookup_is_proven_for_every_record() {
        let small = Fixture::new(40);
        for id in 0..40 {
            assert_proven(&small, id);
        }
        // Past one complete tile, so tiles are authenticated through their
        // parents too.
        let large = Fixture::new(600);
        for id in [0, 1, 5, 255, 256, 300, 511, 512, 575, 599] {
            assert_proven(&large, id);
        }
        assert_eq!(large.tree.n, 600);

        // One lookup fetches the record and each tile it needs once.
        let fresh = Fixture::new(40);
        assert_proven(&fresh, 0);
        assert_eq!(
            fresh.requests(),
            [
                "https://sum.example/lookup/github.com/!example/m0@v1.0.0",
                "https://sum.example/tile/8/0/000.p/40",
            ]
        );
    }

    #[test]
    fn a_go_mod_suffix_on_the_version_asks_for_the_same_record() {
        let fixture = Fixture::new(10);
        let record = &fixture.records[3];
        let lines = lookup(
            &fixture.fetcher,
            &fixture.db,
            &record.module,
            &format!("{}/go.mod", record.version),
        )
        .unwrap();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn a_tampered_record_line_is_refused() {
        let mut fixture = Fixture::new(40);
        let record = &mut fixture.records[7];
        record.text = record.text.replacen("h1:", "h1:A", 1);
        let note = fixture.note.clone();
        fixture.serve(7, 7, &note);
        let reason = fixture.lookup(7).unwrap_err();
        assert!(reason.contains("github.com/Example/m7@v1.0.7"), "{reason}");
        assert!(
            reason.contains("not the record the signed log holds"),
            "{reason}"
        );

        // A genuine record offered under another record's id.
        let mut fixture = Fixture::new(40);
        let note = fixture.note.clone();
        fixture.serve(7, 8, &note);
        let reason = fixture.lookup(7).unwrap_err();
        assert!(
            reason.contains("not the record the signed log holds"),
            "{reason}"
        );
    }

    #[test]
    fn a_proven_record_for_another_module_is_refused() {
        let mut fixture = Fixture::new(40);
        // The database answers the lookup for record 7 with record 8, whole
        // and genuine.
        let text = fixture.records[8].text.clone();
        let note = fixture.note.clone();
        let body = format!("8\n{text}\n{note}");
        let url = lookup_url(&fixture.records[7]);
        fixture
            .fetcher
            .documents
            .insert(url, ("text/plain".to_string(), body.into_bytes()));
        let reason = fixture.lookup(7).unwrap_err();
        assert!(
            reason.contains("no go.sum line for github.com/Example/m7@v1.0.7"),
            "{reason}"
        );
    }

    #[test]
    fn a_tampered_tile_is_refused() {
        // For 600 records record 5 is read from the complete tile 0/000,
        // authenticated through 1/000.p/2, which with 0/002.p/88 gives the
        // tree hash. Tampering with any of them fails the lookup.
        for (path, byte) in [
            ("tile/8/0/000", 5 * 32),
            ("tile/8/0/000", 200 * 32 + 7),
            ("tile/8/0/002.p/88", 0),
            ("tile/8/0/002.p/88", 87 * 32 + 31),
            ("tile/8/1/000.p/2", 32),
        ] {
            let mut fixture = Fixture::new(600);
            fixture.tamper_tile(path, byte);
            let reason = fixture.lookup(5).unwrap_err();
            assert!(reason.contains("github.com/Example/m5@v1.0.5"), "{reason}");
            assert!(reason.contains("tile"), "{path}: {reason}");
        }
        // A tile record 5 does not use leaves it proven, and fails the
        // records it holds.
        let mut fixture = Fixture::new(600);
        fixture.tamper_tile("tile/8/0/001", 44 * 32);
        assert_proven(&fixture, 5);
        let reason = fixture.lookup(300).unwrap_err();
        assert!(
            reason.contains("tile/8/0/001 as served does not match"),
            "{reason}"
        );
    }

    #[test]
    fn a_tile_of_the_wrong_size_is_refused() {
        let mut fixture = Fixture::new(40);
        let (_, data) = fixture
            .fetcher
            .documents
            .get_mut(&format!("{URL}/tile/8/0/000.p/40"))
            .unwrap();
        data.truncate(39 * 32);
        let reason = fixture.lookup(3).unwrap_err();
        assert!(reason.contains("is 1248 bytes, not 1280"), "{reason}");
    }

    #[test]
    fn a_complete_tile_stands_in_for_a_partial_one_gone() {
        // The database has grown to 800 records since it signed 600, so
        // 0/002.p/88 is gone and only the complete 0/002 is served.
        let mut fixture = Fixture::new(600);
        let mut grown = Log::default();
        for i in 0..800 {
            grown.add(record(i).text.as_bytes());
        }
        let full = Tile {
            h: 8,
            l: 0,
            n: 2,
            w: 256,
        };
        fixture
            .fetcher
            .documents
            .remove(&format!("{URL}/tile/8/0/002.p/88"));
        fixture.fetcher.documents.insert(
            tile_url(&full),
            (String::new(), read_tile_data(full, &grown.hashes)),
        );
        assert_proven(&fixture, 5);
        assert_proven(&fixture, 590);
        let requests = fixture.requests();
        assert!(requests.contains(&format!("{URL}/tile/8/0/002.p/88")));
        assert!(requests.contains(&format!("{URL}/tile/8/0/002")));

        // Without either, the lookup names the tile it could not fetch.
        fixture.fetcher.documents.remove(&tile_url(&full));
        let reason = fixture.lookup(5).unwrap_err();
        assert!(
            reason.contains("could not fetch tile/8/0/002.p/88"),
            "{reason}"
        );
    }

    #[test]
    fn a_wrong_signature_is_refused() {
        let mut fixture = Fixture::new(40);
        let signed = fixture.note.clone();
        let (text, line) = signed.split_once("\n\n").unwrap();
        let encoded = line
            .trim_end()
            .rsplit_once(' ')
            .map(|(_, encoded)| encoded)
            .unwrap();
        let mut signature = base64_decode(encoded).unwrap();
        signature[20] ^= 0x40;
        let note = format!(
            "{text}\n\n{SIGNATURE_PREFIX}{NAME} {}\n",
            base64_encode(&signature)
        );
        fixture.serve(4, 4, &note);
        let reason = fixture.lookup(4).unwrap_err();
        assert!(reason.contains("github.com/Example/m4@v1.0.4"), "{reason}");
        assert!(
            reason.contains("signature by sum.example on the tree note is invalid"),
            "{reason}"
        );

        // A valid signature, but over another tree.
        let other = format_tree(&Tree {
            n: 40,
            hash: record_hash(b"another tree"),
        });
        let forged = format!("{other}\n{}", signature_line(&other, NAME, &signing_key()));
        let note = format!("{text}\n\n{}", forged.split_once("\n\n").unwrap().1);
        fixture.serve(4, 4, &note);
        let reason = fixture.lookup(4).unwrap_err();
        assert!(reason.contains("is invalid"), "{reason}");

        // The same tree signed by an impostor under the same name.
        let impostor = SigningKey::from_bytes(&[9u8; 32]);
        let note = format!(
            "{text}\n\n{}",
            signature_line(&format!("{text}\n"), NAME, &impostor)
        );
        fixture.serve(4, 4, &note);
        let reason = fixture.lookup(4).unwrap_err();
        assert!(
            reason.contains("carries no signature by sum.example"),
            "{reason}"
        );
    }

    #[test]
    fn a_key_with_another_name_proves_nothing() {
        let mut fixture = Fixture::new(40);
        fixture.db.key =
            parse_verifier_key(&verifier_key_text("other.example", &signing_key())).unwrap();
        let reason = fixture.lookup(4).unwrap_err();
        assert!(reason.contains("github.com/Example/m4@v1.0.4"), "{reason}");
        assert!(
            reason.contains("carries no signature by other.example"),
            "{reason}"
        );
    }

    #[test]
    fn other_signatures_beside_the_key_are_skipped() {
        let mut fixture = Fixture::new(40);
        let text = format_tree(&fixture.tree);
        let witness = SigningKey::from_bytes(&[3u8; 32]);
        let own = signature_line(&text, NAME, &signing_key());
        let note = format!(
            "{text}\n{}{own}{own}",
            signature_line(&text, "witness.example", &witness)
        );
        fixture.serve(4, 4, &note);
        assert_proven(&fixture, 4);

        // A signature line in the wrong form spoils the note.
        let note = format!("{text}\n{own}- {NAME} AAAA\n");
        fixture.serve(4, 4, &note);
        let reason = fixture.lookup(4).unwrap_err();
        assert!(reason.contains("malformed"), "{reason}");
    }

    #[test]
    fn a_record_id_past_the_tree_is_refused() {
        for claimed in [40, 41, 1_000_000] {
            let mut fixture = Fixture::new(40);
            let note = fixture.note.clone();
            fixture.serve(4, claimed, &note);
            let reason = fixture.lookup(4).unwrap_err();
            assert!(reason.contains("github.com/Example/m4@v1.0.4"), "{reason}");
            assert!(
                reason.contains(&format!(
                    "record {claimed}, which the signed tree of size 40 does not hold"
                )),
                "{reason}"
            );
            // Refused before any tile is fetched.
            assert_eq!(fixture.requests().len(), 1);
        }
    }

    #[test]
    fn credentials_in_the_database_url_never_reach_a_reason() {
        let mut fixture = Fixture::new(4);
        fixture.db.url = "https://kin:hunter2@proxy.example/sumdb/sum.example/".to_string();
        let reason = fixture.lookup(1).unwrap_err();
        assert!(!reason.contains("hunter2"), "{reason}");
        assert!(reason.contains("github.com/Example/m1@v1.0.1"), "{reason}");
        assert!(reason.contains("***@proxy.example"), "{reason}");
        // The request itself went to the credentialed URL, without doubling
        // the trailing slash.
        assert_eq!(
            fixture.requests(),
            ["https://kin:hunter2@proxy.example/sumdb/sum.example/lookup/github.com/!example/m1@v1.0.1"]
        );
        assert!(!format!("{:?}", fixture.db).contains("hunter2"));
    }

    #[test]
    fn a_module_path_or_version_unfit_for_a_url_is_refused_unasked() {
        let fixture = Fixture::new(4);
        for (module, version) in [
            ("github.com/x/y?z", "v1.0.0"),
            ("github.com/x/../y", "v1.0.0"),
            ("github.com//y", "v1.0.0"),
            ("/github.com/y", "v1.0.0"),
            ("github.com/y/", "v1.0.0"),
            ("localmodule", "v1.0.0"),
            ("GitHub.com/y", "v1.0.0"),
            ("github.com/y", "v1.0.0#x"),
            ("github.com/y", "v1.0.0/../x"),
            ("github.com/y", ""),
        ] {
            let reason = lookup(&fixture.fetcher, &fixture.db, module, version).unwrap_err();
            assert!(reason.contains(module), "{reason}");
        }
        assert!(fixture.requests().is_empty());
    }

    #[test]
    fn gosumdb_values_name_databases_as_go_reads_them() {
        let default = SumDb {
            key: parse_verifier_key(DEFAULT_GOSUMDB).unwrap(),
            url: "https://sum.golang.org".to_string(),
        };
        assert_eq!(from_gosumdb("").unwrap(), Some(default.clone()));
        assert_eq!(from_gosumdb("  ").unwrap(), Some(default.clone()));
        assert_eq!(
            from_gosumdb("sum.golang.org").unwrap(),
            Some(default.clone())
        );
        assert_eq!(
            from_gosumdb(DEFAULT_GOSUMDB).unwrap(),
            Some(default.clone())
        );
        assert_eq!(from_gosumdb("off").unwrap(), None);
        assert_eq!(
            from_gosumdb("sum.golang.google.cn").unwrap(),
            Some(SumDb {
                url: "https://sum.golang.google.cn".to_string(),
                ..default.clone()
            })
        );
        assert_eq!(
            from_gosumdb("sum.golang.org https://proxy.example/sumdb/sum.golang.org/").unwrap(),
            Some(SumDb {
                url: "https://proxy.example/sumdb/sum.golang.org".to_string(),
                ..default.clone()
            })
        );
        let own = verifier_key_text(NAME, &signing_key());
        let db = from_gosumdb(&own).unwrap().unwrap();
        assert_eq!(db.key.name, NAME);
        assert_eq!(db.url, "https://sum.example");
        let db = from_gosumdb(&format!("{own} http://127.0.0.1:8080"))
            .unwrap()
            .unwrap();
        assert_eq!(db.url, "http://127.0.0.1:8080");

        for bad in [
            format!("{own} https://a.example https://b.example"),
            "sum.golang.google.cn https://sum.golang.google.cn".to_string(),
            "example.com".to_string(),
            format!("{own} ftp://sum.example"),
            format!("{own} https://"),
            format!("{own} https://sum.example/?x"),
            verifier_key_text("sum.example/", &signing_key()),
            verifier_key_text("user@sum.example", &signing_key()),
            verifier_key_text("sum.example?x", &signing_key()),
        ] {
            assert!(from_gosumdb(&bad).is_err(), "{bad:?}");
        }
        let reason = from_gosumdb(&format!("{own} ftp://kin:hunter2@sum.example")).unwrap_err();
        assert!(!reason.contains("hunter2"), "{reason}");
    }

    #[test]
    fn uppercase_letters_escape_to_bang_and_lowercase() {
        assert_eq!(
            escape_path("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        assert_eq!(escape_path("golang.org/x/text"), "golang.org/x/text");
        assert_eq!(escape_path("v1.0.0-RC1"), "v1.0.0-!r!c1");
    }
}
