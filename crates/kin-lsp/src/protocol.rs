// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP protocol types — the subset Kin needs for graph enrichment.
//!
//! We don't use the full lsp-types crate to keep dependencies minimal.
//! Only the types needed for: initialize, textDocument/definition,
//! textDocument/references, callHierarchy.

use serde::{Deserialize, Serialize};

// ── Initialize ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub process_id: Option<u32>,
    pub root_uri: Option<String>,
    /// The workspace root again, as the one workspace folder.
    ///
    /// `rootUri` alone does not reach every server. pyright reads
    /// `workspaceFolders`, then the deprecated `rootPath`, and never `rootUri`.
    /// Started with `rootUri` only, it runs a default workspace with no root.
    /// It then reads none of the repository's configuration and does not
    /// search its `src` directory, so a test importing the repository's own
    /// package resolves it wherever the Python environment points. That can
    /// be a copy outside the repository, which names no admitted file, and
    /// every answer about that package is lost.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_folders: Option<Vec<WorkspaceFolder>>,
    pub capabilities: ClientCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialization_options: Option<serde_json::Value>,
}

impl InitializeParams {
    /// The parameters every server is started with: the workspace root, named
    /// both as `rootUri` and as the single workspace folder.
    ///
    /// The two name the same directory, so a server that reads either one
    /// sees the same root. `rootPath` is left out: it is deprecated in favour
    /// of `rootUri`, and pyright, the only server here known to fall back to
    /// it, reads `workspaceFolders` first. The client does not declare the
    /// `workspace.workspaceFolders` capability, because the root never changes
    /// during a session. It claims no workspace capability at all here; a
    /// server that needs settings is started through [`Self::for_launch`].
    pub fn for_workspace(
        workspace_root: &std::path::Path,
        initialization_options: Option<serde_json::Value>,
    ) -> Self {
        let root_uri = path_to_uri(workspace_root);
        Self {
            process_id: Some(std::process::id()),
            workspace_folders: Some(vec![WorkspaceFolder::for_root(workspace_root)]),
            root_uri: Some(root_uri),
            capabilities: kin_capabilities(),
            initialization_options,
        }
    }

    /// The parameters for one adapter's launch: [`Self::for_workspace`] with
    /// the launch's initialization options, plus the two capabilities a launch
    /// can need.
    ///
    /// - `workspace.configuration`, only when the launch carries settings. A
    ///   server that sees it asks for its settings with
    ///   `workspace/configuration`, and the client answers from them. pyright
    ///   reads its settings no other way: it ignores `initializationOptions`
    ///   apart from one flag.
    /// - `experimental.serverStatusNotification`, only when the launch waits
    ///   for the server to report its project loaded. rust-analyzer then says
    ///   when it has finished loading and whether that load failed.
    pub fn for_launch(
        workspace_root: &std::path::Path,
        launch: &crate::adapters::ServerLaunch,
    ) -> Self {
        let mut params = Self::for_workspace(workspace_root, launch.initialization_options.clone());
        if launch.settings.is_some() {
            params.capabilities.workspace = Some(serde_json::json!({ "configuration": true }));
        }
        if launch.load_check == Some(crate::adapters::LoadCheck::ServerStatus) {
            params.capabilities.experimental =
                Some(serde_json::json!({ "serverStatusNotification": true }));
        }
        params
    }
}

/// One workspace folder, as LSP names it: a URI and a display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceFolder {
    pub uri: String,
    pub name: String,
}

impl WorkspaceFolder {
    /// The folder for `root`, named by its last path component. A root with
    /// no final component, such as `/`, is named by its URI.
    pub fn for_root(root: &std::path::Path) -> Self {
        let uri = path_to_uri(root);
        let name = root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| uri.clone());
        Self { uri, name }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientCapabilities {
    pub general: serde_json::Value,
    pub text_document: Option<TextDocumentClientCapabilities>,
    /// Claimed only by a launch that answers `workspace/configuration`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<serde_json::Value>,
    /// Claimed only by a launch that waits for rust-analyzer's server status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TextDocumentClientCapabilities {
    pub call_hierarchy: Option<serde_json::Value>,
    pub definition: Option<serde_json::Value>,
    pub references: Option<serde_json::Value>,
    pub type_hierarchy: Option<serde_json::Value>,
    pub type_definition: Option<serde_json::Value>,
    /// Hierarchical symbols, which name a declaration by the whole chain of
    /// declarations that holds it (see [`crate::external_symbols`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_symbol: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub capabilities: ServerCapabilities,
    /// The server's own name and version, when it reports them.
    #[serde(default)]
    pub server_info: Option<ServerInfo>,
}

/// What a server says it is, in its initialize answer.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ServerInfo {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerCapabilities {
    pub position_encoding: Option<String>,
    pub call_hierarchy_provider: Option<serde_json::Value>,
    pub definition_provider: Option<serde_json::Value>,
    pub references_provider: Option<serde_json::Value>,
    pub type_hierarchy_provider: Option<serde_json::Value>,
    pub type_definition_provider: Option<serde_json::Value>,
    pub implementation_provider: Option<serde_json::Value>,
}

// ── Text Document ───────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TextDocumentIdentifier {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Location {
    pub uri: String,
    pub range: Range,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TextDocumentPositionParams {
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

// ── Call Hierarchy ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallHierarchyPrepareParams {
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CallHierarchyItem {
    pub name: String,
    pub kind: u32, // SymbolKind
    pub uri: String,
    pub range: Range,
    pub selection_range: Range,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CallHierarchyIncomingCallsParams {
    pub item: CallHierarchyItem,
}

#[derive(Debug, Serialize)]
pub struct CallHierarchyOutgoingCallsParams {
    pub item: CallHierarchyItem,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallHierarchyIncomingCall {
    pub from: CallHierarchyItem,
    pub from_ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallHierarchyOutgoingCall {
    pub to: CallHierarchyItem,
    pub from_ranges: Vec<Range>,
}

// ── Type Hierarchy ─────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeHierarchyPrepareParams {
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TypeHierarchyItem {
    pub name: String,
    pub kind: u32,
    pub uri: String,
    pub range: Range,
    pub selection_range: Range,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TypeHierarchySupertypesParams {
    pub item: TypeHierarchyItem,
}

// ── File URIs ───────────────────────────────────────────────────────────

/// How a filesystem path spells its root and its separators.
///
/// A parameter rather than a `cfg!` inside the conversion, so the Windows
/// spelling is exercised by tests on every host. The conversion is string
/// work and needs no Windows machine to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathStyle {
    /// `/`-separated and rooted at `/`, as on macOS and Linux.
    Posix,
    /// Drive letters, `\` or `/` separators, UNC shares, and the `\\?\`
    /// verbatim prefix that `std::fs::canonicalize` returns on Windows.
    Windows,
}

impl PathStyle {
    /// The style of the host this binary runs on.
    pub const HOST: Self = if cfg!(windows) {
        Self::Windows
    } else {
        Self::Posix
    };
}

/// Convert a file path to the `file:` URI a language server expects.
///
/// `file:///home/me/src/lib.rs` on Unix and `file:///C:/Users/me/src/lib.rs`
/// on Windows (RFC 8089). This used to paste the path after `file://`, which
/// got Windows wrong twice over: the drive landed where the URI's host goes
/// (`file://C:\Users\...`) and the separators stayed backslashes, so a Windows
/// language server could not resolve any document Kin opened. It also left
/// `#`, `?`, `%` and spaces unescaped on every platform, where they end or
/// corrupt the path part of a URI.
pub fn path_to_uri(path: &std::path::Path) -> String {
    file_uri_from_path(&host_path_bytes(path), PathStyle::HOST)
}

/// Extract a file path from a `file:` URI, in the host's spelling.
///
/// `None` for another scheme, for a host that is not this machine on Unix, and
/// for a path Windows cannot spell. See [`path_from_file_uri`] for the form a
/// Windows path comes back in.
pub fn uri_to_path(uri: &str) -> Option<std::path::PathBuf> {
    host_path_from_bytes(path_from_file_uri(uri, PathStyle::HOST)?)
}

/// Whether two `file:` URIs name the same file on this host.
///
/// Servers spell one path in more than one way. A server built on VS Code's URI
/// library writes a Windows drive as `c%3A` and escapes characters Kin leaves
/// as they are, and comparing the strings would refuse that server's answer as
/// naming a file Kin never opened.
pub fn same_file_uri(left: &str, right: &str) -> bool {
    same_file_uri_in(left, right, PathStyle::HOST)
}

/// [`same_file_uri`] for an explicit path style.
pub fn same_file_uri_in(left: &str, right: &str, style: PathStyle) -> bool {
    if left == right {
        return true;
    }
    let canonical =
        |uri: &str| path_from_file_uri(uri, style).map(|path| file_uri_from_path(&path, style));
    match (canonical(left), canonical(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

/// Spell a path, given as bytes, as a `file:` URI in the given style.
///
/// The path should be absolute: a relative path names no file a server can
/// open, and is spelled here as if it hung from the root. That includes a bare
/// drive, `D:`, which on Windows names the drive's current directory: a URI
/// cannot say that, so it is spelled as the drive's root, `file:///D:/`. On
/// Windows the separators become `/`, the drive letter is upper-cased, and a
/// `\\?\` or `\\.\` prefix is dropped, since `\\?\C:\x` and `C:\x` are the same
/// file and a server must see one spelling. A UNC path carries its server as
/// the URI's host: `\\server\share\x` is `file://server/share/x`.
pub fn file_uri_from_path(path: &[u8], style: PathStyle) -> String {
    let mut uri = String::from("file://");
    let local: std::borrow::Cow<'_, [u8]> = match style {
        PathStyle::Posix => std::borrow::Cow::Borrowed(path),
        PathStyle::Windows => {
            let (host, local) = split_windows_path(path);
            if let Some(host) = host {
                push_percent_encoded(&mut uri, host, is_uri_host_byte);
            }
            let local: Vec<u8> = local
                .iter()
                .map(|&byte| if byte == b'\\' { b'/' } else { byte })
                .collect();
            std::borrow::Cow::Owned(if starts_with_drive(&local) {
                with_drive(&local)
            } else {
                local
            })
        }
    };
    if local.first() != Some(&b'/') {
        uri.push('/');
    }
    push_percent_encoded(&mut uri, &local, is_uri_path_byte);
    uri
}

/// The path a `file:` URI names, as bytes spelled in the given style.
///
/// Escapes are decoded, a query or fragment is dropped, and `localhost` is
/// this machine. On Unix a URI naming another host has no local path and is
/// `None`. On Windows another host is a UNC share, and a path comes back with
/// `/` separators, which Windows accepts in every path that is not verbatim.
/// That keeps one separator across Kin: repository-relative paths in the graph
/// are `/`-separated, and the index that maps a server's answer onto them
/// strips the workspace root from this path and compares the rest exactly.
/// `file:///C:/x` and `file:///c%3A/x` both come back as `C:/x`.
pub fn path_from_file_uri(uri: &str, style: PathStyle) -> Option<Vec<u8>> {
    let scheme = uri.get(..5)?;
    if !scheme.eq_ignore_ascii_case("file:") {
        return None;
    }
    let rest = &uri[5..];
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.strip_prefix("//") {
        Some(after) => match after.find('/') {
            Some(slash) => (&after[..slash], &after[slash..]),
            None => (after, ""),
        },
        None => ("", rest),
    };
    let authority = percent_decode(authority);
    let path = percent_decode(path);
    if path.contains(&0) || authority.contains(&0) {
        return None;
    }
    let local_host = authority.is_empty() || authority.eq_ignore_ascii_case(b"localhost");
    match style {
        PathStyle::Posix => (local_host && path.first() == Some(&b'/')).then_some(path),
        PathStyle::Windows => {
            let path: Vec<u8> = path
                .iter()
                .map(|&byte| if byte == b'\\' { b'/' } else { byte })
                .collect();
            let decoded = if local_host {
                if path.first() != Some(&b'/') {
                    return None;
                }
                if starts_with_drive(&path[1..]) {
                    with_drive(&path[1..])
                } else {
                    path
                }
            } else if starts_with_drive(&authority) && authority.len() == 2 {
                // `file://C:/x` is not RFC 8089, but some tools write it.
                let mut drive = authority;
                drive.extend_from_slice(&path);
                with_drive(&drive)
            } else {
                let mut unc = b"//".to_vec();
                unc.extend_from_slice(&authority);
                unc.extend_from_slice(&path);
                unc
            };
            Some(decoded)
        }
    }
}

/// Split a Windows path into the UNC host it names, if any, and the rest.
///
/// The rest starts at the drive (`C:\x`) or at the separator after the host
/// (`\share\x`). A `\\?\` or `\\.\` prefix before a drive is dropped; before
/// anything else it is kept as a host, so the URI still round-trips.
fn split_windows_path(path: &[u8]) -> (Option<&[u8]>, &[u8]) {
    let separator = |byte: &u8| *byte == b'\\' || *byte == b'/';
    for verbatim_unc in [br"\\?\UNC\", br"\\.\UNC\"] {
        if path.len() >= verbatim_unc.len()
            && path[..verbatim_unc.len()].eq_ignore_ascii_case(verbatim_unc)
        {
            return split_host(&path[verbatim_unc.len()..], separator);
        }
    }
    for device in [br"\\?\", br"\\.\"] {
        if let Some(rest) = path.strip_prefix(device) {
            if starts_with_drive(rest) {
                return (None, rest);
            }
        }
    }
    if path.len() >= 2 && separator(&path[0]) && separator(&path[1]) {
        return split_host(&path[2..], separator);
    }
    (None, path)
}

fn split_host(rest: &[u8], separator: impl Fn(&u8) -> bool) -> (Option<&[u8]>, &[u8]) {
    match rest.iter().position(separator) {
        Some(end) => (Some(&rest[..end]), &rest[end..]),
        None => (Some(rest), &[]),
    }
}

/// Whether a path starts with a drive, `C:`, followed by a separator or by
/// nothing. `C:x` is relative to the drive's current directory and is not one.
fn starts_with_drive(path: &[u8]) -> bool {
    path.len() >= 2
        && path[0].is_ascii_alphabetic()
        && matches!(path[1], b':' | b'|')
        && path.get(2).is_none_or(|byte| matches!(byte, b'/' | b'\\'))
}

/// A drive path in its one spelling: `C:/x`, from `c:/x` or `C|/x`, and `C:/`
/// from a bare `C:`.
fn with_drive(path: &[u8]) -> Vec<u8> {
    let mut drive = path.to_vec();
    drive[0] = drive[0].to_ascii_uppercase();
    drive[1] = b':';
    if drive.len() == 2 {
        drive.push(b'/');
    }
    drive
}

/// Bytes a URI path carries as they are (RFC 3986 `pchar` and `/`).
fn is_uri_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&byte)
}

/// Bytes a URI host carries as they are (RFC 3986 `reg-name`).
fn is_uri_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte)
}

fn push_percent_encoded(out: &mut String, bytes: &[u8], keep: fn(u8) -> bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        if keep(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

/// Decode `%XX` escapes. A `%` without two hex digits after it is kept as it
/// is, as a lenient reader of a server's URI should.
fn percent_decode(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(byte) = bytes
                .get(index + 1..index + 3)
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

#[cfg(unix)]
fn host_path_bytes(path: &std::path::Path) -> std::borrow::Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt;
    std::borrow::Cow::Borrowed(path.as_os_str().as_bytes())
}

#[cfg(not(unix))]
fn host_path_bytes(path: &std::path::Path) -> std::borrow::Cow<'_, [u8]> {
    match path.to_string_lossy() {
        std::borrow::Cow::Borrowed(text) => std::borrow::Cow::Borrowed(text.as_bytes()),
        std::borrow::Cow::Owned(text) => std::borrow::Cow::Owned(text.into_bytes()),
    }
}

#[cfg(unix)]
fn host_path_from_bytes(bytes: Vec<u8>) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    Some(std::ffi::OsString::from_vec(bytes).into())
}

#[cfg(not(unix))]
fn host_path_from_bytes(bytes: Vec<u8>) -> Option<std::path::PathBuf> {
    String::from_utf8(bytes).ok().map(std::path::PathBuf::from)
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Build standard client capabilities requesting the features Kin needs.
pub fn kin_capabilities() -> ClientCapabilities {
    ClientCapabilities {
        general: serde_json::json!({"positionEncodings": ["utf-16"]}),
        text_document: Some(TextDocumentClientCapabilities {
            call_hierarchy: Some(serde_json::json!({"dynamicRegistration": false})),
            definition: Some(
                serde_json::json!({"dynamicRegistration": false, "linkSupport": false}),
            ),
            references: Some(serde_json::json!({"dynamicRegistration": false})),
            type_hierarchy: Some(serde_json::json!({"dynamicRegistration": false})),
            type_definition: Some(serde_json::json!({"dynamicRegistration": false})),
            document_symbol: Some(serde_json::json!({
                "dynamicRegistration": false,
                "hierarchicalDocumentSymbolSupport": true
            })),
        }),
        workspace: None,
        experimental: None,
    }
}

#[cfg(test)]
mod file_uri_tests {
    use super::*;

    fn windows_uri(path: &str) -> String {
        file_uri_from_path(path.as_bytes(), PathStyle::Windows)
    }

    fn posix_uri(path: &str) -> String {
        file_uri_from_path(path.as_bytes(), PathStyle::Posix)
    }

    fn windows_path(uri: &str) -> Option<String> {
        path_from_file_uri(uri, PathStyle::Windows).map(|bytes| String::from_utf8(bytes).unwrap())
    }

    fn posix_path(uri: &str) -> Option<String> {
        path_from_file_uri(uri, PathStyle::Posix).map(|bytes| String::from_utf8(bytes).unwrap())
    }

    /// The shape a Windows language server has to be able to resolve: three
    /// slashes, the drive in the path rather than the host, and `/` between
    /// every component, whatever mix of separators the path was built with.
    #[test]
    fn windows_drive_paths_become_rfc_8089_uris() {
        assert_eq!(
            windows_uri(r"C:\Users\me\src\main.rs"),
            "file:///C:/Users/me/src/main.rs"
        );
        // `root.join("src/lib.rs")` on Windows mixes the two separators.
        assert_eq!(
            windows_uri(r"C:\repo\src/lib.rs"),
            "file:///C:/repo/src/lib.rs"
        );
        assert_eq!(
            windows_uri("C:/repo/src/lib.rs"),
            "file:///C:/repo/src/lib.rs"
        );
        // One drive, one spelling, so two URIs for one file compare equal.
        assert_eq!(windows_uri(r"c:\repo"), "file:///C:/repo");
        assert_eq!(windows_uri(r"C:\"), "file:///C:/");
        // A bare drive is spelled as its root, the same URI `D:\` gets.
        assert_eq!(windows_uri("D:"), "file:///D:/");
        assert_eq!(windows_uri(r"D:\"), "file:///D:/");
    }

    /// `std::fs::canonicalize` returns the verbatim spelling on Windows, and
    /// the daemon canonicalizes its workspace root. `\\?\C:\x` and `C:\x` are
    /// one file, so a server must see one URI for both.
    #[test]
    fn windows_verbatim_and_device_prefixes_are_dropped_before_a_drive() {
        assert_eq!(
            windows_uri(r"\\?\C:\Users\me\repo"),
            "file:///C:/Users/me/repo"
        );
        assert_eq!(
            windows_uri(r"\\.\C:\Users\me\repo"),
            "file:///C:/Users/me/repo"
        );
        assert_eq!(
            windows_uri(r"\\?\C:\Users\me\repo"),
            windows_uri(r"C:\Users\me\repo")
        );
    }

    /// A UNC share carries its server as the URI's host.
    #[test]
    fn windows_unc_paths_carry_the_server_as_the_host() {
        assert_eq!(
            windows_uri(r"\\fileserver\share\dir\file.rs"),
            "file://fileserver/share/dir/file.rs"
        );
        assert_eq!(
            windows_uri(r"\\?\UNC\fileserver\share\dir\file.rs"),
            "file://fileserver/share/dir/file.rs"
        );
        assert_eq!(
            windows_uri(r"\\?\unc\fileserver\share"),
            "file://fileserver/share"
        );
        assert_eq!(
            windows_uri("//fileserver/share/file.rs"),
            "file://fileserver/share/file.rs"
        );
    }

    /// `#` and `?` end the path part of a URI, `%` starts an escape, and a
    /// space or a non-ASCII byte is not allowed in one at all.
    #[test]
    fn characters_a_uri_path_cannot_carry_are_escaped() {
        assert_eq!(
            windows_uri(r"C:\My Projects\C# app\100%\é?.rs"),
            "file:///C:/My%20Projects/C%23%20app/100%25/%C3%A9%3F.rs"
        );
        assert_eq!(
            posix_uri("/home/me/My Projects/C# app/100%/é?.rs"),
            "file:///home/me/My%20Projects/C%23%20app/100%25/%C3%A9%3F.rs"
        );
        // A backslash is an ordinary file name byte on Unix.
        assert_eq!(posix_uri(r"/tmp/a\b.rs"), "file:///tmp/a%5Cb.rs");
        // What RFC 3986 allows in a path stays as it is, so the URIs Kin sends
        // for ordinary paths did not change.
        assert_eq!(
            posix_uri("/w/node_modules/@types/node/index.d.ts"),
            "file:///w/node_modules/@types/node/index.d.ts"
        );
        assert_eq!(
            posix_uri("/w/a-b_c.d~e/f+g=h,i;j(k)!$&'*:l.rs"),
            "file:///w/a-b_c.d~e/f+g=h,i;j(k)!$&'*:l.rs"
        );
    }

    /// Servers answer in their own spelling, and the path has to come back
    /// either way: a VS Code derived server writes `c%3A`, others `C:`.
    #[test]
    fn windows_uris_decode_to_one_forward_slash_spelling() {
        let expected = Some("C:/Users/me/src/main.rs".to_string());
        assert_eq!(windows_path("file:///C:/Users/me/src/main.rs"), expected);
        assert_eq!(windows_path("file:///c%3A/Users/me/src/main.rs"), expected);
        assert_eq!(windows_path("file:///c:/Users/me/src/main.rs"), expected);
        assert_eq!(
            windows_path("file://localhost/C:/Users/me/src/main.rs"),
            expected
        );
        assert_eq!(windows_path("FILE:///C:/Users/me/src/main.rs"), expected);
        // Not RFC 8089, but some tools write the drive where the host goes.
        assert_eq!(windows_path("file://C:/Users/me/src/main.rs"), expected);
        assert_eq!(windows_path(r"file:///C:\Users\me\src\main.rs"), expected);
        assert_eq!(
            windows_path("file:///C:/My%20Projects/C%23%20app/%C3%A9.rs"),
            Some("C:/My Projects/C# app/é.rs".to_string())
        );
        assert_eq!(
            windows_path("file://fileserver/share/dir/file.rs"),
            Some("//fileserver/share/dir/file.rs".to_string())
        );
        assert_eq!(windows_path("file:///C:"), Some("C:/".to_string()));
        assert_eq!(windows_path("untitled:Untitled-1"), None);
        assert_eq!(windows_path("file:C:/relative"), None);
    }

    #[test]
    fn posix_uris_decode_escapes_and_refuse_other_hosts() {
        assert_eq!(
            posix_path("file:///home/me/My%20Projects/C%23%20app/%C3%A9.rs"),
            Some("/home/me/My Projects/C# app/é.rs".to_string())
        );
        assert_eq!(
            posix_path("file:///w/node_modules/%40types/node/index.d.ts"),
            Some("/w/node_modules/@types/node/index.d.ts".to_string())
        );
        assert_eq!(
            posix_path("file://localhost/etc/hosts"),
            Some("/etc/hosts".to_string())
        );
        assert_eq!(
            posix_path("file:/etc/hosts"),
            Some("/etc/hosts".to_string())
        );
        assert_eq!(
            posix_path("file:///a/b.rs#L10"),
            Some("/a/b.rs".to_string())
        );
        // A lone `%` is kept rather than refused.
        assert_eq!(
            posix_path("file:///a/100%.rs"),
            Some("/a/100%.rs".to_string())
        );
        assert_eq!(posix_path("file://otherhost/etc/hosts"), None);
        assert_eq!(posix_path("file:///a%00b"), None);
        assert_eq!(posix_path("https://example.com/a.rs"), None);
        assert_eq!(posix_path("file"), None);
    }

    /// Encoding what a URI decodes to gives the URI back, so a spelling Kin
    /// wrote survives a server's answer and a comparison of the two.
    #[test]
    fn a_uri_survives_decoding_and_encoding_again() {
        for path in [
            r"C:\Users\me\src\main.rs",
            r"\\?\C:\Users\me\repo\src/lib.rs",
            r"\\fileserver\share\dir\file.rs",
            r"\\?\UNC\fileserver\share\dir\file.rs",
            r"C:\My Projects\C# app\100%\é.rs",
            r"\\?\Volume{0b1f}\dir\file.rs",
            "D:",
            "d:/",
        ] {
            let uri = windows_uri(path);
            let decoded = path_from_file_uri(&uri, PathStyle::Windows).unwrap();
            assert_eq!(
                file_uri_from_path(&decoded, PathStyle::Windows),
                uri,
                "{path}"
            );
        }
        for path in ["/home/me/src/lib.rs", "/tmp/a b#c?d%e/é.rs", r"/tmp/a\b"] {
            let uri = posix_uri(path);
            assert_eq!(posix_path(&uri).as_deref(), Some(path));
        }
    }

    #[test]
    fn equal_files_compare_equal_across_server_spellings() {
        assert!(same_file_uri_in(
            "file:///c%3A/repo/src/lib.rs",
            "file:///C:/repo/src/lib.rs",
            PathStyle::Windows
        ));
        assert!(same_file_uri_in(
            "file:///C:/repo/my%20dir/a.py",
            &windows_uri(r"\\?\C:\repo\my dir/a.py"),
            PathStyle::Windows
        ));
        assert!(same_file_uri_in(
            "file:///w/packages/%40scope/x.ts",
            "file:///w/packages/@scope/x.ts",
            PathStyle::Posix
        ));
        assert!(!same_file_uri_in(
            "file:///C:/repo/a.py",
            "file:///D:/repo/a.py",
            PathStyle::Windows
        ));
        assert!(!same_file_uri_in(
            "file:///repo/a.py",
            "file:///repo/b.py",
            PathStyle::Posix
        ));
        assert!(!same_file_uri_in(
            "untitled:a",
            "untitled:b",
            PathStyle::Posix
        ));
    }

    /// The host functions the rest of the crate calls go through the same
    /// conversion, and a path comes back as the path that went in.
    #[test]
    fn host_paths_round_trip_through_their_uri() {
        let dir = std::env::temp_dir().join("kin lsp uri #1").join("é?.rs");
        let uri = path_to_uri(&dir);
        assert!(uri.starts_with("file:///"), "{uri}");
        assert!(
            !uri.contains(' ') && !uri.contains('#') && !uri.contains('\\'),
            "{uri}"
        );
        assert_eq!(uri_to_path(&uri).as_deref(), Some(dir.as_path()));
    }
}

#[cfg(test)]
mod initialize_params_tests {
    use super::*;

    /// The initialize payload names the root as its one workspace folder, with
    /// the same URI as `rootUri`, and sends no `rootPath`.
    #[test]
    fn the_workspace_root_is_sent_as_the_one_workspace_folder() {
        let root = std::env::temp_dir().join("kin lsp root").join("repo");
        let params = InitializeParams::for_workspace(&root, None);
        let sent = serde_json::to_value(&params).unwrap();

        let root_uri = path_to_uri(&root);
        assert_eq!(sent["rootUri"], serde_json::json!(root_uri));
        assert_eq!(
            sent["workspaceFolders"],
            serde_json::json!([{ "uri": root_uri, "name": "repo" }]),
            "{sent}"
        );
        assert!(sent.get("rootPath").is_none(), "{sent}");
        assert!(
            sent["capabilities"].get("workspace").is_none(),
            "no workspace capability is claimed by a start that carries no settings\n{sent}"
        );
        assert_eq!(
            uri_to_path(sent["workspaceFolders"][0]["uri"].as_str().unwrap()).as_deref(),
            Some(root.as_path()),
            "the folder names the root itself"
        );
    }

    /// Initialization options pass through beside the folder.
    #[test]
    fn initialization_options_travel_with_the_folder() {
        let root = std::env::temp_dir().join("repo");
        let options = serde_json::json!({"diagnosticMode": "off"});
        let sent = serde_json::to_value(InitializeParams::for_workspace(
            &root,
            Some(options.clone()),
        ))
        .unwrap();
        assert_eq!(sent["initializationOptions"], options);
        assert_eq!(sent["workspaceFolders"].as_array().map(Vec::len), Some(1));
    }

    /// A root with no final component is still named, by its URI.
    #[test]
    fn a_root_without_a_final_component_is_named_by_its_uri() {
        let root = std::path::Path::new("/");
        let folder = WorkspaceFolder::for_root(root);
        assert_eq!(folder.name, folder.uri);
    }

    /// A launch with settings claims `workspace.configuration`, so the server
    /// asks for them; one that waits for server status claims rust-analyzer's
    /// status notification. A launch with neither claims neither, and its
    /// payload is exactly the plain workspace start.
    #[test]
    fn a_launch_claims_only_the_capabilities_it_serves() {
        use crate::adapters::{LoadCheck, ServerLaunch};
        let root = std::env::temp_dir().join("repo");

        let plain = serde_json::to_value(InitializeParams::for_launch(
            &root,
            &ServerLaunch::with_initialization_options(Some(serde_json::json!({"a": 1}))),
        ))
        .unwrap();
        assert_eq!(
            plain,
            serde_json::to_value(InitializeParams::for_workspace(
                &root,
                Some(serde_json::json!({"a": 1}))
            ))
            .unwrap()
        );
        assert!(plain["capabilities"].get("workspace").is_none(), "{plain}");
        assert!(
            plain["capabilities"].get("experimental").is_none(),
            "{plain}"
        );

        let launch = ServerLaunch {
            settings: Some(serde_json::json!({"python": {"pythonPath": "/env/bin/python"}})),
            load_check: Some(LoadCheck::ServerStatus),
            ..ServerLaunch::default()
        };
        let sent = serde_json::to_value(InitializeParams::for_launch(&root, &launch)).unwrap();
        assert_eq!(
            sent["capabilities"]["workspace"],
            serde_json::json!({"configuration": true})
        );
        assert_eq!(
            sent["capabilities"]["experimental"],
            serde_json::json!({"serverStatusNotification": true})
        );
        assert!(
            sent.get("initializationOptions").is_none(),
            "settings travel by request, not in the initialize payload: {sent}"
        );
    }
}
