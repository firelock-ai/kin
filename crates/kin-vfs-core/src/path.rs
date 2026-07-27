// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Byte-exact path identity for the VFS.
//!
//! Repository paths are sequences of bytes, not strings: Unix allows any
//! non-NUL, non-`/` byte in a file name, and the graph must preserve every
//! tracked name exactly. UTF-8 is a presentation property, never an authority
//! requirement. These types are the only path identities allowed on the VFS
//! protocol, in provider lookups, and in cache keys.
//!
//! [`VfsPath`] is a validated, workspace-relative path whose empty value is the
//! workspace root. [`VfsName`] is one validated path component (a directory
//! entry name). Both serialize as raw bytes and re-validate on deserialization,
//! so a malformed peer cannot inject `..`, absolute, NUL-bearing, or
//! empty-component paths through the wire.

use std::fmt;

use serde::de::{Deserializer, Error as DeError, SeqAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// Why a byte sequence is not a valid [`VfsPath`] or [`VfsName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VfsPathError {
    #[error("path must be workspace-relative, not absolute")]
    Absolute,
    #[error("path must not contain NUL")]
    Nul,
    #[error("path must not contain empty components")]
    EmptyComponent,
    #[error("path must not contain '.' or '..' components")]
    DotComponent,
    #[error("name must not be empty")]
    EmptyName,
    #[error("name must not contain '/'")]
    NameSeparator,
}

/// Validate one path component: non-empty, no `/`, no NUL, not `.`/`..`.
fn validate_component(component: &[u8]) -> Result<(), VfsPathError> {
    if component.is_empty() {
        return Err(VfsPathError::EmptyComponent);
    }
    if component == b"." || component == b".." {
        return Err(VfsPathError::DotComponent);
    }
    if component.contains(&0) {
        return Err(VfsPathError::Nul);
    }
    Ok(())
}

/// Render path bytes for humans: UTF-8 passes through, anything else is
/// byte-escaped. Presentation only — never an identity or lookup form.
fn display_bytes(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return formatter.write_str(text);
    }
    for byte in bytes {
        match byte {
            b'\\' => formatter.write_str("\\\\")?,
            0x20..=0x7e => write!(formatter, "{}", char::from(*byte))?,
            _ => write!(formatter, "\\x{byte:02x}")?,
        }
    }
    Ok(())
}

/// A validated, byte-exact, workspace-relative VFS path.
///
/// The empty path is the workspace root. Non-root paths are `/`-separated
/// components with no NUL bytes, no empty components, and no `.`/`..`
/// components. Serialized as raw bytes; deserialization re-validates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VfsPath(Vec<u8>);

impl VfsPath {
    /// The workspace root (the empty path).
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// Validate `bytes` as a workspace-relative path. Empty bytes are the root.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, VfsPathError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Ok(Self(bytes));
        }
        if bytes[0] == b'/' {
            return Err(VfsPathError::Absolute);
        }
        for component in bytes.split(|byte| *byte == b'/') {
            validate_component(component)?;
        }
        Ok(Self(bytes))
    }

    /// Validate a UTF-8 path. Convenience over [`VfsPath::from_bytes`].
    pub fn from_utf8(path: impl Into<String>) -> Result<Self, VfsPathError> {
        Self::from_bytes(path.into().into_bytes())
    }

    /// The exact path bytes (empty for the root).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume into the exact path bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// `true` when this is the workspace root.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The path's components, in order. Empty for the root.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.0
            .split(|byte| *byte == b'/')
            .filter(|component| !component.is_empty())
    }

    /// The final component, or `None` for the root.
    pub fn file_name(&self) -> Option<&[u8]> {
        if self.is_root() {
            return None;
        }
        Some(match self.0.iter().rposition(|byte| *byte == b'/') {
            Some(position) => &self.0[position + 1..],
            None => &self.0,
        })
    }

    /// The containing directory, or `None` for the root.
    pub fn parent(&self) -> Option<VfsPath> {
        if self.is_root() {
            return None;
        }
        Some(match self.0.iter().rposition(|byte| *byte == b'/') {
            Some(position) => Self(self.0[..position].to_vec()),
            None => Self::root(),
        })
    }

    /// Append one validated name component.
    pub fn join(&self, name: &VfsName) -> VfsPath {
        if self.is_root() {
            return Self(name.as_bytes().to_vec());
        }
        let mut bytes = Vec::with_capacity(self.0.len() + 1 + name.as_bytes().len());
        bytes.extend_from_slice(&self.0);
        bytes.push(b'/');
        bytes.extend_from_slice(name.as_bytes());
        Self(bytes)
    }

    /// `true` when `self` is a directory prefix of `descendant` (component
    /// boundary respected). The root contains every non-root path. A path does
    /// not contain itself.
    pub fn is_ancestor_of(&self, descendant: &VfsPath) -> bool {
        if descendant.is_root() {
            return false;
        }
        if self.is_root() {
            return true;
        }
        descendant.0.len() > self.0.len()
            && descendant.0.starts_with(&self.0)
            && descendant.0[self.0.len()] == b'/'
    }

    /// The remaining path after directory `self`, or `None` when `self` is not
    /// an ancestor.
    pub fn strip_dir_prefix<'a>(&self, descendant: &'a VfsPath) -> Option<&'a [u8]> {
        if !self.is_ancestor_of(descendant) {
            return None;
        }
        if self.is_root() {
            Some(&descendant.0)
        } else {
            Some(&descendant.0[self.0.len() + 1..])
        }
    }
}

impl TryFrom<&str> for VfsPath {
    type Error = VfsPathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_utf8(value)
    }
}

impl TryFrom<&[u8]> for VfsPath {
    type Error = VfsPathError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value.to_vec())
    }
}

impl fmt::Display for VfsPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_bytes(&self.0, formatter)
    }
}

impl Serialize for VfsPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for VfsPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = deserializer.deserialize_byte_buf(BytesVisitor("a byte-exact VFS path"))?;
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

/// One validated directory-entry name: non-empty bytes with no `/`, no NUL,
/// and not `.`/`..`. Serialized as raw bytes; deserialization re-validates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VfsName(Vec<u8>);

impl VfsName {
    /// Validate `bytes` as one path component.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, VfsPathError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(VfsPathError::EmptyName);
        }
        if bytes.contains(&b'/') {
            return Err(VfsPathError::NameSeparator);
        }
        validate_component(&bytes)?;
        Ok(Self(bytes))
    }

    /// Validate a UTF-8 name. Convenience over [`VfsName::from_bytes`].
    pub fn from_utf8(name: impl Into<String>) -> Result<Self, VfsPathError> {
        Self::from_bytes(name.into().into_bytes())
    }

    /// The exact name bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume into the exact name bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<&str> for VfsName {
    type Error = VfsPathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_utf8(value)
    }
}

impl TryFrom<&[u8]> for VfsName {
    type Error = VfsPathError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value.to_vec())
    }
}

impl fmt::Display for VfsName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_bytes(&self.0, formatter)
    }
}

impl Serialize for VfsName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for VfsName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = deserializer.deserialize_byte_buf(BytesVisitor("a byte-exact VFS name"))?;
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

/// Visitor accepting bytes in every serde encoding a format may choose
/// (`bytes`, `byte_buf`, or a sequence of `u8`).
struct BytesVisitor(&'static str);

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }

    fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(value.to_vec())
    }

    fn visit_byte_buf<E: DeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(byte) = seq.next_element::<u8>()? {
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_empty_and_valid() {
        let root = VfsPath::root();
        assert!(root.is_root());
        assert_eq!(root.as_bytes(), b"");
        assert_eq!(VfsPath::from_bytes(Vec::new()).unwrap(), root);
        assert_eq!(root.components().count(), 0);
        assert_eq!(root.file_name(), None);
        assert_eq!(root.parent(), None);
    }

    #[test]
    fn non_utf8_bytes_are_first_class_identity() {
        let raw = b"logs/x-\xff\xfe.log".to_vec();
        let path = VfsPath::from_bytes(raw.clone()).unwrap();
        assert_eq!(path.as_bytes(), raw.as_slice());
        assert_eq!(path.file_name(), Some(&b"x-\xff\xfe.log"[..]));
        assert_eq!(path.parent().unwrap().as_bytes(), b"logs");
        assert_eq!(path.to_string(), "logs/x-\\xff\\xfe.log");
    }

    #[test]
    fn invalid_paths_are_rejected() {
        assert_eq!(
            VfsPath::from_bytes(b"/abs".to_vec()),
            Err(VfsPathError::Absolute)
        );
        assert_eq!(
            VfsPath::from_bytes(b"a\0b".to_vec()),
            Err(VfsPathError::Nul)
        );
        for empty in [&b"a//b"[..], b"a/", b"trailing//"] {
            assert_eq!(
                VfsPath::from_bytes(empty.to_vec()),
                Err(VfsPathError::EmptyComponent),
                "{empty:?}"
            );
        }
        for dotted in [&b"."[..], b"..", b"a/./b", b"a/../b", b"a/.."] {
            assert_eq!(
                VfsPath::from_bytes(dotted.to_vec()),
                Err(VfsPathError::DotComponent),
                "{dotted:?}"
            );
        }
    }

    #[test]
    fn join_parent_roundtrip() {
        let name = VfsName::from_bytes(b"main.rs".to_vec()).unwrap();
        let src = VfsPath::from_utf8("src").unwrap();
        let joined = src.join(&name);
        assert_eq!(joined.as_bytes(), b"src/main.rs");
        assert_eq!(joined.parent().unwrap(), src);
        assert_eq!(VfsPath::root().join(&name).as_bytes(), b"main.rs");
    }

    #[test]
    fn ancestor_checks_respect_component_boundaries() {
        let root = VfsPath::root();
        let src = VfsPath::from_utf8("src").unwrap();
        let srcx = VfsPath::from_utf8("srcx").unwrap();
        let deep = VfsPath::from_utf8("src/util/helpers.rs").unwrap();

        assert!(root.is_ancestor_of(&src));
        assert!(root.is_ancestor_of(&deep));
        assert!(src.is_ancestor_of(&deep));
        assert!(!srcx.is_ancestor_of(&deep));
        assert!(!src.is_ancestor_of(&src));
        assert!(!src.is_ancestor_of(&srcx));
        assert!(!deep.is_ancestor_of(&src));
        assert_eq!(src.strip_dir_prefix(&deep), Some(&b"util/helpers.rs"[..]));
        assert_eq!(
            root.strip_dir_prefix(&deep),
            Some(&b"src/util/helpers.rs"[..])
        );
        assert_eq!(srcx.strip_dir_prefix(&deep), None);
    }

    #[test]
    fn names_reject_separators_dots_and_nul() {
        assert!(VfsName::from_bytes(b"ok-name".to_vec()).is_ok());
        assert!(VfsName::from_bytes(b"caf\xc3\xa9".to_vec()).is_ok());
        assert!(VfsName::from_bytes(b"raw-\xff".to_vec()).is_ok());
        assert_eq!(
            VfsName::from_bytes(Vec::new()),
            Err(VfsPathError::EmptyName)
        );
        assert_eq!(
            VfsName::from_bytes(b"a/b".to_vec()),
            Err(VfsPathError::NameSeparator)
        );
        assert_eq!(
            VfsName::from_bytes(b".".to_vec()),
            Err(VfsPathError::DotComponent)
        );
        assert_eq!(
            VfsName::from_bytes(b"..".to_vec()),
            Err(VfsPathError::DotComponent)
        );
        assert_eq!(VfsName::from_bytes(b"a\0".to_vec()), Err(VfsPathError::Nul));
    }

    #[test]
    fn serde_roundtrips_exact_bytes_and_revalidates() {
        let path = VfsPath::from_bytes(b"dir/x-\xff.bin".to_vec()).unwrap();
        let wire = rmp_serde::to_vec(&path).unwrap();
        let decoded: VfsPath = rmp_serde::from_slice(&wire).unwrap();
        assert_eq!(decoded, path);

        let name = VfsName::from_bytes(b"x-\xff.bin".to_vec()).unwrap();
        let wire = rmp_serde::to_vec(&name).unwrap();
        let decoded: VfsName = rmp_serde::from_slice(&wire).unwrap();
        assert_eq!(decoded, name);

        // Malformed wire bytes must be rejected at decode time, not accepted
        // as identity.
        let absolute = rmp_serde::to_vec(&serde_bytes_wrapper(b"/etc/passwd")).unwrap();
        assert!(rmp_serde::from_slice::<VfsPath>(&absolute).is_err());
        let dotted = rmp_serde::to_vec(&serde_bytes_wrapper(b"a/../b")).unwrap();
        assert!(rmp_serde::from_slice::<VfsPath>(&dotted).is_err());
        let separator = rmp_serde::to_vec(&serde_bytes_wrapper(b"a/b")).unwrap();
        assert!(rmp_serde::from_slice::<VfsName>(&separator).is_err());
    }

    /// Serialize raw bytes exactly as `VfsPath`/`VfsName` do (`serialize_bytes`).
    fn serde_bytes_wrapper(bytes: &[u8]) -> impl Serialize + '_ {
        struct Raw<'a>(&'a [u8]);
        impl Serialize for Raw<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(self.0)
            }
        }
        Raw(bytes)
    }
}
