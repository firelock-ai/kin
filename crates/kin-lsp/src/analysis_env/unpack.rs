// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Unpacking verified archives into the store, as plain files and nothing
//! else.
//!
//! An archive is data from the network even after its digest matched the
//! lock, so every entry is checked before it lands: no absolute path, no
//! `..`, no device or FIFO, and no link that leaves the tree it is unpacked
//! into. Wheels carry no links at all, so a link in one is refused; a CPython
//! build carries relative ones (`bin/python3 -> python3.11`) and keeps them.
//! Totals are bounded so a hostile archive costs a bounded amount of disk.
//! Nothing unpacked is ever executed.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// The most an archive may unpack to.
pub const MAX_UNPACKED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// The most entries an archive may hold.
pub const MAX_ENTRIES: usize = 500_000;

/// What an unpack wrote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Unpacked {
    pub files: usize,
    pub bytes: u64,
}

/// `relative` as a path inside the tree, or `None` when it would leave it.
fn contained(relative: &Path) -> Option<PathBuf> {
    let mut clean = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!clean.as_os_str().is_empty()).then_some(clean)
}

/// Whether a link at `entry` pointing to `target` stays inside the tree.
fn link_stays_inside(entry: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth: i64 = entry.components().count() as i64 - 1;
    for component in target.components() {
        match component {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            _ => return false,
        }
        if depth < 0 {
            return false;
        }
    }
    true
}

fn copy_bounded(reader: &mut dyn Read, path: &Path, total: &mut Unpacked) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    }
    let mut file =
        std::fs::File::create(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let budget = MAX_UNPACKED_BYTES.saturating_sub(total.bytes);
    let written = std::io::copy(&mut reader.take(budget + 1), &mut file)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if written > budget {
        return Err(format!(
            "the archive unpacks to more than {MAX_UNPACKED_BYTES} bytes"
        ));
    }
    total.bytes += written;
    total.files += 1;
    if total.files > MAX_ENTRIES {
        return Err(format!("the archive holds more than {MAX_ENTRIES} entries"));
    }
    Ok(())
}

/// Unpack a zip archive (a wheel) into `destination`, which must not exist
/// yet. Links are refused.
pub fn unzip(archive: &Path, destination: &Path) -> Result<Unpacked, String> {
    let file =
        std::fs::File::open(archive).map_err(|error| format!("{}: {error}", archive.display()))?;
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(file))
        .map_err(|error| format!("{} is not a zip archive: {error}", archive.display()))?;
    if zip.len() > MAX_ENTRIES {
        return Err(format!("the archive holds more than {MAX_ENTRIES} entries"));
    }
    std::fs::create_dir_all(destination)
        .map_err(|error| format!("{}: {error}", destination.display()))?;
    let mut total = Unpacked::default();
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|error| format!("{}: {error}", archive.display()))?;
        let name = entry.name().to_string();
        let relative = contained(Path::new(&name))
            .ok_or_else(|| format!("the entry `{name}` would land outside the archive's tree"))?;
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(format!(
                "the entry `{name}` is a link, which no wheel holds"
            ));
        }
        let path = destination.join(&relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
        } else {
            copy_bounded(&mut entry, &path, &mut total)?;
        }
    }
    Ok(total)
}

/// How much of a tar archive's own layout an unpack keeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TarLayout {
    /// Keep links that stay inside the tree, as a CPython build needs.
    pub links: bool,
    /// Keep the executable bit of files that have it, as a CPython build's
    /// interpreter needs. Every other mode bit is dropped.
    pub executables: bool,
}

impl TarLayout {
    /// Data only: regular files, readable, never executable, and no links.
    pub const DATA: TarLayout = TarLayout {
        links: false,
        executables: false,
    };
    /// A toolchain build: its links and executables kept.
    pub const TOOLCHAIN: TarLayout = TarLayout {
        links: true,
        executables: true,
    };
}

/// Unpack a gzip-compressed tar archive into `destination`, which must not
/// exist yet. Regular files and directories land; a link lands only when the
/// layout keeps links and it stays inside the tree; anything else is
/// refused.
pub fn untar_gz(archive: &Path, destination: &Path, layout: TarLayout) -> Result<Unpacked, String> {
    let file =
        std::fs::File::open(archive).map_err(|error| format!("{}: {error}", archive.display()))?;
    let decoder = flate2::read::GzDecoder::new(std::io::BufReader::new(file));
    unpack_tar(decoder, destination, layout)
        .map_err(|error| format!("{}: {error}", archive.display()))
}

fn unpack_tar(
    reader: impl Read,
    destination: &Path,
    layout: TarLayout,
) -> Result<Unpacked, String> {
    let keep_links = layout.links;
    let mut tar = tar::Archive::new(reader);
    std::fs::create_dir_all(destination)
        .map_err(|error| format!("{}: {error}", destination.display()))?;
    let mut total = Unpacked::default();
    let entries = tar
        .entries()
        .map_err(|error| format!("not a tar archive: {error}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| format!("tar entry: {error}"))?;
        let name = entry
            .path()
            .map_err(|error| format!("tar entry: {error}"))?
            .into_owned();
        let Some(relative) = contained(&name) else {
            // A lone `./` entry names the root itself.
            if name.components().all(|c| matches!(c, Component::CurDir)) {
                continue;
            }
            return Err(format!(
                "the entry `{}` would land outside the archive's tree",
                name.display()
            ));
        };
        let path = destination.join(&relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            std::fs::create_dir_all(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
        } else if kind.is_file() || kind == tar::EntryType::Continuous {
            let executable = entry.header().mode().is_ok_and(|mode| mode & 0o111 != 0);
            copy_bounded(&mut entry, &path, &mut total)?;
            if layout.executables && executable {
                make_executable(&path)?;
            }
        } else if kind.is_symlink() && keep_links {
            let target = entry
                .link_name()
                .map_err(|error| format!("tar entry: {error}"))?
                .ok_or_else(|| format!("the link `{}` names no target", name.display()))?
                .into_owned();
            if !link_stays_inside(&relative, &target) {
                return Err(format!(
                    "the link `{}` points outside the archive's tree",
                    name.display()
                ));
            }
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)
                    .map_err(|error| format!("{}: {error}", dir.display()))?;
            }
            make_link(&target, &path)?;
        } else if kind.is_hard_link() && keep_links {
            let target = entry
                .link_name()
                .map_err(|error| format!("tar entry: {error}"))?
                .and_then(|target| contained(&target))
                .ok_or_else(|| {
                    format!("the hard link `{}` points outside the tree", name.display())
                })?;
            std::fs::copy(destination.join(&target), &path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
        } else if kind.is_pax_global_extensions()
            || kind.is_pax_local_extensions()
            || kind.is_gnu_longname()
            || kind.is_gnu_longlink()
        {
            continue;
        } else {
            return Err(format!(
                "the entry `{}` is a {:?}, which is not unpacked",
                name.display(),
                kind
            ));
        }
    }
    Ok(total)
}

/// Read counters identify the decoder's consumed prefix, not an exact corrupt
/// byte: compressed reads may include buffered lookahead.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct UnpackFailure {
    pub phase: &'static str,
    pub compressed_bytes_read: u64,
    pub decoded_bytes_read: u64,
    pub reason: String,
}

struct Counted<'a, R> {
    inner: R,
    read: &'a std::cell::Cell<u64>,
    limit: u64,
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        let total = self.read.get().saturating_add(count as u64);
        self.read.set(total);
        if total > self.limit {
            return Err(std::io::Error::other(
                "archive decoding exceeded its byte limit",
            ));
        }
        Ok(count)
    }
}

fn observe_gzip(
    file: &mut std::fs::File,
    phase: &'static str,
    operation: impl FnOnce(&mut dyn Read) -> Result<Unpacked, String>,
) -> Result<Unpacked, UnpackFailure> {
    let compressed = std::cell::Cell::new(0);
    let decoded = std::cell::Cell::new(0);
    let source = Counted {
        inner: file,
        read: &compressed,
        limit: u64::MAX,
    };
    let mut reader = Counted {
        inner: flate2::read::GzDecoder::new(std::io::BufReader::new(source)),
        read: &decoded,
        // Account for tar headers/padding as well as the extracted bytes.
        limit: MAX_UNPACKED_BYTES + MAX_ENTRIES as u64 * 1024,
    };
    let result = operation(&mut reader)
        .map_err(|reason| (phase, reason))
        .and_then(|total| {
            // A tar end marker may precede the gzip checksum. Verify it too.
            std::io::copy(&mut reader, &mut std::io::sink())
                .map_err(|error| ("gzip-trailer", error.to_string()))?;
            Ok(total)
        });
    result.map_err(|(phase, reason)| UnpackFailure {
        phase,
        compressed_bytes_read: compressed.get(),
        decoded_bytes_read: decoded.get(),
        reason,
    })
}

#[derive(Default)]
struct CasePaths {
    paths: std::collections::BTreeMap<Vec<u8>, PathBuf>,
    bytes: usize,
}

impl CasePaths {
    fn insert(&mut self, relative: &Path) -> Result<(), String> {
        let mut prefix = PathBuf::new();
        for component in relative.components() {
            prefix.push(component);
            let key = prefix.as_os_str().as_encoded_bytes().to_ascii_lowercase();
            if let Some(previous) = self.paths.get(&key) {
                if previous != &prefix {
                    return Err(format!(
                        "this case-insensitive destination cannot represent both `{}` and `{}`;                          use a case-sensitive filesystem for KIN_HOME (for a Linux container, a native volume)",
                        previous.display(), prefix.display()
                    ));
                }
            } else {
                self.bytes = self.bytes.saturating_add(key.len());
                if self.bytes > 16 * 1024 * 1024 {
                    return Err("archive case-compatibility inventory exceeds 16 MiB".into());
                }
                self.paths.insert(key, prefix.clone());
            }
        }
        Ok(())
    }
}

/// Use the already hashed, open archive. On an insensitive destination, prove
/// that every name is representable before creating the extraction directory.
/// The caller owns the parent and removes any incomplete attempt.
pub(crate) fn untar_gz_checked(
    file: &mut std::fs::File,
    destination: &Path,
    layout: TarLayout,
    case_insensitive: bool,
) -> Result<Unpacked, UnpackFailure> {
    use std::io::{Seek, SeekFrom};
    if case_insensitive {
        observe_gzip(file, "destination-compatibility", |reader| {
            let mut tar = tar::Archive::new(reader);
            let mut paths = CasePaths::default();
            for (index, entry) in tar
                .entries()
                .map_err(|error| error.to_string())?
                .enumerate()
            {
                if index >= MAX_ENTRIES {
                    return Err(format!("the archive holds more than {MAX_ENTRIES} entries"));
                }
                let entry = entry.map_err(|error| error.to_string())?;
                let name = entry.path().map_err(|error| error.to_string())?;
                if let Some(relative) = contained(&name) {
                    paths.insert(&relative)?;
                }
            }
            Ok(Unpacked::default())
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| UnpackFailure {
                phase: "archive-rewind",
                compressed_bytes_read: 0,
                decoded_bytes_read: 0,
                reason: error.to_string(),
            })?;
    }
    // Never reuse an incomplete tree, even though the legacy unpack helper
    // accepts an existing parent. This path owns every entry it extracts.
    std::fs::create_dir(destination).map_err(|error| UnpackFailure {
        phase: "destination-create",
        compressed_bytes_read: 0,
        decoded_bytes_read: 0,
        reason: error.to_string(),
    })?;
    observe_gzip(file, "tar-extract", |reader| {
        unpack_tar(reader, destination, layout)
    })
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn make_link(target: &Path, path: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, path).map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(not(unix))]
fn make_link(_target: &Path, path: &Path) -> Result<(), String> {
    Err(format!(
        "{}: links are unpacked only on unix hosts",
        path.display()
    ))
}

#[cfg(test)]
pub(crate) mod testing {
    //! Archives built in memory, for tests.

    use std::io::Write;
    use std::path::Path;

    /// Write a zip holding `files` (name, bytes) to `path`.
    pub(crate) fn write_zip(path: &Path, files: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for (name, bytes) in files {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }

    /// Write a gzip-compressed tar holding an executable, a link to it and a
    /// data file, as a CPython build lays out its `bin`.
    pub(crate) fn write_toolchain_tar_gz(path: &Path) {
        let file = std::fs::File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(encoder);
        for (name, mode, bytes) in [
            ("python/bin/python3.12", 0o755, &b"#!binary"[..]),
            ("python/lib/os.py", 0o644, &b"x = 1\n"[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(mode);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes).unwrap();
        }
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        tar.append_link(&mut link, "python/bin/python3", "python3.12")
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    /// Write a gzip-compressed tar holding `files` to `path`.
    pub(crate) fn write_tar_gz(path: &Path, files: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(encoder);
        for (name, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            tar.append_data(&mut header, name, *bytes).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    #[test]
    fn a_wheel_unpacks_to_its_files() {
        let dir = Fixture::new("unzip");
        let archive = dir.root.join("x.whl");
        write_zip(
            &archive,
            &[
                ("pkg/__init__.py", b"def f(): pass\n"),
                ("pkg-1.0.dist-info/METADATA", b"Name: pkg\n"),
            ],
        );
        let unpacked = unzip(&archive, &dir.root.join("out")).unwrap();
        assert_eq!(unpacked.files, 2);
        assert!(dir.root.join("out/pkg/__init__.py").is_file());
    }

    #[test]
    fn an_entry_that_escapes_the_tree_is_refused() {
        let dir = Fixture::new("unzip-escape");
        let archive = dir.root.join("x.whl");
        write_zip(&archive, &[("../evil.py", b"x")]);
        let error = unzip(&archive, &dir.root.join("out")).unwrap_err();
        assert!(error.contains("outside"), "{error}");
        assert!(!dir.root.join("evil.py").exists());
    }

    #[test]
    fn links_stay_inside_or_are_refused() {
        assert!(link_stays_inside(
            Path::new("python/bin/python3"),
            Path::new("python3.11")
        ));
        assert!(link_stays_inside(
            Path::new("python/lib/libx.dylib"),
            Path::new("../lib/liby.dylib")
        ));
        assert!(!link_stays_inside(
            Path::new("a/b"),
            Path::new("../../../etc/passwd")
        ));
        assert!(!link_stays_inside(
            Path::new("a/b"),
            Path::new("/etc/passwd")
        ));
    }

    /// A toolchain keeps its executables and inner links; data keeps
    /// neither, so nothing unpacked as data can be run or point elsewhere.
    #[cfg(unix)]
    #[test]
    fn only_a_toolchain_keeps_executables_and_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Fixture::new("untar-toolchain");
        let archive = dir.root.join("python.tar.gz");
        write_toolchain_tar_gz(&archive);
        let toolchain = dir.root.join("toolchain");
        untar_gz(&archive, &toolchain, TarLayout::TOOLCHAIN).unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&toolchain.join("python/bin/python3.12")), 0o755);
        assert_eq!(
            std::fs::read_link(toolchain.join("python/bin/python3")).unwrap(),
            Path::new("python3.12")
        );
        let data = dir.root.join("data");
        let error = untar_gz(&archive, &data, TarLayout::DATA).unwrap_err();
        assert!(error.contains("Symlink"), "{error}");
        assert_eq!(mode(&data.join("python/bin/python3.12")) & 0o111, 0);
    }

    #[test]
    fn case_collisions_are_refused_before_any_extraction() {
        let dir = Fixture::new("untar-case-conflict");
        let archive = dir.root.join("x.tar.gz");
        write_tar_gz(
            &archive,
            &[
                ("python/share/terminfo/E/Eterm-color", b"first"),
                ("python/share/terminfo/e/eterm-color", b"different"),
            ],
        );
        let destination = dir.root.join("out");
        let mut file = std::fs::File::open(&archive).unwrap();
        let error =
            untar_gz_checked(&mut file, &destination, TarLayout::TOOLCHAIN, true).unwrap_err();
        assert_eq!(error.phase, "destination-compatibility");
        assert!(error.reason.contains("case-insensitive"), "{error:?}");
        assert!(error.reason.contains("KIN_HOME"));
        assert!(error.compressed_bytes_read > 0);
        assert!(error.decoded_bytes_read > 0);
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn compatible_checked_toolchains_keep_bytes_links_and_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Fixture::new("untar-checked-toolchain");
        let archive = dir.root.join("x.tar.gz");
        write_toolchain_tar_gz(&archive);
        let destination = dir.root.join("out");
        let mut file = std::fs::File::open(&archive).unwrap();
        let unpacked =
            untar_gz_checked(&mut file, &destination, TarLayout::TOOLCHAIN, true).unwrap();
        assert_eq!(unpacked.files, 2);
        assert_eq!(
            std::fs::read(destination.join("python/lib/os.py")).unwrap(),
            b"x = 1\n"
        );
        assert_eq!(
            std::fs::read_link(destination.join("python/bin/python3")).unwrap(),
            Path::new("python3.12")
        );
        assert_eq!(
            std::fs::metadata(destination.join("python/bin/python3.12"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    fn a_checked_archive_never_reuses_an_existing_extraction_tree() {
        let dir = Fixture::new("untar-checked-existing");
        let archive = dir.root.join("x.tar.gz");
        write_tar_gz(&archive, &[("sentinel", b"replacement")]);
        let destination = dir.root.join("out");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("sentinel"), b"other owner").unwrap();
        let error = untar_gz_checked(
            &mut std::fs::File::open(archive).unwrap(),
            &destination,
            TarLayout::DATA,
            false,
        )
        .unwrap_err();
        assert_eq!(error.phase, "destination-create");
        assert_eq!(
            std::fs::read(destination.join("sentinel")).unwrap(),
            b"other owner"
        );
    }

    #[test]
    fn checked_extraction_reads_the_gzip_trailer_after_the_tar_end_marker() {
        let dir = Fixture::new("untar-checked-trailer");
        let archive = dir.root.join("x.tar.gz");
        write_tar_gz(&archive, &[("file", b"content")]);
        let mut bytes = std::fs::read(&archive).unwrap();
        let crc = bytes.len() - 8;
        bytes[crc] ^= 1;
        std::fs::write(&archive, bytes).unwrap();
        let error = untar_gz_checked(
            &mut std::fs::File::open(archive).unwrap(),
            &dir.root.join("out"),
            TarLayout::DATA,
            false,
        )
        .unwrap_err();
        assert!(matches!(error.phase, "tar-extract" | "gzip-trailer"));
        assert!(error.compressed_bytes_read > 0);
    }

    #[test]
    fn a_tarball_unpacks_its_regular_files() {
        let dir = Fixture::new("untar");
        let archive = dir.root.join("x.tar.gz");
        write_tar_gz(&archive, &[("pkg-1.0/pkg/__init__.py", b"x = 1\n")]);
        let unpacked = untar_gz(&archive, &dir.root.join("out"), TarLayout::DATA).unwrap();
        assert_eq!(unpacked.files, 1);
        assert!(dir.root.join("out/pkg-1.0/pkg/__init__.py").is_file());
    }
}
