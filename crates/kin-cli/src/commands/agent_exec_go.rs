// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The launcher's half of keeping `kin_session_exec`'s Go targets inside the
//! repository.
//!
//! [`kin_mcp::session_exec`] judges a `go build`, `go run`, `go test` or `go
//! vet` target by its words. What only the session workspace can say is read
//! here, statically and before anything runs:
//!
//! * the repository's own modules, and the modules the build takes from
//!   elsewhere, from the `module`, `require`, `replace` and `use` directives of
//!   the committed go.mod and go.work files;
//! * where each target resolves once symbolic links are followed, and which
//!   go.mod governs it, so a path that leaves the workspace or lands in a
//!   nested module of its own is refused;
//! * for `go run`, whether the `.go` files it names are a main package's, and
//!   which main package a `...` pattern matches;
//! * the GOFLAGS and GO111MODULE a go command inherits from the server's
//!   environment or its Go environment file, which could change which module
//!   owns a target.
//!
//! Nothing is executed to decide, and nothing is fetched. These reads are an
//! execution-admission boundary, like the launcher's read of the workspace's
//! top-level names: no answer about the code comes from them, and a refusal
//! names paths and module paths, never a file's text. GOWORK is pinned for
//! every go command exec runs, to the repository's own go.work or `off`, so
//! the go.work this module reads is the one the command uses.

use std::io::Read;
use std::path::{Path, PathBuf};

use kin_mcp::session_exec::{
    outside_repository, refused_inherited_goflags, unverifiable_go_env_file, CommandRefusal,
    GoModule, GoModules, GoTargets, RefusalKind,
};

/// The most bytes read of a go.mod, go.work or Go environment file.
const MANIFEST_BYTES: u64 = 1 << 20;

/// The most bytes read of a `.go` file to find its package clause.
const PACKAGE_CLAUSE_BYTES: u64 = 64 * 1024;

/// The most directory entries one `go run` pattern's walk reads.
const WALK_BUDGET: usize = 20_000;

/// The GOWORK every go command exec runs is given: the repository's own
/// go.work when the workspace root holds one as a regular file, and `off`
/// otherwise, so neither the server's environment nor a go.work above the
/// workspace changes which modules the command builds.
pub(crate) fn pinned_gowork(root: &Path) -> std::ffi::OsString {
    let work = root.join("go.work");
    match std::fs::symlink_metadata(&work) {
        Ok(meta) if meta.file_type().is_file() => work.into_os_string(),
        _ => "off".into(),
    }
}

/// The Go settings a go command inherits that decide who owns a package, as
/// the command will see them: each from the server's environment when it is
/// set there, and from the Go environment file otherwise.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct GoEnvironment {
    /// The effective GOFLAGS and where it comes from.
    pub goflags: Option<(String, String)>,
    /// Where GO111MODULE=off comes from, when it is off.
    pub modules_off: Option<String>,
    /// The Go environment file and why it could not be verified the way Go
    /// reads it, when it could not.
    pub unverified_file: Option<(String, String)>,
}

impl GoEnvironment {
    /// Read from this process's environment and the Go environment file it
    /// names or implies.
    pub(crate) fn inherited() -> Self {
        Self::read(|name| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned()))
    }

    /// Read through `env`, which looks up one variable of the environment
    /// the command inherits.
    pub(crate) fn read(env: impl Fn(&str) -> Option<String>) -> Self {
        let file = go_env_file(&env);
        let (file_values, unverified_file) = match file.as_deref().map(read_go_env_file) {
            None | Some(EnvFile::Absent) => (None, None),
            Some(EnvFile::Values(values)) => (file.as_deref().map(|path| (path, values)), None),
            Some(EnvFile::Unverifiable(why)) => (
                None,
                file.as_deref()
                    .map(|path| (path.display().to_string(), why)),
            ),
        };
        // Go's cfg.Getenv: a non-empty variable in the environment wins, and the
        // file's value is used otherwise. An empty value sets nothing.
        let lookup = |name: &str| -> Option<(String, String)> {
            if let Some(value) = env(name).filter(|value| !value.is_empty()) {
                return Some((value, "the Kin server's environment".to_string()));
            }
            let (path, values) = file_values.as_ref()?;
            let value = values.get(name).filter(|value| !value.is_empty())?;
            Some((
                value.clone(),
                format!("the Go environment file {}", path.display()),
            ))
        };
        Self {
            goflags: lookup("GOFLAGS"),
            modules_off: lookup("GO111MODULE")
                .filter(|(value, _)| value == "off")
                .map(|(_, source)| source),
            unverified_file,
        }
    }

    /// A refusal when the inherited GOFLAGS carries a flag exec refuses in
    /// argv.
    pub(crate) fn refusal(&self) -> Option<CommandRefusal> {
        if let Some((path, why)) = &self.unverified_file {
            return Some(unverifiable_go_env_file(path, why));
        }
        let (value, source) = self.goflags.as_ref()?;
        refused_inherited_goflags(value, source)
    }
}

/// The Go environment file a go command reads: GOENV when it is set, none
/// when it is `off`, and `go/env` under the user's configuration directory
/// otherwise.
fn go_env_file(env: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    match env("GOENV").filter(|value| !value.is_empty()) {
        Some(value) if value == "off" => None,
        Some(value) => Some(PathBuf::from(value)),
        None => directories::BaseDirs::new().map(|dirs| dirs.config_dir().join("go").join("env")),
    }
}

/// A Go environment file as Go's `readEnvFile` sees it.
#[derive(Debug, PartialEq, Eq)]
enum EnvFile {
    /// Missing, a directory, or unreadable: Go ignores it, and so does exec.
    Absent,
    /// Its settings, the last line for a key winning.
    Values(std::collections::HashMap<String, String>),
    /// A file exec will not guess about: larger than exec reads, or not a
    /// regular file once symbolic links are followed.
    Unverifiable(String),
}

/// Read a Go environment file the way cmd/go's `readEnvFile` does: the whole
/// file, following symbolic links, one `KEY=VALUE` per line, a line counting
/// only when it starts with an ASCII capital letter and holds `=`, the key and
/// value taken byte for byte with nothing trimmed, and a later line for a key
/// replacing an earlier one. A file Go cannot read is ignored, as Go ignores
/// it. A file larger than exec reads is refused rather than cut short, so no
/// setting past the cut can go unseen.
fn read_go_env_file(path: &Path) -> EnvFile {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return EnvFile::Absent,
    };
    if meta.is_dir() {
        return EnvFile::Absent;
    }
    if !meta.is_file() {
        return EnvFile::Unverifiable("is not a regular file.".to_string());
    }
    if meta.len() > MANIFEST_BYTES {
        return EnvFile::Unverifiable(format!(
            "is {} bytes, more than the {MANIFEST_BYTES} exec reads.",
            meta.len()
        ));
    }
    let mut bytes = Vec::new();
    let read = std::fs::File::open(path)
        .and_then(|file| file.take(MANIFEST_BYTES + 1).read_to_end(&mut bytes));
    if read.is_err() {
        return EnvFile::Absent;
    }
    if bytes.len() as u64 > MANIFEST_BYTES {
        return EnvFile::Unverifiable(format!(
            "grew past the {MANIFEST_BYTES} bytes exec reads while it was read."
        ));
    }
    let mut values = std::collections::HashMap::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let Some(eq) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if !line[0].is_ascii_uppercase() {
            continue;
        }
        values.insert(
            String::from_utf8_lossy(&line[..eq]).into_owned(),
            String::from_utf8_lossy(&line[eq + 1..]).into_owned(),
        );
    }
    EnvFile::Values(values)
}

/// A regular file's text, at most `limit` bytes. `None` when it is missing,
/// is not a regular file, a symbolic link included, or cannot be read.
fn regular_file_text(path: &Path, limit: u64) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(limit)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// What a go.mod or go.work file declares that decides who owns a package.
#[derive(Debug, Default, PartialEq, Eq)]
struct ModFile {
    module: Option<String>,
    requires: Vec<String>,
    replaces: Vec<String>,
    uses: Vec<String>,
}

/// Read the `module`, `require`, `replace` and `use` directives of a go.mod
/// or go.work file, one line or a parenthesized block at a time. Only the
/// first word of each entry is kept: the module path, or for `replace` the
/// path it replaces, or for `use` the directory.
fn parse_mod_file(text: &str) -> ModFile {
    let mut parsed = ModFile::default();
    let mut block: Option<String> = None;
    for raw in text.lines() {
        let line = raw.split_once("//").map_or(raw, |(code, _)| code).trim();
        if line.is_empty() {
            continue;
        }
        if block.is_some() && line == ")" {
            block = None;
            continue;
        }
        let (verb, rest) = match &block {
            Some(verb) => (verb.clone(), line),
            None => {
                let end = line
                    .find(|c: char| c.is_whitespace() || c == '(')
                    .unwrap_or(line.len());
                let (verb, rest) = (&line[..end], line[end..].trim());
                if rest == "(" {
                    block = Some(verb.to_string());
                    continue;
                }
                (verb.to_string(), rest)
            }
        };
        let Some(first) = rest.split_whitespace().next().map(unquote) else {
            continue;
        };
        match verb.as_str() {
            "module" => parsed.module = Some(first),
            "require" => parsed.requires.push(first),
            "replace" => parsed.replaces.push(first),
            "use" => parsed.uses.push(first),
            _ => {}
        }
    }
    parsed
}

fn unquote(word: &str) -> String {
    for quote in ['"', '`'] {
        if let Some(inner) = word
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner.to_string();
        }
    }
    word.to_string()
}

/// A directory a go.work names, relative to the workspace root, or `None`
/// when it leaves the workspace.
fn workspace_relative(dir: &str) -> Option<String> {
    if dir.starts_with(['/', '\\', '~'])
        || dir.as_bytes().get(1) == Some(&b':')
        || dir.split(['/', '\\']).any(|part| part == "..")
    {
        return None;
    }
    let parts: Vec<&str> = dir
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    Some(if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    })
}

fn canonical(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

/// The repository's Go modules, read from the workspace at `root`: with a
/// go.work, each module it uses inside the workspace, and without one, the
/// module of the go.mod at the root. Every module those files require or
/// replace is another module's, and anything exec cannot read for certain
/// leaves import paths unresolved, which refuses them.
pub(crate) fn go_modules(root: &Path, env: &GoEnvironment) -> GoModules {
    let mut modules = GoModules::default();
    let unresolved = |why: String, modules: &mut GoModules| {
        modules.unresolved.get_or_insert(why);
    };
    if let Some(source) = &env.modules_off {
        unresolved(
            format!(
                "is an import path, and GO111MODULE=off from {source} turns modules off, so Go \
                 would look it up in GOPATH, outside the repository."
            ),
            &mut modules,
        );
    }
    let croot = canonical(root).unwrap_or_else(|| root.to_path_buf());
    let work = root.join("go.work");
    let dirs: Vec<String> = if std::fs::symlink_metadata(&work).is_ok() {
        match regular_file_text(&work, MANIFEST_BYTES) {
            None => {
                unresolved(
                    "is an import path, and the repository's go.work is not a regular file exec \
                     can read."
                        .to_string(),
                    &mut modules,
                );
                Vec::new()
            }
            Some(text) => {
                let parsed = parse_mod_file(&text);
                modules.other.extend(parsed.replaces);
                let mut dirs = Vec::new();
                for used in parsed.uses {
                    let inside = workspace_relative(&used).filter(|dir| {
                        canonical(&root.join(dir)).is_none_or(|path| path.starts_with(&croot))
                    });
                    match inside {
                        Some(dir) => dirs.push(dir),
                        None => unresolved(
                            format!(
                                "is an import path, and the repository's go.work uses {used}, \
                                 outside the workspace, so exec cannot tell which module owns it."
                            ),
                            &mut modules,
                        ),
                    }
                }
                dirs
            }
        }
    } else {
        vec![".".to_string()]
    };
    for dir in dirs {
        let manifest = root.join(&dir).join("go.mod");
        if std::fs::symlink_metadata(&manifest).is_err() {
            continue;
        }
        let parsed = regular_file_text(&manifest, MANIFEST_BYTES).map(|text| parse_mod_file(&text));
        match parsed {
            Some(ModFile {
                module: Some(path),
                requires,
                replaces,
                ..
            }) => {
                modules.main.push(GoModule { path, dir });
                modules.other.extend(requires);
                modules.other.extend(replaces);
            }
            _ => unresolved(
                format!(
                    "is an import path, and the go.mod in {dir} is not a regular file declaring a \
                     module path exec can read."
                ),
                &mut modules,
            ),
        }
    }
    let main: Vec<String> = modules
        .main
        .iter()
        .map(|module| module.path.clone())
        .collect();
    modules.other.retain(|path| !main.contains(path));
    modules.other.sort();
    modules.other.dedup();
    modules
}

/// What a target resolves to on disk, and which of the repository's modules
/// it must be in.
struct Disk<'a> {
    root: &'a Path,
    croot: PathBuf,
    /// Each main module's directory, canonical.
    module_dirs: Vec<PathBuf>,
}

impl Disk<'_> {
    /// `path` relative to the workspace, as a refusal names it.
    fn shown(&self, path: &Path) -> String {
        match path.strip_prefix(&self.croot) {
            Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
            Ok(rel) => format!("./{}", rel.display()),
            Err(_) => path.display().to_string(),
        }
    }

    /// `path`, canonical and inside the workspace, or the refusal.
    fn inside(&self, word: &str, path: &Path) -> Result<Option<PathBuf>, CommandRefusal> {
        let Some(resolved) = canonical(path) else {
            return Ok(None);
        };
        if resolved.starts_with(&self.croot) {
            return Ok(Some(resolved));
        }
        Err(CommandRefusal {
            kind: RefusalKind::PathOutsideWorkspace,
            reason: format!(
                "{word:?} resolves outside the session workspace through a symbolic link. Every \
                 path exec takes stays inside the workspace."
            ),
        })
    }

    /// Refuse `dir` unless the nearest go.mod at or above it in the
    /// workspace is one of the repository's modules.
    fn governed(&self, word: &str, dir: &Path) -> Result<(), CommandRefusal> {
        let mut at = Some(dir);
        while let Some(current) = at {
            if !current.starts_with(&self.croot) {
                break;
            }
            if std::fs::symlink_metadata(current.join("go.mod")).is_ok() {
                if self.module_dirs.iter().any(|module| module == current) {
                    return Ok(());
                }
                return Err(outside_repository(
                    word,
                    &format!(
                        "is in the module of {}/go.mod, which is not one of the repository's \
                         modules this workspace builds.",
                        self.shown(current)
                    ),
                ));
            }
            at = current.parent();
        }
        Err(outside_repository(
            word,
            "is governed by no go.mod inside the workspace. Create the module with go mod init \
             first.",
        ))
    }
}

/// Check a Go build, run, test or vet command's targets in the workspace at
/// `root` before it runs.
pub(crate) fn check_targets_on_disk(
    targets: &GoTargets,
    root: &Path,
    modules: &GoModules,
) -> Result<(), CommandRefusal> {
    let disk = Disk {
        root,
        croot: canonical(root).unwrap_or_else(|| root.to_path_buf()),
        module_dirs: modules
            .main
            .iter()
            .filter_map(|module| canonical(&root.join(&module.dir)))
            .collect(),
    };
    let base = match &targets.dir {
        Some(dir) => {
            let base = root.join(dir);
            disk.inside(&format!("-C {dir}"), &base)?;
            base
        }
        None => root.to_path_buf(),
    };
    let implied = [".".to_string()];
    let words: &[String] = match (&targets.packages[..], targets.run) {
        ([], true) => return Ok(()),
        ([], false) => &implied,
        (words, _) => words,
    };
    for word in words {
        if word.ends_with(".go") {
            check_file(&disk, &base, word, targets.run)?;
        } else if word == "." || word.starts_with("./") || word.starts_with(".\\") {
            check_directory(&disk, &base, word, word, targets.run, false)?;
        } else {
            let Some(owner) = modules.owner(word) else {
                return Err(outside_repository(
                    word,
                    "is not a package of the repository's own module.",
                ));
            };
            let local = format!(".{}", &word[owner.path.len()..]);
            // An import path Go could also resolve from another module, so the
            // package must be there in the repository's module.
            check_directory(
                &disk,
                &disk.root.join(&owner.dir),
                word,
                &local,
                targets.run,
                true,
            )?;
        }
    }
    Ok(())
}

/// A `.go` file argument: an existing file inside the workspace, in one of
/// the repository's modules, and for `go run` a main package's.
fn check_file(disk: &Disk<'_>, base: &Path, word: &str, run: bool) -> Result<(), CommandRefusal> {
    let path = base.join(word);
    let is_file = std::fs::metadata(&path).is_ok_and(|meta| meta.is_file());
    let resolved = if is_file {
        disk.inside(word, &path)?
    } else {
        None
    };
    let Some(resolved) = resolved else {
        return Err(outside_repository(
            word,
            "names no .go file in the workspace.",
        ));
    };
    let dir = resolved.parent().unwrap_or(&disk.croot);
    disk.governed(word, dir)?;
    if run && package_clause(&resolved).as_deref() != Some("main") {
        return Err(outside_repository(
            word,
            "is not a file of a main package, so it is not an application of the repository's \
             that go run can run.",
        ));
    }
    Ok(())
}

/// A directory or `...` pattern, written relative to `base` as `local`:
/// inside the workspace, in one of the repository's modules, and for `go
/// run` a pattern must match exactly one main package.
fn check_directory(
    disk: &Disk<'_>,
    base: &Path,
    word: &str,
    local: &str,
    run: bool,
    import_path: bool,
) -> Result<(), CommandRefusal> {
    let (dir, whole_tree) = match local.find("...") {
        None => (local, false),
        Some(at) => {
            let (literal, after) = (&local[..at], &local[at + 3..]);
            match literal.strip_suffix('/') {
                Some(dir) if after.is_empty() => (dir, true),
                _ if run => {
                    return Err(outside_repository(
                        word,
                        "is a pattern exec cannot match to one directory for go run. Name the \
                         main package's directory, such as ./cmd/app.",
                    ))
                }
                // Build, test and vet match any shape; the directory it starts
                // in is what must stay inside.
                _ => (literal.rsplit_once('/').map_or(".", |(dir, _)| dir), false),
            }
        }
    };
    let Some(resolved) = disk.inside(word, &base.join(dir))? else {
        if import_path {
            // A missing directory under the module's path is not evidence the
            // repository owns the package: with -mod=mod Go can resolve the same
            // import path from another module, a nested one included.
            return Err(outside_repository(
                word,
                "names no package directory in the repository's module, so Go could resolve \
                 it from another module. Name a package that exists in the repository, such as \
                 ./cmd/app.",
            ));
        }
        // Go reports a relative directory that is not there itself.
        return Ok(());
    };
    disk.governed(word, &resolved)?;
    if import_path && !whole_tree && go_package_in(&resolved).is_none() {
        return Err(outside_repository(
            word,
            "names a directory of the repository's module that holds no Go package, so Go could \
             resolve it from another module. Name a package that exists in the repository.",
        ));
    }
    if run && whole_tree {
        let mut budget = WALK_BUDGET;
        let found = main_package_dirs(&resolved, &mut budget);
        let shown: Vec<String> = found.iter().take(10).map(|dir| disk.shown(dir)).collect();
        let why = match (found.len(), budget == 0) {
            (_, true) => Some(
                "reaches more directories than exec reads to find its main package. Name the \
                 main package's directory, such as ./cmd/app."
                    .to_string(),
            ),
            (1, false) => None,
            (0, false) => Some("matches no main package of the repository.".to_string()),
            (count, false) => Some(format!(
                "matches {count} main packages ({}), and go run runs one. Name it, such as go run \
                 {}.",
                shown.join(", "),
                shown[0]
            )),
        };
        if let Some(why) = why {
            return Err(outside_repository(word, &why));
        }
    }
    Ok(())
}

/// The directories under `start` that hold a main package, the way Go's
/// `...` matches them: skipping hidden, `_`-prefixed, `testdata` and
/// `vendor` directories and nested modules, and never following a symbolic
/// link. Stops when `budget` directory entries have been read.
fn main_package_dirs(start: &Path, budget: &mut usize) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![start.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut is_main = false;
        let mut names: Vec<(String, std::fs::FileType)> = Vec::new();
        for entry in entries.flatten() {
            if *budget == 0 {
                return found;
            }
            *budget -= 1;
            if let (Ok(name), Ok(kind)) = (entry.file_name().into_string(), entry.file_type()) {
                names.push((name, kind));
            }
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, kind) in names {
            let skipped = name.starts_with(['.', '_']);
            if kind.is_dir() {
                let child = dir.join(&name);
                if skipped
                    || name == "testdata"
                    || name == "vendor"
                    || std::fs::symlink_metadata(child.join("go.mod")).is_ok()
                {
                    continue;
                }
                pending.push(child);
            } else if kind.is_file()
                && !is_main
                && !skipped
                && name.ends_with(".go")
                && !name.ends_with("_test.go")
            {
                is_main = package_clause(&dir.join(&name)).as_deref() == Some("main");
            }
        }
        if is_main {
            found.push(dir);
        }
    }
    found.sort();
    found
}

/// The package a directory holds, read from the package clause of its first
/// `.go` file that is not a test, hidden or `_`-prefixed, the way Go names it.
fn go_package_in(dir: &Path) -> Option<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            name.ends_with(".go") && !name.ends_with("_test.go") && !name.starts_with(['.', '_'])
        })
        .collect();
    names.sort();
    names
        .iter()
        .find_map(|name| package_clause(&dir.join(name)))
}

/// The package name a `.go` file declares: the identifier after `package`,
/// past any leading comments. Only the clause is read, and it never leaves
/// the launcher.
fn package_clause(path: &Path) -> Option<String> {
    let text = regular_file_text(path, PACKAGE_CLAUSE_BYTES)?;
    let mut rest = text.trim_start_matches('\u{feff}');
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.split_once('\n').map_or("", |(_, next)| next);
        } else if let Some(after) = rest.strip_prefix("/*") {
            rest = after.split_once("*/")?.1;
        } else {
            break;
        }
    }
    let after = rest.strip_prefix("package")?;
    if !after.starts_with(char::is_whitespace) {
        return None;
    }
    let name: String = after
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_mod_and_go_work_directives_are_read_statically() {
        let parsed = parse_mod_file(
            "// a comment\nmodule \"example.com/app\" // trailing\n\ngo 1.25\n\nrequire golang.org/x/tools v0.1.0\nrequire (\n\texample.com/app/tools v1.0.0 // indirect\n\tgithub.com/x/y v1.2.3\n)\nreplace example.com/lib => ../lib\nreplace (\n\tgolang.org/x/net v1.0.0 => ./third_party/net\n)\n",
        );
        assert_eq!(parsed.module.as_deref(), Some("example.com/app"));
        assert_eq!(
            parsed.requires,
            [
                "golang.org/x/tools",
                "example.com/app/tools",
                "github.com/x/y"
            ]
        );
        assert_eq!(parsed.replaces, ["example.com/lib", "golang.org/x/net"]);
        let work = parse_mod_file("go 1.25\n\nuse ./app\nuse (\n\t.\n\t\"./tools\"\n)\n");
        assert_eq!(work.uses, ["./app", ".", "./tools"]);
    }

    #[test]
    fn a_package_clause_is_read_past_leading_comments() {
        let dir = tempfile::tempdir().unwrap();
        for (name, text, expected) in [
            ("a.go", "package main\n", Some("main")),
            (
                "b.go",
                "// Copyright\n/* block\n comment */\n//go:build ignore\n\npackage main // x\n",
                Some("main"),
            ),
            ("c.go", "\u{feff}package store\n", Some("store")),
            ("d.go", "packagemain\n", None),
            ("e.go", "func main() {}\n", None),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, text).unwrap();
            assert_eq!(package_clause(&path).as_deref(), expected, "{name}");
        }
    }
}
