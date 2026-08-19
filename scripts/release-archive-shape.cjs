// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

"use strict";

const fs = require("node:fs");
const path = require("node:path");

// Directory name of the macOS notification bundle inside a release archive.
//
// Every other release component is a bare executable or shared library. This one
// cannot be: macOS reads a notification's sender name, icon, and grouping from
// the posting process's bundle, and codesign seals Info.plist and Resources
// alongside the executable, so flattening the bundle into loose files destroys
// both the identity and the signature. It therefore travels as a directory, and
// the release archive's shape rules have to say so explicitly rather than
// treating every directory as a tarbomb.
const NOTIFIER_BUNDLE_DIR = "KinNotifier.app";

// Bundle members whose absence leaves nothing to launch or nothing to attribute
// the notification to. A bundle missing either is broken in a way that only
// shows up as a wrong sender name at runtime, so it is rejected at release time.
const NOTIFIER_BUNDLE_EXECUTABLE = ["Contents", "MacOS", "KinNotifier"];
const NOTIFIER_BUNDLE_PLIST = ["Contents", "Info.plist"];

// A release archive is assembled from a fixed component list plus one bundle, so
// its shape is bounded. These caps turn "the archive grew something unexpected"
// into a failure rather than an unbounded walk over attacker-chosen structure.
const MAX_ARCHIVE_MEMBERS = 256;
const MAX_BUNDLE_ENTRIES = 64;
const MAX_BUNDLE_DEPTH = 6;

// Component file names a release archive root may carry, by target family.
//
// This is the release-build side of a two-sided contract. `kin update` stages a
// downloaded archive by matching every member's file name against the component
// list for the running platform and aborts the whole staging on the first name
// it does not manage. A stray file at the archive root therefore does not
// degrade an update, it stops every update on that platform until a new release
// replaces the archive. Naming the sanctioned set here is what keeps that
// failure inside the release build, where the archive can still be rebuilt.
//
// The set is an upper bound rather than a checklist. Which components are
// mandatory is decided by the packaging step's own presence assertions and by
// the publish job's per-artifact required list; what this decides is only which
// names may appear at all, which is why the Windows projection components sit
// here even though that leg ships them opportunistically. Adding a component to
// a release archive means adding it to the updater's platform component list
// and to this set together.
// Documentation members every archive carries, on every platform.
//
// The v0.5.40 archive was four executables and no words, and both strangers who
// installed it scored the packaging below the binaries for exactly that reason.
// A stranger's first two decisions, where the three executables go and what to
// do with the shared library, are both unguided, and no `kin` command can
// advise them before `kin` is on PATH. These three files are the answer that
// travels with the bytes.
//
// They are members of the archive and nothing installs them: `kin update` skips
// them by name (see RELEASE_ARCHIVE_DOC_FILES in the updater) and `scripts/
// install.sh` moves a fixed list of binaries, so neither changes behaviour.
const DOC_FILES = Object.freeze(["README.md", "INSTALL.md", "checksums-sha256.txt"]);

const ROOT_FILES_BY_FAMILY = {
  darwin: Object.freeze([
    "kin",
    "kin-daemon",
    "kin-vfs",
    "libkin_vfs_shim.dylib",
    ...DOC_FILES,
  ]),
  linux: Object.freeze(["kin", "kin-daemon", "kin-vfs", "libkin_vfs_shim.so", ...DOC_FILES]),
  windows: Object.freeze([
    "kin.exe",
    "kin-daemon.exe",
    "kin-vfs.exe",
    "kin_vfs_shim.dll",
    ...DOC_FILES,
  ]),
};

// Whether a target triple is one whose archive may carry the notification
// bundle. Only macOS has a bundle concept, so every other leg must stay flat.
function targetCarriesNotifierBundle(target) {
  if (typeof target !== "string" || target === "") {
    throw new Error("release archive shape requires a target triple");
  }
  return target.endsWith("-apple-darwin");
}

// The component file names an archive for `target` may carry at its root.
//
// An unrecognized triple is refused rather than defaulted onto a family. The
// release matrix is a closed list that the publish job pins by target, so a
// triple that reaches here without a family is a matrix change that did not
// update this file, and judging its archive by another platform's names would
// admit exactly the entries this set exists to refuse.
function releaseArchiveRootFiles(target) {
  if (targetCarriesNotifierBundle(target)) {
    return ROOT_FILES_BY_FAMILY.darwin;
  }
  if (target.includes("-windows-")) {
    return ROOT_FILES_BY_FAMILY.windows;
  }
  if (target.includes("-linux-")) {
    return ROOT_FILES_BY_FAMILY.linux;
  }
  throw new Error(`release archive shape has no component list for target ${target}`);
}

// Split an archive member path into its segments, rejecting the encodings that
// let a member escape the extraction root.
//
// This runs against the archive listing rather than the extracted tree, because
// by the time a traversing member has been materialized it has already been
// written outside the directory under inspection.
function memberSegments(member, label) {
  if (typeof member !== "string" || member === "") {
    throw new Error(`${label} contains an empty member path`);
  }
  if (member.includes("\\")) {
    throw new Error(`${label} member '${member}' uses a backslash separator`);
  }
  if (member.startsWith("/")) {
    throw new Error(`${label} member '${member}' is an absolute path`);
  }
  if (/^[A-Za-z]:/.test(member)) {
    throw new Error(`${label} member '${member}' carries a drive prefix`);
  }
  const isDirectory = member.endsWith("/");
  const segments = (isDirectory ? member.slice(0, -1) : member).split("/");
  for (const segment of segments) {
    if (segment === "") {
      throw new Error(`${label} member '${member}' has an empty path segment`);
    }
    if (segment === "." || segment === "..") {
      throw new Error(`${label} member '${member}' traverses its archive root`);
    }
  }
  return { segments, isDirectory };
}

// Assert that an archive listing declares only the sanctioned release shape.
//
// Unix archives wrap their contents in a single `<artifact>/` directory; the
// Windows zip is built from `<artifact>/*` and so is flat. Both are accepted,
// but not mixed: an archive that is partly prefixed is describing two roots.
function assertReleaseArchiveMemberPaths(memberPaths, options) {
  const { artifact, target } = options ?? {};
  if (typeof artifact !== "string" || artifact === "") {
    throw new Error("release archive shape requires an artifact name");
  }
  const bundleAllowed = targetCarriesNotifierBundle(target);
  const rootFiles = releaseArchiveRootFiles(target);
  const label = `${artifact} archive listing`;
  if (!Array.isArray(memberPaths) || memberPaths.length === 0) {
    throw new Error(`${label} is empty`);
  }
  if (memberPaths.length > MAX_ARCHIVE_MEMBERS) {
    throw new Error(
      `${label} declares ${memberPaths.length} members, above the limit of ${MAX_ARCHIVE_MEMBERS}`
    );
  }

  const parsed = memberPaths.map((member) => ({
    member,
    ...memberSegments(member, label),
  }));
  const prefixed = parsed.filter((entry) => entry.segments[0] === artifact);
  if (prefixed.length !== 0 && prefixed.length !== parsed.length) {
    throw new Error(`${label} mixes prefixed and unprefixed members`);
  }
  const hasPrefix = prefixed.length === parsed.length;

  let sawBundle = false;
  for (const { member, segments, isDirectory } of parsed) {
    const relative = hasPrefix ? segments.slice(1) : segments;
    if (relative.length === 0) {
      if (!isDirectory) {
        throw new Error(`${label} declares its root '${member}' as a file`);
      }
      continue;
    }
    if (relative[0] === NOTIFIER_BUNDLE_DIR) {
      if (!bundleAllowed) {
        throw new Error(
          `${label} carries ${NOTIFIER_BUNDLE_DIR} on non-macOS target ${target}`
        );
      }
      if (relative.length > MAX_BUNDLE_DEPTH) {
        throw new Error(`${label} member '${member}' is nested past the bundle depth limit`);
      }
      sawBundle = true;
      continue;
    }
    if (relative.length > 1) {
      throw new Error(`${label} member '${member}' nests content below the archive root`);
    }
    if (isDirectory) {
      throw new Error(`${label} declares unexpected directory '${member}'`);
    }
    if (!rootFiles.includes(relative[0])) {
      throw new Error(`${label} declares unexpected file '${member}'`);
    }
  }

  if (bundleAllowed && !sawBundle) {
    throw new Error(`${label} is missing ${NOTIFIER_BUNDLE_DIR}`);
  }
}

// Walk a materialized notification bundle and reject anything that is not a
// plain file or directory beneath it.
//
// The archive listing check cannot see what extraction actually produced, so
// this is the second half of the same guard: an entry that arrived as a
// symbolic link, a device node, or a second application bundle is refused here
// even if its declared path looked ordinary.
function assertNotifierBundle(bundleRoot, bundleName) {
  const seen = new Set();
  const stack = [{ dir: bundleRoot, relative: [], depth: 0 }];
  let count = 0;
  while (stack.length > 0) {
    const { dir, relative, depth } = stack.pop();
    if (depth > MAX_BUNDLE_DEPTH) {
      throw new Error(`${bundleName} nests past the depth limit of ${MAX_BUNDLE_DEPTH}`);
    }
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      count += 1;
      if (count > MAX_BUNDLE_ENTRIES) {
        throw new Error(`${bundleName} holds more than ${MAX_BUNDLE_ENTRIES} entries`);
      }
      const entryRelative = [...relative, entry.name];
      const printable = entryRelative.join("/");
      if (entry.isSymbolicLink()) {
        throw new Error(`${bundleName} entry '${printable}' is a symbolic link`);
      }
      if (entry.isDirectory()) {
        if (entry.name.endsWith(".app")) {
          throw new Error(`${bundleName} nests another application bundle at '${printable}'`);
        }
        stack.push({
          dir: path.join(dir, entry.name),
          relative: entryRelative,
          depth: depth + 1,
        });
        continue;
      }
      if (!entry.isFile()) {
        throw new Error(`${bundleName} entry '${printable}' is not a regular file`);
      }
      seen.add(printable);
    }
  }

  for (const member of [NOTIFIER_BUNDLE_EXECUTABLE, NOTIFIER_BUNDLE_PLIST]) {
    const printable = member.join("/");
    if (!seen.has(printable)) {
      throw new Error(`${bundleName} is missing '${printable}'`);
    }
  }
  const executable = path.join(bundleRoot, ...NOTIFIER_BUNDLE_EXECUTABLE);
  if ((fs.statSync(executable).mode & 0o111) === 0) {
    throw new Error(
      `${bundleName} entry '${NOTIFIER_BUNDLE_EXECUTABLE.join("/")}' is not executable`
    );
  }
}

// Classify the extracted root of a release archive into its component files and
// its sanctioned bundles, refusing every other shape.
//
// The returned file list is the release's content inventory: it is what the
// build job hashes into the per-artifact provenance manifest and what the
// publish job compares that manifest against, so both sides agree on which
// entries carry per-file provenance and which travel as a sealed bundle.
function classifyReleaseArchiveRoot(contentRoot, options) {
  const { target } = options ?? {};
  const bundleAllowed = targetCarriesNotifierBundle(target);
  const rootFiles = releaseArchiveRootFiles(target);
  const files = [];
  const bundles = [];
  for (const entry of fs.readdirSync(contentRoot, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) {
      throw new Error(`release archive root entry '${entry.name}' is a symbolic link`);
    }
    if (entry.isFile()) {
      if (!rootFiles.includes(entry.name)) {
        throw new Error(
          `release archive root for ${target} holds unexpected file '${entry.name}'`
        );
      }
      files.push(entry.name);
      continue;
    }
    if (!entry.isDirectory()) {
      throw new Error(`release archive root entry '${entry.name}' is not a regular file`);
    }
    if (entry.name !== NOTIFIER_BUNDLE_DIR) {
      throw new Error(`release archive root holds unexpected directory '${entry.name}'`);
    }
    if (!bundleAllowed) {
      throw new Error(
        `release archive root carries ${NOTIFIER_BUNDLE_DIR} on non-macOS target ${target}`
      );
    }
    assertNotifierBundle(path.join(contentRoot, entry.name), entry.name);
    bundles.push(entry.name);
  }

  if (bundleAllowed && bundles.length === 0) {
    throw new Error(`release archive root for ${target} is missing ${NOTIFIER_BUNDLE_DIR}`);
  }
  files.sort();
  bundles.sort();
  return { files, bundles };
}

module.exports = {
  DOC_FILES,
  MAX_ARCHIVE_MEMBERS,
  MAX_BUNDLE_DEPTH,
  MAX_BUNDLE_ENTRIES,
  NOTIFIER_BUNDLE_DIR,
  assertReleaseArchiveMemberPaths,
  classifyReleaseArchiveRoot,
  releaseArchiveRootFiles,
  targetCarriesNotifierBundle,
};
