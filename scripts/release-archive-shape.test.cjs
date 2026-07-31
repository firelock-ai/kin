// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  MAX_BUNDLE_ENTRIES,
  NOTIFIER_BUNDLE_DIR,
  assertReleaseArchiveMemberPaths,
  classifyReleaseArchiveRoot,
  targetCarriesNotifierBundle,
} = require("./release-archive-shape.cjs");

const MACOS_TARGET = "x86_64-apple-darwin";
const LINUX_TARGET = "x86_64-unknown-linux-musl";
const WINDOWS_TARGET = "x86_64-pc-windows-msvc";
const MACOS_ARTIFACT = "kin-macos-x86_64";
const LINUX_ARTIFACT = "kin-linux-x86_64";
const WINDOWS_ARTIFACT = "kin-windows-x86_64";

// Verbatim `tar -tzf kin-macos-x86_64.tar.gz` output from the release build that
// this guard rejected, including its interleaved directory records and the
// bundle's signature payload. Fixtures are derived from it rather than from an
// idealized listing so the accepted shape is the shape a release actually has.
const MACOS_LISTING = [
  "kin-macos-x86_64/",
  "kin-macos-x86_64/kin",
  "kin-macos-x86_64/kin-vfs",
  "kin-macos-x86_64/libkin_vfs_shim.dylib",
  "kin-macos-x86_64/KinNotifier.app/",
  "kin-macos-x86_64/kin-daemon",
  "kin-macos-x86_64/KinNotifier.app/Contents/",
  "kin-macos-x86_64/KinNotifier.app/Contents/CodeResources",
  "kin-macos-x86_64/KinNotifier.app/Contents/_CodeSignature/",
  "kin-macos-x86_64/KinNotifier.app/Contents/MacOS/",
  "kin-macos-x86_64/KinNotifier.app/Contents/Resources/",
  "kin-macos-x86_64/KinNotifier.app/Contents/Info.plist",
  "kin-macos-x86_64/KinNotifier.app/Contents/Resources/Kin.icns",
  "kin-macos-x86_64/KinNotifier.app/Contents/MacOS/KinNotifier",
  "kin-macos-x86_64/KinNotifier.app/Contents/_CodeSignature/CodeResources",
];

// The same archive one release earlier, before the notification bundle shipped.
const LINUX_LISTING = [
  "kin-linux-x86_64/",
  "kin-linux-x86_64/kin",
  "kin-linux-x86_64/kin-vfs",
  "kin-linux-x86_64/libkin_vfs_shim.so",
  "kin-linux-x86_64/kin-daemon",
];

// The Windows zip is compressed from `<artifact>/*`, so its members carry no
// artifact prefix at all.
const WINDOWS_LISTING = ["kin.exe", "kin-daemon.exe", "kin-vfs.exe"];

const MACOS_FILES = ["kin", "kin-daemon", "kin-vfs", "libkin_vfs_shim.dylib"];

function tempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "release-archive-shape-"));
}

function writeFile(root, relative, mode = 0o644) {
  const file = path.join(root, ...relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, relative.join("/"));
  fs.chmodSync(file, mode);
  return file;
}

// Materialize the extracted content root of a real macOS release archive.
function macosRoot(options = {}) {
  const { bundle = true, executableMode = 0o755 } = options;
  const root = tempRoot();
  for (const name of MACOS_FILES) {
    writeFile(root, [name], 0o755);
  }
  if (bundle) {
    writeFile(root, [NOTIFIER_BUNDLE_DIR, "Contents", "Info.plist"]);
    writeFile(root, [NOTIFIER_BUNDLE_DIR, "Contents", "CodeResources"]);
    writeFile(root, [NOTIFIER_BUNDLE_DIR, "Contents", "Resources", "Kin.icns"]);
    writeFile(root, [NOTIFIER_BUNDLE_DIR, "Contents", "_CodeSignature", "CodeResources"]);
    writeFile(root, [NOTIFIER_BUNDLE_DIR, "Contents", "MacOS", "KinNotifier"], executableMode);
  }
  return root;
}

function linuxRoot() {
  const root = tempRoot();
  for (const name of ["kin", "kin-daemon", "kin-vfs", "libkin_vfs_shim.so"]) {
    writeFile(root, [name], 0o755);
  }
  return root;
}

test("a macOS target carries the bundle and no other target does", () => {
  assert.equal(targetCarriesNotifierBundle(MACOS_TARGET), true);
  assert.equal(targetCarriesNotifierBundle("aarch64-apple-darwin"), true);
  assert.equal(targetCarriesNotifierBundle(LINUX_TARGET), false);
  assert.equal(targetCarriesNotifierBundle(WINDOWS_TARGET), false);
  assert.throws(() => targetCarriesNotifierBundle(""), /requires a target triple/);
});

test("the released macOS archive listing is accepted whole", () => {
  assertReleaseArchiveMemberPaths(MACOS_LISTING, {
    artifact: MACOS_ARTIFACT,
    target: MACOS_TARGET,
  });
});

test("prefixed Unix and unprefixed Windows listings are both accepted", () => {
  assertReleaseArchiveMemberPaths(LINUX_LISTING, {
    artifact: LINUX_ARTIFACT,
    target: LINUX_TARGET,
  });
  assertReleaseArchiveMemberPaths(WINDOWS_LISTING, {
    artifact: WINDOWS_ARTIFACT,
    target: WINDOWS_TARGET,
  });
});

test("a listing that escapes or renames its archive root is rejected", () => {
  const cases = [
    [["/etc/passwd"], /is an absolute path/],
    [["C:/Windows/system32/kin.exe"], /carries a drive prefix/],
    [[`${LINUX_ARTIFACT}/../kin`], /traverses its archive root/],
    [[`${LINUX_ARTIFACT}/./kin`], /traverses its archive root/],
    [[`${LINUX_ARTIFACT}\\kin`], /uses a backslash separator/],
    [[`${LINUX_ARTIFACT}//kin`], /has an empty path segment/],
    [[""], /contains an empty member path/],
    [[], /is empty/],
    [[`${LINUX_ARTIFACT}`], /declares its root .* as a file/],
    [[...LINUX_LISTING, "kin-daemon"], /mixes prefixed and unprefixed members/],
  ];
  for (const [listing, expected] of cases) {
    assert.throws(
      () =>
        assertReleaseArchiveMemberPaths(listing, {
          artifact: LINUX_ARTIFACT,
          target: LINUX_TARGET,
        }),
      expected,
      `listing ${JSON.stringify(listing)} should have been refused`
    );
  }
});

test("a listing nesting anything but the sanctioned bundle is rejected", () => {
  assert.throws(
    () =>
      assertReleaseArchiveMemberPaths([...LINUX_LISTING, `${LINUX_ARTIFACT}/payload/kin`], {
        artifact: LINUX_ARTIFACT,
        target: LINUX_TARGET,
      }),
    /nests content below the archive root/
  );
  assert.throws(
    () =>
      assertReleaseArchiveMemberPaths([...LINUX_LISTING, `${LINUX_ARTIFACT}/payload/`], {
        artifact: LINUX_ARTIFACT,
        target: LINUX_TARGET,
      }),
    /declares unexpected directory/
  );
  assert.throws(
    () =>
      assertReleaseArchiveMemberPaths(
        [...MACOS_LISTING, `${MACOS_ARTIFACT}/KinNotifier.appx/payload`],
        { artifact: MACOS_ARTIFACT, target: MACOS_TARGET }
      ),
    /nests content below the archive root/
  );
});

test("the bundle is required on macOS listings and refused on every other target", () => {
  assert.throws(
    () =>
      assertReleaseArchiveMemberPaths(
        MACOS_LISTING.filter((member) => !member.includes(NOTIFIER_BUNDLE_DIR)),
        { artifact: MACOS_ARTIFACT, target: MACOS_TARGET }
      ),
    /is missing KinNotifier\.app/
  );
  assert.throws(
    () =>
      assertReleaseArchiveMemberPaths(
        [...LINUX_LISTING, `${LINUX_ARTIFACT}/KinNotifier.app/Contents/Info.plist`],
        { artifact: LINUX_ARTIFACT, target: LINUX_TARGET }
      ),
    /carries KinNotifier\.app on non-macOS target/
  );
});

test("the extracted macOS root yields exactly the four provenance-bearing files", () => {
  const root = macosRoot();
  const { files, bundles } = classifyReleaseArchiveRoot(root, { target: MACOS_TARGET });
  assert.deepEqual(files, MACOS_FILES);
  assert.deepEqual(bundles, [NOTIFIER_BUNDLE_DIR]);
});

test("the extracted Linux root yields its files and no bundle", () => {
  const { files, bundles } = classifyReleaseArchiveRoot(linuxRoot(), { target: LINUX_TARGET });
  assert.deepEqual(files, ["kin", "kin-daemon", "kin-vfs", "libkin_vfs_shim.so"]);
  assert.deepEqual(bundles, []);
});

test("an extracted root holding an unsanctioned directory is rejected", () => {
  const root = macosRoot();
  fs.mkdirSync(path.join(root, "payload"));
  assert.throws(
    () => classifyReleaseArchiveRoot(root, { target: MACOS_TARGET }),
    /holds unexpected directory 'payload'/
  );
});

test("an extracted root is rejected for a missing or misplaced bundle", () => {
  assert.throws(
    () => classifyReleaseArchiveRoot(macosRoot({ bundle: false }), { target: MACOS_TARGET }),
    /is missing KinNotifier\.app/
  );
  const linux = linuxRoot();
  fs.mkdirSync(path.join(linux, NOTIFIER_BUNDLE_DIR, "Contents", "MacOS"), { recursive: true });
  assert.throws(
    () => classifyReleaseArchiveRoot(linux, { target: LINUX_TARGET }),
    /carries KinNotifier\.app on non-macOS target/
  );
});

test("symbolic links are refused at the archive root and inside the bundle", () => {
  const root = macosRoot();
  fs.symlinkSync(path.join(root, "kin"), path.join(root, "kin-link"));
  assert.throws(
    () => classifyReleaseArchiveRoot(root, { target: MACOS_TARGET }),
    /root entry 'kin-link' is a symbolic link/
  );

  const disguised = macosRoot({ bundle: false });
  const real = macosRoot();
  fs.symlinkSync(path.join(real, NOTIFIER_BUNDLE_DIR), path.join(disguised, NOTIFIER_BUNDLE_DIR));
  assert.throws(
    () => classifyReleaseArchiveRoot(disguised, { target: MACOS_TARGET }),
    /root entry 'KinNotifier\.app' is a symbolic link/
  );

  const nested = macosRoot();
  fs.symlinkSync(
    path.join(nested, "kin"),
    path.join(nested, NOTIFIER_BUNDLE_DIR, "Contents", "MacOS", "shortcut")
  );
  assert.throws(
    () => classifyReleaseArchiveRoot(nested, { target: MACOS_TARGET }),
    /entry 'Contents\/MacOS\/shortcut' is a symbolic link/
  );
});

test("a bundle missing a required member or its executable bit is rejected", () => {
  const noExecutable = macosRoot();
  fs.rmSync(path.join(noExecutable, NOTIFIER_BUNDLE_DIR, "Contents", "MacOS", "KinNotifier"));
  assert.throws(
    () => classifyReleaseArchiveRoot(noExecutable, { target: MACOS_TARGET }),
    /is missing 'Contents\/MacOS\/KinNotifier'/
  );

  const noPlist = macosRoot();
  fs.rmSync(path.join(noPlist, NOTIFIER_BUNDLE_DIR, "Contents", "Info.plist"));
  assert.throws(
    () => classifyReleaseArchiveRoot(noPlist, { target: MACOS_TARGET }),
    /is missing 'Contents\/Info\.plist'/
  );

  assert.throws(
    () => classifyReleaseArchiveRoot(macosRoot({ executableMode: 0o644 }), { target: MACOS_TARGET }),
    /entry 'Contents\/MacOS\/KinNotifier' is not executable/
  );
});

test("a bundle hiding another bundle or exceeding its entry budget is rejected", () => {
  const nestedApp = macosRoot();
  fs.mkdirSync(path.join(nestedApp, NOTIFIER_BUNDLE_DIR, "Contents", "Payload.app"), {
    recursive: true,
  });
  assert.throws(
    () => classifyReleaseArchiveRoot(nestedApp, { target: MACOS_TARGET }),
    /nests another application bundle at 'Contents\/Payload\.app'/
  );

  const overfull = macosRoot();
  for (let index = 0; index <= MAX_BUNDLE_ENTRIES; index += 1) {
    writeFile(overfull, [NOTIFIER_BUNDLE_DIR, "Contents", "Resources", `filler-${index}`]);
  }
  assert.throws(
    () => classifyReleaseArchiveRoot(overfull, { target: MACOS_TARGET }),
    new RegExp(`holds more than ${MAX_BUNDLE_ENTRIES} entries`)
  );
});
