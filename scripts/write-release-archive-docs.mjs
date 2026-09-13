// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Write the documentation members a release archive carries.
//
// The v0.5.40 archive was four executables and no words. Both arms of the
// isolated stranger run installed it successfully and both scored the packaging
// below the binaries, for the same reason: a stranger's first two decisions,
// where the executables go are unguided, and no `kin` command can advise them
// before `kin` is on PATH. One arm extracted to `~/.local/lib` and symlinked
// into `/usr/local/bin`, and the other to `/opt/kin`.
//
// Both arms were also told to verify against `checksums-sha256.txt` and found
// only the per-archive sidecar. That sidecar covers the tarball; this file
// covers what is inside it, which is the thing a reader who has already
// extracted can still check.
//
// The names considered here are the ones `scripts/release-archive-shape.cjs`
// admits at the archive root and the ones `kin update` skips by name. The
// artifact bytes decide the runtime inventory, so this generator cannot claim
// that a retired component was packaged.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [, , artifactDir, target, version] = process.argv;
if (!artifactDir || !target || !version) {
  console.error(
    "usage: write-release-archive-docs.mjs <artifact-dir> <target-triple> <version>",
  );
  process.exit(2);
}

const windows = target.includes("-windows-");
const macos = target.endsWith("-apple-darwin");
const exe = windows ? ".exe" : "";
const cli = `kin${exe}`;
const daemon = `kin-daemon${exe}`;
const vfs = `kin-vfs${exe}`;
const shim = windows
  ? "kin_vfs_shim.dll"
  : macos
    ? "libkin_vfs_shim.dylib"
    : "libkin_vfs_shim.so";

const binDir = windows ? "%USERPROFILE%\\.kin\\bin" : "~/.kin/bin";

function hasRegularFile(name) {
  try {
    return fs.statSync(path.join(artifactDir, name)).isFile();
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

for (const required of [cli, daemon]) {
  if (!hasRegularFile(required)) {
    console.error(`release archive is missing mandatory executable ${required}`);
    process.exit(1);
  }
}

const retiredProjectionFiles = [vfs, shim].filter(hasRegularFile);
if (retiredProjectionFiles.length !== 0) {
  console.error(
    `release archive carries retired VFS runtime artifact(s): ${retiredProjectionFiles.join(", ")}`,
  );
  process.exit(1);
}

const executableNames = [cli, daemon];
const inlineNames = executableNames
  .map((name) => `\`${name}\``)
  .map((name, index, names) => {
    if (index === 0) {
      return name;
    }
    return index === names.length - 1 ? ` and ${name}` : `, ${name}`;
  })
  .join("");
const copyNames = executableNames.join(" ");
const makeBinDirCommand = windows ? `mkdir "${binDir}"` : `mkdir -p ${binDir}`;
const copyExecutablesCommand = windows
  ? executableNames.map((name) => `copy ${name} "${binDir}\\${name}"`).join("\n    ")
  : `cp ${copyNames} ${binDir}/`;

const runtimeFiles = [
  `- \`${cli}\` is the command line interface. Start here.`,
  `- \`${daemon}\` serves one repository's graph.\n  \`${cli}\` starts it for you; you do not run it by hand.`,
];

const readme = `# Kin ${version} (${target})

Kin is a graph-native code repository for people and AI agents. It answers questions
about a repository from a graph rather than from raw file search.

This archive carries these runtime files:

${runtimeFiles.join("\n")}

Deprecated VFS executables and preload shims are not included in release archives.

## After installing

Run \`kin doctor\` first. It checks every part of the install, names what is
missing, and offers \`kin doctor --fix\` for the parts it can repair itself. It is
the fastest way to find out whether this machine is set up correctly, and it
tells you more than any document here can.

Then, in a repository:

    kin init
    kin status

\`kin --help\` starts with first-use guidance and groups the complete command index by task.

## Verifying these bytes

\`checksums-sha256.txt\` in this archive lists the SHA-256 of every file beside
it. The \`.sha256\` file published next to the archive covers the archive itself.
`;

const install = `# Installing Kin ${version} (${target})

Start with one number to plan around, then place each packaged runtime as
described below.

## Requirements

Give the machine or container 16 GB per repository per write. A commit on a
converted repository has been observed driving a whole 12 GiB machine to 12.0 GiB
in total and being killed there, and how much of that total the commit itself
needed is not modelled, so the figure is a margin over what has been observed
rather than a prediction from the size of your repository or your edit.

Run \`kin doctor\` inside the repository to see where you stand. It compares this
machine's memory ceiling against the totals Kin has recorded and tells you which
side of that line you are on, before you spend a write finding out.

## 1. The executables

Put ${inlineNames} in one directory that is on your PATH.
Kin looks for its siblings beside the running binary, so keeping these files
together lets \`kin\` find every packaged runtime without configuration.

The managed installer uses \`${binDir}\`. Any directory works as long as
these files land together:

    ${makeBinDirCommand}
    ${copyExecutablesCommand}

Then add that directory to PATH.

## Then

    kin doctor

It reports what is installed, what is not, and what it can repair. Run it before
anything else.
`;

fs.writeFileSync(path.join(artifactDir, "README.md"), readme);
fs.writeFileSync(path.join(artifactDir, "INSTALL.md"), install);

// Hash every regular file in the archive root except the manifest itself, which
// cannot contain its own digest. Sorted, so the manifest is a property of the
// contents rather than of directory-read order.
const CHECKSUM_FILE = "checksums-sha256.txt";
const lines = [];
for (const name of fs.readdirSync(artifactDir).sort()) {
  if (name === CHECKSUM_FILE) {
    continue;
  }
  const full = path.join(artifactDir, name);
  if (!fs.statSync(full).isFile()) {
    continue;
  }
  lines.push(`${createHash("sha256").update(fs.readFileSync(full)).digest("hex")}  ${name}`);
}
if (lines.length === 0) {
  console.error("release archive has no files to checksum");
  process.exit(1);
}
fs.writeFileSync(path.join(artifactDir, CHECKSUM_FILE), `${lines.join("\n")}\n`);
console.log(`wrote README.md, INSTALL.md and ${CHECKSUM_FILE} (${lines.length} entries)`);
