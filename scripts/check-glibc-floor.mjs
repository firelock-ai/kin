#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Refuse a Linux release archive whose dynamic binaries demand a newer glibc
// than the oldest distribution Kin claims to run on.
//
// The v0.5.38 linux-aarch64 archive shipped a kin-vfs that the Debian 12
// loader refused outright:
//
//   kin-vfs: /lib/aarch64-linux-gnu/libc.so.6: version `GLIBC_2.39' not found
//
// Nothing in the build was wrong about kin-vfs. Rust std references
// pidfd_spawnp and pidfd_getpid as weak undefined symbols, and the linker
// binds a weak undefined symbol to whatever the BUILD HOST's libc exports. On
// a runner image carrying glibc 2.39 those two references acquire a
// GLIBC_2.39 version requirement; on an older host they stay unresolved and
// cost nothing. So the floor of every shipped binary was a property of the
// runner image rather than of anything under review, and a routine image bump
// moved it past a distribution Kin's own install docs name.
//
// The build now pins that floor explicitly (release.yml builds the Linux
// kin-vfs and shim through zig's bundled glibc headers at FLOOR), and this
// guard is the half that cannot be skipped: it reads the produced bytes and
// refuses anything above the floor, naming the symbols that pushed it there.
// Pinning alone would go quiet the day the pin stops working; a check on the
// artifact fails loudly instead.

import childProcess from 'node:child_process';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

// The oldest glibc a published Linux binary must load against. Debian 11 is
// 2.31, Debian 12 is 2.36, Ubuntu 22.04 is 2.35, Ubuntu 24.04 is 2.39. The
// floor sits BELOW Debian 12 on purpose: a floor set at the distribution we
// care about most leaves no margin, so the next symbol pulled in from a newer
// libc lands directly on a supported user. At 2.31 both current Debian
// stables load the archive, and the release build has room to acquire a
// symbol without shipping a binary nobody can start.
//
// This value is the one source of truth for the floor. release.yml reads it
// from here (`--print-floor`) to build against it rather than recording it a
// second time, because a guard checking a different floor than the build
// targets is worse than no guard.
export const GLIBC_FLOOR = '2.31';

// readelf prints `symbol@GLIBC_2.39` or `symbol@@GLIBC_2.39`.
const READELF_REQUIREMENT = /([A-Za-z_][A-Za-z0-9_.]*)@@?GLIBC_(\d+(?:\.\d+)*)/g;
// objdump -T puts the version before the name, parenthesized when the symbol
// is undefined: `(GLIBC_2.39) pidfd_spawnp`.
const OBJDUMP_REQUIREMENT = /\bGLIBC_(\d+(?:\.\d+)*)\)?\s+([A-Za-z_][A-Za-z0-9_.]*)\s*$/gm;

export function compareVersions(left, right) {
  const leftParts = left.split('.').map(Number);
  const rightParts = right.split('.').map(Number);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const a = leftParts[index] ?? 0;
    const b = rightParts[index] ?? 0;
    if (a !== b) {
      return a < b ? -1 : 1;
    }
  }
  return 0;
}

// Parses either tool's dynamic symbol listing. readelf is tried first and
// objdump only when readelf's shape matched nothing, because objdump's
// "version then name" pattern would otherwise read readelf's trailing
// `(12)` version index as a symbol name.
export function parseGlibcRequirements(text) {
  const requirements = [];
  for (const match of text.matchAll(READELF_REQUIREMENT)) {
    requirements.push({ symbol: match[1], version: match[2] });
  }
  if (requirements.length > 0) {
    return requirements;
  }
  for (const match of text.matchAll(OBJDUMP_REQUIREMENT)) {
    requirements.push({ symbol: match[2], version: match[1] });
  }
  return requirements;
}

// Fails closed on an empty parse. Every binary this guard is pointed at links
// glibc dynamically, so "no requirements found" means the listing was
// unreadable, not that the binary is clean, and reading one as the other is
// exactly how a guard stops being able to fail.
export function summarizeGlibcRequirements(text, { label } = {}) {
  const requirements = parseGlibcRequirements(text);
  if (requirements.length === 0) {
    throw new Error(
      `${label ?? 'binary'} reported no GLIBC version requirements at all; ` +
      'a dynamically linked release binary always has some, so this listing ' +
      'is unreadable rather than clean',
    );
  }
  const max = requirements
    .map((requirement) => requirement.version)
    .reduce((highest, version) => (compareVersions(version, highest) > 0 ? version : highest));
  const symbols = [
    ...new Set(
      requirements
        .filter((requirement) => requirement.version === max)
        .map((requirement) => requirement.symbol),
    ),
  ].sort();
  return { max, symbols, count: requirements.length };
}

const runTool = (command, args, file) => {
  const result = childProcess.spawnSync(command, [...args, file], { encoding: 'utf8' });
  if (result.error || result.status !== 0) {
    return null;
  }
  return result.stdout;
};

export function readDynamicSymbols(file, { run = runTool } = {}) {
  const listing =
    run('readelf', ['--dyn-syms', '-W'], file) ?? run('objdump', ['-T'], file);
  if (listing === null) {
    throw new Error(
      `could not read the dynamic symbols of ${file} with readelf or objdump; ` +
      'refusing to publish a binary whose glibc floor was never read',
    );
  }
  return listing;
}

export function checkFiles(files, { floor = GLIBC_FLOOR, run = runTool, log = console.log } = {}) {
  if (files.length === 0) {
    throw new Error(
      'no binaries were named; a floor check that runs on nothing reports the ' +
      'same success as a floor check that passed',
    );
  }
  const violations = [];
  for (const file of files) {
    const summary = summarizeGlibcRequirements(readDynamicSymbols(file, { run }), {
      label: file,
    });
    log(
      `${file}: highest requirement GLIBC_${summary.max} ` +
      `(${summary.symbols.join(', ')}) across ${summary.count} versioned references`,
    );
    if (compareVersions(summary.max, floor) > 0) {
      violations.push({ file, ...summary });
    }
  }
  if (violations.length > 0) {
    const detail = violations
      .map(
        (violation) =>
          `${violation.file} requires GLIBC_${violation.max} ` +
          `(${violation.symbols.join(', ')})`,
      )
      .join('; ');
    throw new Error(
      `${detail}; the published floor is GLIBC_${floor}, so this archive cannot ` +
      'start on a distribution below that glibc. Build the Linux kin-vfs ' +
      'binaries against the pinned floor instead of against the runner image.',
    );
  }
  return floor;
}

export function main({ argv = process.argv.slice(2), log = console.log } = {}) {
  if (argv.includes('--print-floor')) {
    log(GLIBC_FLOOR);
    return GLIBC_FLOOR;
  }
  return checkFiles(argv, { log });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(`::error::${error.message}`);
    process.exit(1);
  }
}
