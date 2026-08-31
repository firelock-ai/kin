// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GENERATOR = path.join(HERE, 'write-release-archive-docs.mjs');

// The three archive layouts release.yml builds. The docs differ across them
// (extensions, shim name, home directory), so every assertion below runs
// against all three rather than against whichever one is convenient.
const TARGETS = [
  'aarch64-apple-darwin',
  'x86_64-unknown-linux-gnu',
  'x86_64-pc-windows-msvc',
];

const PAYLOAD = {
  'aarch64-apple-darwin': ['kin', 'kin-daemon', 'kin-vfs', 'libkin_vfs_shim.dylib'],
  'x86_64-unknown-linux-gnu': ['kin', 'kin-daemon', 'kin-vfs', 'libkin_vfs_shim.so'],
  // release.yml sets skip_vfs on this row. Its two VFS copies are optional and
  // therefore produce no archive members when the build step is skipped.
  'x86_64-pc-windows-msvc': ['kin.exe', 'kin-daemon.exe'],
};

function generate(target, payload = PAYLOAD[target]) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-archive-docs-'));
  for (const name of payload) {
    fs.writeFileSync(path.join(dir, name), `stand-in bytes for ${name}\n`);
  }
  execFileSync(process.execPath, [GENERATOR, dir, target, '9.9.9'], { stdio: 'pipe' });
  return {
    dir,
    readme: fs.readFileSync(path.join(dir, 'README.md'), 'utf8'),
    install: fs.readFileSync(path.join(dir, 'INSTALL.md'), 'utf8'),
    checksums: fs.readFileSync(path.join(dir, 'checksums-sha256.txt'), 'utf8'),
  };
}

test('archive docs name only the runtime files that were actually packaged', () => {
  for (const target of TARGETS) {
    const { readme } = generate(target);
    const listed = [...readme.matchAll(/^- `([^`]+)` /gmu)].map((match) => match[1]);
    assert.deepEqual(
      listed,
      PAYLOAD[target],
      `${target}: README runtime list and packaged archive members differ`,
    );
  }

  const windows = generate('x86_64-pc-windows-msvc');
  for (const docs of [windows.readme, windows.install]) {
    assert.match(docs, /kin\.exe/, 'Windows docs omit the packaged CLI');
    assert.match(docs, /kin-daemon\.exe/, 'Windows docs omit the packaged daemon');
    assert.doesNotMatch(
      docs,
      /kin-vfs\.exe/,
      'Windows docs tell the reader to install a VFS executable the archive does not carry',
    );
    assert.doesNotMatch(
      docs,
      /kin_vfs_shim\.dll/,
      'Windows docs tell the reader to install a VFS shim the archive does not carry',
    );
  }
  assert.match(
    `${windows.readme}\n${windows.install}`,
    /Transparent filesystem projection is not shipped on native Windows/,
    'Windows docs hide the native projection boundary',
  );
  assert.match(
    `${windows.readme}\n${windows.install}`,
    /WSL2.+full Kin experience/s,
    'Windows docs do not name the supported full-product path',
  );
  assert.ok(
    windows.install.includes('mkdir "%USERPROFILE%\\.kin\\bin"'),
    'Windows INSTALL does not quote the managed bin directory',
  );
  for (const executable of PAYLOAD['x86_64-pc-windows-msvc']) {
    assert.ok(
      windows.install.includes(
        `copy ${executable} "%USERPROFILE%\\.kin\\bin\\${executable}"`,
      ),
      `Windows INSTALL does not copy packaged executable ${executable} to a quoted path`,
    );
  }
  assert.doesNotMatch(
    windows.install,
    /copy kin\.exe kin-daemon\.exe/,
    'Windows INSTALL uses cmd.exe copy as if it accepted multiple independent sources',
  );
  assert.doesNotMatch(
    windows.install,
    /^\s+mkdir %USERPROFILE%/mu,
    'Windows INSTALL leaves the managed directory unquoted',
  );
  assert.doesNotMatch(
    windows.install,
    /^\s+copy [^\r\n]+ %USERPROFILE%/mu,
    'Windows INSTALL leaves a copy destination unquoted',
  );

  for (const target of TARGETS.filter((candidate) => !candidate.includes('-windows-'))) {
    const { readme, install } = generate(target);
    for (const name of PAYLOAD[target]) {
      assert.match(
        readme,
        new RegExp(name.replaceAll('.', '\\.'), 'u'),
        `${target}: README omits ${name}`,
      );
      assert.match(
        install,
        new RegExp(name.replaceAll('.', '\\.'), 'u'),
        `${target}: INSTALL omits ${name}`,
      );
    }
    assert.doesNotMatch(
      `${readme}\n${install}`,
      /not shipped on native Windows/,
      `${target}: Unix docs inherited the Windows support boundary`,
    );
    assert.ok(
      install.includes(`cp ${PAYLOAD[target].slice(0, 3).join(' ')} ~/.kin/bin/`),
      `${target}: INSTALL no longer copies every packaged executable`,
    );
    assert.ok(
      install.includes(`cp ${PAYLOAD[target][3]} ~/.kin/lib/`),
      `${target}: INSTALL no longer copies the packaged VFS shim`,
    );
  }
});

test('archive docs refuse a half-packaged VFS pair', () => {
  const target = 'x86_64-pc-windows-msvc';
  for (const loneProjectionMember of ['kin-vfs.exe', 'kin_vfs_shim.dll']) {
    assert.throws(
      () => generate(target, [...PAYLOAD[target], loneProjectionMember]),
      (error) => {
        assert.match(error.stderr.toString(), /VFS executable and shim must be packaged together/);
        return true;
      },
      `generator accepted an unusable archive carrying only ${loneProjectionMember}`,
    );
  }
});

test('archive docs follow a complete Windows VFS pair if the artifact starts shipping it', () => {
  const payload = [
    ...PAYLOAD['x86_64-pc-windows-msvc'],
    'kin-vfs.exe',
    'kin_vfs_shim.dll',
  ];
  const { readme, install } = generate('x86_64-pc-windows-msvc', payload);
  const listed = [...readme.matchAll(/^- `([^`]+)` /gmu)].map((match) => match[1]);
  assert.deepEqual(listed, payload, 'Windows README does not follow the packaged VFS pair');
  for (const executable of payload.slice(0, 3)) {
    assert.ok(
      install.includes(`copy ${executable} "%USERPROFILE%\\.kin\\bin\\${executable}"`),
      `Windows INSTALL does not copy packaged executable ${executable} to a quoted path`,
    );
  }
  assert.ok(
    install.includes('mkdir "%USERPROFILE%\\.kin\\lib"'),
    'Windows INSTALL does not quote the managed lib directory',
  );
  assert.ok(
    install.includes(
      'copy kin_vfs_shim.dll "%USERPROFILE%\\.kin\\lib\\kin_vfs_shim.dll"',
    ),
    'Windows INSTALL does not copy the packaged VFS shim to a quoted path',
  );
  assert.doesNotMatch(
    install,
    /^\s+mkdir %USERPROFILE%/mu,
    'Windows full-pair INSTALL leaves a managed directory unquoted',
  );
  assert.doesNotMatch(
    install,
    /^\s+copy [^\r\n]+ %USERPROFILE%/mu,
    'Windows full-pair INSTALL leaves a copy destination unquoted',
  );
  assert.doesNotMatch(
    `${readme}\n${install}`,
    /not shipped on native Windows/,
    'Windows docs claim projection is absent even though the artifact carries the full pair',
  );
});

test('archive docs refuse a Unix artifact missing both mandatory VFS members', () => {
  assert.throws(
    () => generate('x86_64-unknown-linux-gnu', ['kin', 'kin-daemon']),
    (error) => {
      assert.match(error.stderr.toString(), /missing its mandatory VFS executable and shim/);
      return true;
    },
    'generator silently documented a Unix archive without its mandatory VFS pair',
  );
});

// An isolated stranger run lost a task to this number. Its container had 12 GiB,
// `kin doctor` had the measurement the whole time, and the only place the cost
// was written down was a health check the reader had to think to run. A commit
// peak that big is a requirement, and a requirement belongs where someone reads
// before they choose the machine.
test('every archive states the memory a commit needs before a reader picks a machine', () => {
  for (const target of TARGETS) {
    const { install } = generate(target);
    assert.match(
      install,
      /16 GB per repository per write/,
      `${target}: INSTALL.md does not state the per-write memory requirement, so the only ` +
        'place it is written down is a health check the reader has to think to run',
    );
    assert.match(
      install,
      /## Requirements/,
      `${target}: the memory figure is not in a requirements section`,
    );
    assert.match(
      install,
      /kin doctor/,
      `${target}: the requirement names no way to check it against this machine`,
    );
  }
});

// FIR-2643: the same wrong model had three homes, and this was the one shipped
// inside the archive. The requirement itself is grounded, a margin over a total
// that has actually been observed, but the sentence that justified it explained
// the cost as following repository size, which is the claim the one measurement
// separating the terms contradicts: a docstring-only edit on a 500 MiB store
// cost about 0.9 GB while the store-size reading implied a 10.6 GiB floor. A
// requirement a reader disbelieves is a requirement they stop reading.
test('the memory requirement does not explain itself with a model the measurement contradicts', () => {
  for (const target of TARGETS) {
    const { install } = generate(target);
    assert.doesNotMatch(
      install,
      /peak follows\s+the size of the repository/,
      `${target}: INSTALL.md still derives the commit cost from repository size`,
    );
    assert.doesNotMatch(
      install,
      /rather than the size of the edit/,
      `${target}: INSTALL.md still contrasts store size against edit size as the model`,
    );
    // Positive controls: deleting the paragraph passes both assertions above.
    assert.match(
      install,
      /not modelled/,
      `${target}: INSTALL.md drops the requirement instead of stating its uncertainty`,
    );
    assert.match(
      install,
      /observed/,
      `${target}: INSTALL.md states a figure with nothing observed behind it`,
    );
  }
});

// Requirements that arrive after the install steps are requirements nobody
// used. The reader has already chosen the machine by then.
test('the requirement is stated before the install steps', () => {
  for (const target of TARGETS) {
    const { install } = generate(target);
    const requirements = install.indexOf('## Requirements');
    const executables = install.indexOf('## 1. The executables');
    assert.ok(requirements > 0, `${target}: no requirements section`);
    assert.ok(
      requirements < executables,
      `${target}: the requirements section sits after the install steps`,
    );
  }
});

// A stranger who has extracted the archive can still check what is inside it,
// which is the whole reason this manifest exists beside the per-archive sidecar.
test('the checksum manifest covers every file beside it and no others', () => {
  for (const target of TARGETS) {
    const { dir, checksums } = generate(target);
    const listed = new Map(
      checksums
        .trimEnd()
        .split('\n')
        .map((line) => {
          const [digest, name] = line.split('  ');
          return [name, digest];
        }),
    );
    const present = fs
      .readdirSync(dir)
      .filter((name) => name !== 'checksums-sha256.txt')
      .sort();
    assert.deepEqual(
      [...listed.keys()].sort(),
      present,
      `${target}: the manifest and the archive root disagree about what is in the archive`,
    );
    for (const [name, digest] of listed) {
      const actual = createHash('sha256')
        .update(fs.readFileSync(path.join(dir, name)))
        .digest('hex');
      assert.equal(digest, actual, `${target}: ${name} is listed with the wrong digest`);
    }
  }
});

// House rule, on the one prose surface that ships inside the product and is
// generated rather than reviewed line by line.
test('the shipped archive prose carries no em dash', () => {
  for (const target of TARGETS) {
    const { readme, install } = generate(target);
    assert.ok(!readme.includes('—'), `${target}: README.md carries an em dash`);
    assert.ok(!install.includes('—'), `${target}: INSTALL.md carries an em dash`);
  }
});
