// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  GLIBC_FLOOR,
  checkFiles,
  compareVersions,
  parseGlibcRequirements,
  readDynamicSymbols,
  summarizeGlibcRequirements,
} from './check-glibc-floor.mjs';

// Real `readelf --dyn-syms -W` bytes from the v0.5.38 linux-aarch64 archive.
// The last two lines are the defect: Rust std's pidfd spawn path, versioned by
// the runner image's glibc, which the Debian 12 loader refuses.
const READELF_2_39 = `
Symbol table '.dynsym' contains 199 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
    26: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND dlsym@GLIBC_2.34 (6)
    40: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND pthread_detach@GLIBC_2.34 (6)
    93: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND pidfd_spawnp@GLIBC_2.39 (12)
   182: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND pidfd_getpid@GLIBC_2.39 (12)
`;

// Real bytes from the same archive's libkin_vfs_shim.so. It loads on Debian 12
// and was never the reported defect, but 2.34 is still above the floor: it is
// where the runner image happened to leave it, and only a build pinned to the
// floor keeps it there on the next image.
const READELF_2_34 = `
Symbol table '.dynsym' contains 121 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.17 (2)
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memmove@GLIBC_2.17 (2)
    72: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND dlsym@GLIBC_2.34 (8)
    63: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND pthread_create@GLIBC_2.34 (8)
`;

// Real bytes from the same shim rebuilt through the pinned floor. This is what
// the guard has to pass, and the whole point of the pin: the highest reference
// left is gettid, which glibc has carried since 2.30.
const READELF_2_30 = `
Symbol table '.dynsym' contains 96 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.17 (2)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getcwd@GLIBC_2.17 (2)
    28: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND gettid@GLIBC_2.30 (5)
`;

// Real `objdump -T` bytes from the same binary. The version comes before the
// name here, and is parenthesized on an undefined symbol.
const OBJDUMP_2_39 = `
DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.34) dlsym
0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.34) pthread_detach
0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.39) pidfd_spawnp
`;

test('the published floor stays below Debian 12 glibc', () => {
  assert.equal(compareVersions(GLIBC_FLOOR, '2.36') < 0, true);
});

test('compares versions numerically rather than lexically', () => {
  assert.equal(compareVersions('2.9', '2.31'), -1);
  assert.equal(compareVersions('2.31', '2.9'), 1);
  assert.equal(compareVersions('2.34', '2.34'), 0);
  assert.equal(compareVersions('2.34', '2.34.1'), -1);
});

test('reads every requirement out of a readelf listing', () => {
  const requirements = parseGlibcRequirements(READELF_2_39);
  assert.deepEqual(
    requirements.map((requirement) => `${requirement.symbol}@${requirement.version}`),
    [
      'dlsym@2.34',
      'pthread_detach@2.34',
      'pidfd_spawnp@2.39',
      'pidfd_getpid@2.39',
    ],
  );
});

test('reads an objdump listing, whose columns are the other way round', () => {
  const summary = summarizeGlibcRequirements(OBJDUMP_2_39);
  assert.equal(summary.max, '2.39');
  assert.deepEqual(summary.symbols, ['pidfd_spawnp']);
});

test('names the symbols that set the highest requirement', () => {
  const summary = summarizeGlibcRequirements(READELF_2_39);
  assert.equal(summary.max, '2.39');
  assert.deepEqual(summary.symbols, ['pidfd_getpid', 'pidfd_spawnp']);
  assert.equal(summary.count, 4);
});

test('the floor-pinned shim passes', () => {
  const floor = checkFiles(['libkin_vfs_shim.so'], {
    run: () => READELF_2_30,
    log: () => {},
  });
  assert.equal(floor, GLIBC_FLOOR);
});

test('the runner-image shim at 2.34 is refused too, not just kin-vfs', () => {
  assert.throws(
    () => checkFiles(['libkin_vfs_shim.so'], { run: () => READELF_2_34, log: () => {} }),
    /libkin_vfs_shim\.so requires GLIBC_2\.34 \(dlsym, pthread_create\)/,
  );
});

test('the shipped 2.39 kin-vfs is refused, with the pidfd symbols named', () => {
  assert.throws(
    () => checkFiles(['kin-vfs'], { run: () => READELF_2_39, log: () => {} }),
    (error) => {
      assert.match(error.message, /kin-vfs requires GLIBC_2\.39/);
      assert.match(error.message, /pidfd_getpid/);
      assert.match(error.message, /pidfd_spawnp/);
      return true;
    },
  );
});

test('a binary exactly at the floor passes', () => {
  const atFloor = `    1: 0 0 FUNC GLOBAL DEFAULT UND memfd_create@GLIBC_${GLIBC_FLOOR} (3)\n`;
  assert.equal(
    checkFiles(['kin-vfs'], { run: () => atFloor, log: () => {} }),
    GLIBC_FLOOR,
  );
});

test('one requirement above the floor refuses the whole set', () => {
  const files = ['libkin_vfs_shim.so', 'kin-vfs'];
  assert.throws(
    () =>
      checkFiles(files, {
        run: (_command, _args, file) =>
          file === 'kin-vfs' ? READELF_2_39 : READELF_2_30,
        log: () => {},
      }),
    /kin-vfs requires GLIBC_2\.39/,
  );
});

test('an unreadable listing is refused rather than read as clean', () => {
  assert.throws(
    () => checkFiles(['kin-vfs'], { run: () => '', log: () => {} }),
    /unreadable rather than clean/,
  );
});

test('both symbol readers failing refuses rather than passing', () => {
  assert.throws(
    () => readDynamicSymbols('kin-vfs', { run: () => null }),
    /whose glibc floor was never read/,
  );
});

test('a check pointed at no binaries at all refuses', () => {
  assert.throws(
    () => checkFiles([], { run: () => READELF_2_34, log: () => {} }),
    /runs on nothing/,
  );
});
