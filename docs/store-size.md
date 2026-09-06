# Store size

`kin init` writes a `.kin/` store beside your repository, and `kin init` and
`kin status` both report how large it is next to the Git object store it was
admitted from. This page explains what drives that number and records what has
actually been measured.

## What the number means

Two directories are walked and their file bytes summed.

- **Store**, everything under `.kin/`. That is the graph snapshot, the admitted
  source bodies, the repository authority record, and any index built beside
  them.
- **Git object store**, everything under `.git/objects`, following a `.git`
  gitlink file when the checkout is a linked worktree or a submodule. Packfiles
  and loose objects both count.

The ratio is the first divided by the second. Neither number includes your
checkout, so a repository whose working tree dwarfs its history is not being
compared against its own file sizes.

Symlinks are skipped rather than followed, so a link out of the store never
charges it for bytes that live somewhere else. If any entry cannot be read, the
reported size becomes a stated floor ("at least N, M entries unreadable") rather
than a total, because a partial walk printed as a total would understate the
store.

## What drives it

The store is not a copy of the packfile, so it is not bounded by one, and the
gap is much larger than the semantic layer alone accounts for.

Two things account for almost all of the store on the repository broken down
below, and a third can appear and rival the snapshot in size. Broken down on
ripgrep at 2,261 commits, whose 6.1 MiB object store became a 405.4 MiB store:

| Part of `.kin/` | Size | Share |
| --- | --- | --- |
| `kindb/<repo>/snapshots` (the graph snapshot) | 287.4 MiB | 64% |
| `kindb/<repo>/source-blobs` (admitted bodies) | 159.8 MiB | 36% |
| everything else | under 1 MiB | rounding |

**Source blobs.** Git keeps history as zlib-compressed objects packed with
deltas, so one packfile holds every revision of a file as a base plus a chain of
differences. Kin admits that same reachable history into a content-addressed
store that writes each body verbatim, one file per body, with no compression and
no deltas between revisions. Everything Git had folded together is unfolded, and
14,063 reachable objects become 14,063 files. This cost is paid even where Kin
parses nothing: a 27-file shell repository with zero entities extracted still
produced a store many times its pack.

**The graph snapshot.** Larger than the blobs, and it is not a snapshot of the
current state. It carries the semantic layer for the whole history, one delta per
change, and a delta records entities in full rather than by reference. So the
snapshot grows with the number of entity identities the history ever held, which
is far more than the number alive at the tip: ripgrep's tip carries 3,568
entities across 2,327 changes, and an entity's identity is derived partly from
its starting line, so an edit that shifts a function down a file retires one
identity and creates another for code that did not change.

**The prepared query graph.** Not present in the ripgrep breakdown above, and
large enough elsewhere that a reader should not treat that breakdown as the
shape of every store. Kin writes a prepared workspace query graph at
`kindb/<repo>/prepared/<workspace>.kpqg`, with a small `.kpqg.json` binding
beside it, to accelerate reopening a workspace. On psf/requests at `dae7ef63b`
under v0.7.0 it measured 1163.50 MiB, 46.2% of a 2.46 GiB store, slightly
smaller than that store's graph snapshot and roughly nine times its admitted
bodies. It is written during `kin init` rather than by a later commit: on the
measured store its mtime preceded the command's own return by 24 seconds. It
appears to be tied to a workspace carrying a semantic overlay rather than
written unconditionally, so treat it as a component that can appear and can be
roughly half the store, not as a guaranteed third row.

The first two terms scale with **history depth** rather than with the size of
your checkout, which is why a repository with a small working tree and thousands
of commits can still produce a large store.

The ratio is not a constant and is not fully explained. It varies by more than
3x across repositories of similar size in different languages, and why is an open
question rather than a documented property.

A store can also land **below** its Git object store, but not for the reason it
is tempting to assume. A short history does not do it: a two-commit repository
measures well above, because a nearly empty store still carries fixed authority
scaffolding while a nearly empty object store carries almost nothing. What does
it is Git holding bytes Kin never admits. Git keeps unreachable objects until it
is garbage collected, and Kin admits exact reachable history only, so a
repository that has reset away a large commit carries megabytes in
`.git/objects` that are legitimately absent from `.kin/`.

## A note on which Git number you compare against

This page compares against `.git/objects`, the object store. Comparing against
the whole `.git` directory gives a different and smaller multiple, because
`.git` also holds the index, the config, and roughly 25 KB of sample hooks that
have nothing to do with your history. On a large repository the two are nearly
the same; on a tiny one they are not remotely the same, and the difference is
large enough to flip a ratio from above one to below it. The two-commit
repository in the table below measures 36.9x against the object store and 0.59x
against the whole `.git` directory. Neither is wrong, but they answer different
questions, and a ratio quoted without its denominator is not a measurement.

## Measured

Measured with the walk described above, on stores produced by `kin init` alone
with no embedding pass. Adding embeddings adds a vector index on top of these
numbers.

| Repository | Commits | Git object store | Kin store | Ratio |
| --- | --- | --- | --- | --- |
| ripgrep (Rust), at `e89fff89` | 2,261 | 6.1 MiB | 405.4 MiB | 66.5x |
| cobra (Go), at `adbc8813` | 1,106 | 2.2 MiB | 121.2 MiB | 55.6x |
| a two-commit fixture (one Rust file) | 2 | 444 B | 16.0 KiB | 36.9x |
| a fixture that reset away a 3 MB commit | 1 | 2.9 MiB | 10.6 KiB | `<0.01x` |

Reported separately, measured against packs rather than by the walk above, so
listed as corroboration rather than as rows measured the same way: anyhow 47x,
click 109.1x, zod 163x, sinatra 75.1x, and a 27-file shell repository with zero
entities extracted at 27.4x.

Across every real repository named on this page, the table and the corroboration
list together, the measured ratios span **27.4x to 163x**: 27.4x, 47x, 55.6x,
66.5x, 75.1x, 109.1x and 163x. The table's other two rows are fixtures built to
show edge behaviour rather than repositories. So the table's two repository rows
are not the range, and reading the table alone gives a much narrower impression
than this page's own numbers support.

This is a record of what has been measured, not a bound. Kin does not currently
cap store size, warn above a threshold, or refuse to admit a repository for
being large. If your repository lands far outside 27.4x to 163x, that is worth
reporting, and the numbers `kin status` prints are what to report.

One repository is deliberately absent from the table. psf/requests at
`dae7ef63b` has been measured at 178.0x under v0.7.0, but that store carried a
partial embedding pass and one commit, so it was not produced by `kin init`
alone and a row from it would not mean what the other rows mean. It is named
here rather than added above, because a table whose rows were gathered different
ways stops being a comparison.

## Where to see it

`kin init` prints the size and ratio when it completes, and `kin init --json`
carries the raw byte counts under `store_footprint` so you can record them.
`kin status` prints the same line for an existing repository.

`kin status --json` deliberately does NOT carry it. That payload is derived from
one immutable authority lease and is byte-identical no matter what the checkout
does, which is a property Kin tests directly. A store size is the opposite kind
of fact, since it moves whenever the working tree does, so it rides alongside the
report on the text surface rather than inside it.
