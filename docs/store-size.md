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
ripgrep at 2,261 commits under v0.7.2 (measured 2026-09-07 at `e89fff89`),
whose 5.7 MiB object store became a 703.9 MiB store:

| Part of `.kin/` | Size (by `du`) | Share |
| --- | --- | --- |
| `kindb/<repo>/snapshots` (the graph snapshot) | 592.9 MiB | 78.6% |
| `kindb/<repo>/source-blobs` (admitted bodies) | 154.0 MiB | 20.4% |
| everything else | about 7 MiB | 1.0% |

This breakdown is measured by `du`, which counts allocated disk blocks rather
than the logical file bytes this page's own walk sums, so it totals 754.2 MiB
here, above the 703.9 MiB `kin init` itself prints. The two methods measure
different things and are not meant to be added across columns; a table like
this one, left unlabeled, is what put a wrong number on this page the first
time.

**Source blobs.** Git keeps history as zlib-compressed objects packed with
deltas, so one packfile holds every revision of a file as a base plus a chain of
differences. Kin admits that same reachable history into a content-addressed
store that writes each body verbatim, one file per body, with no compression and
no deltas between revisions. Everything Git had folded together is unfolded: on
ripgrep's admitted history (v0.7.2, 2026-09-07) 13,383 reachable objects become
13,383 files. This cost is paid even on a repository with no entities extracted
at all, since every admitted revision still needs a body on disk.

**The graph snapshot.** Larger than the blobs, and it is not a snapshot of the
current state. It carries the semantic layer for the whole history, one delta per
change, and a delta records entities in full rather than by reference. So the
snapshot grows with the number of entity identities the history ever held, which
is far more than the number alive at the tip: ripgrep's tip carries 3,563
entities (v0.7.2, 2026-09-07), and an entity's identity is derived partly from
its starting line, so an edit that shifts a function down a file retires one
identity and creates another for code that did not change.

**The prepared query graph.** Not present in the ripgrep breakdown above, and
large enough elsewhere that a reader should not treat that breakdown as the
shape of every store. Kin writes a prepared workspace query graph at
`kindb/<repo>/prepared/<workspace>.kpqg`, with a small `.kpqg.json` binding
beside it, to accelerate reopening a workspace. On psf/requests at
`dae7ef63b` it measured 1163.50 MiB under v0.7.0 and 1377.80 MiB under v0.7.2
(2026-09-06), a rise of 18.4% on byte-identical input; under v0.7.0 that was
46.2% of a 2.46 GiB store, slightly smaller than that store's graph snapshot
and roughly nine times its admitted bodies. It is written during `kin init`
rather than by a later commit: on the measured store its mtime preceded the
command's own return by 24 seconds. It appears to be tied to a workspace
carrying a semantic overlay rather than written unconditionally, so treat it
as a component that can appear and can be roughly half the store, not as a
guaranteed third row.

The first two terms scale with **history depth** rather than with the size of
your checkout, which is why a repository with a small working tree and thousands
of commits can still produce a large store.

The ratio is not a constant and is not fully explained. It depends on how much
of a repository's history is still reachable, how many distinct entity
identities that history ever held, and how a language's own structure maps to
entities, and why it varies as much as it does across repositories is an open
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
numbers. Every figure below carries the Kin version and the date it was
measured, because a number without both is not safe to read as current: an
unstamped ripgrep figure sat on this page for a month and understated the real
cost by 1.74x, as the row below now shows.

| Repository | Commits | Git object store | Kin store | Ratio | Version, date |
| --- | --- | --- | --- | --- | --- |
| ripgrep (Rust), at `e89fff89` | 2,261 | 5.7 MiB | 703.9 MiB | 122.7x | v0.7.2, 2026-09-07 |
| a two-commit fixture (one Rust file) | 2 | 444 B | 16.0 KiB | 36.9x | synthetic fixture |
| a fixture that reset away a 3 MB commit | 1 | 2.9 MiB | 10.6 KiB | `<0.01x` | synthetic fixture |

Cobra and a corroboration list of five more repositories this page used to
cite (anyhow at 47x, click at 109.1x, zod at 163x, sinatra at 75.1x, and a
27-file shell repository at 27.4x) are removed here. All six came from the
same August 2026 measurement pass as the old ripgrep figure, a Kin build from
around v0.5.6, at least a dozen releases before today's v0.7.2, and none could
be traced to an exact build. The ripgrep row above shows what that gap costs
when a figure sits unstamped: the same-vintage number understated today's real
cost by 1.74x. They are pending re-measurement on the shipped release rather
than published as comparisons this page can no longer stand behind.

This is a record of what has been measured, not a bound. Kin does not currently
cap store size, warn above a threshold, or refuse to admit a repository for
being large. Right now this page can stand behind one current ratio, ripgrep's
122.7x under v0.7.2; the wider range this page used to quote came from the
figures pulled above. If your own repository's ratio surprises you, the
numbers `kin status` prints are what to report.

One repository is deliberately absent from the table. psf/requests at
`dae7ef63b` measures 178.0x under v0.7.0 and 208.7x under v0.7.2 (2026-09-06),
both produced by `kin init` alone, but both runs also completed a full
embedding pass before the store was read, so the figure carries a vector index
on top of what the table above measures. A row from it would not mean what the
other rows mean, so it is named here rather than added above.

## Where to see it

`kin init` prints the size and ratio when it completes, and `kin init --json`
carries the raw byte counts under `store_footprint` so you can record them.
`kin status` prints the same line for an existing repository.

`kin status --json` deliberately does NOT carry it. That payload is derived from
one immutable authority lease and is byte-identical no matter what the checkout
does, which is a property Kin tests directly. A store size is the opposite kind
of fact, since it moves whenever the working tree does, so it rides alongside the
report on the text surface rather than inside it.
