# Store size

`kin init` writes a `.kin/` store beside your repository, and `kin init` and
`kin status` both report how large it is next to the Git object store it was
admitted from. This page explains what drives that number and records what has
actually been measured.

## What the number means

Two directories are walked and their file bytes summed.

- **Store**, everything under `.kin/`. That is the graph snapshot, the text
  index, the source CAS, and the repository authority payload.
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

The larger driver is the import itself. Git keeps history as zlib-compressed
objects packed with deltas, so one packfile holds every revision of a file as a
base plus a chain of differences. Kin admits that same reachable history into a
content-addressed store that writes each body verbatim, one file per body, with
no compression and no deltas between revisions. Everything Git had folded
together is unfolded. That cost is paid on a repository Kin parses nothing in:
a 27-file shell repository with zero entities extracted still produced a store
many times its pack.

On top of that, Kin derives a semantic entity and relation layer over every
revision, which adds a second, smaller amount that does scale with how much of
the history is in a language Kin parses. `kin languages` lists them.

Both terms scale with **history depth** rather than with the size of your
checkout, which is why a repository with a small working tree and thousands of
commits can still produce a large store.

The ratio is not a constant and it is not currently explained. It varies by
more than 3x across repositories of similar size in different languages, and
why is an open question rather than a documented property.

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

This is a record of what has been measured, not a bound. Kin does not currently
cap store size, warn above a threshold, or refuse to admit a repository for
being large. If your repository lands far outside this range, that is worth
reporting, and the numbers `kin status` prints are what to report.

## Where to see it

`kin init` prints the size and ratio when it completes, and `kin init --json`
carries the raw byte counts under `store_footprint` so you can record them.
`kin status` prints the same line for an existing repository.

`kin status --json` deliberately does NOT carry it. That payload is derived from
one immutable authority lease and is byte-identical no matter what the checkout
does, which is a property Kin tests directly. A store size is the opposite kind
of fact, since it moves whenever the working tree does, so it rides alongside the
report on the text surface rather than inside it.
