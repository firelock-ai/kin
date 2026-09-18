# kin-grammar-typescript

The tree-sitter TypeScript and TSX grammars, patched so two constructs `tsc`
accepts do not cost Kin the rest of the file.

Everything under `grammar/` is
[tree-sitter-typescript](https://github.com/tree-sitter/tree-sitter-typescript)
v0.23.2 (`f975a621f4e7f532fe322e13c4f79495e0a7b2e7`), MIT licensed, with the two
patches in `patches/` applied and the parser regenerated. `LICENSE` is upstream's.
Only `common/define-grammar.js` and `common/scanner.h` are edited by hand; the
files under `typescript/src` and `tsx/src` are generated from them.

## Why this is vendored rather than pinned

0.23.2 is the newest release on crates.io, published 2024-11-11, so there is no
version to upgrade to. Both defects below are upstream bugs rather than Kin bugs,
both reproduce in three lines, and each makes the parser return an `ERROR` node
that swallows every declaration after it. On `honojs/hono` at `098e1191` they cost
8 of 188 TypeScript files, holding 5,016 of the tree's 25,979 lines.

The patches are kept as separate files, in a shape that applies to an upstream
checkout, so each can be sent upstream without being reconstructed from a diff of
9 MB of generated C.

## The two patches

**0001, an object type member followed by a generic call signature.** A member
not terminated by `;` or `,`, followed by a member beginning with `<`:

```ts
interface I {
  p: string
  <T>(): void
}
```

The external scanner refused to insert an automatic semicolon before any `<`,
because a `<` on the next line usually continues an expression. Between the
members of an object type it does not: it opens the type parameters of a generic
call signature, and the member before it has already ended. TypeScript itself
reads it that way, and reports the type parameter `T` and the unparameterised
type on the line before as two separate members.

The patch adds `_type_member_automatic_semicolon`, an external token the scanner
never returns. The grammar makes it valid only between object type members, so
the scanner reads its validity to tell that boundary from every other place a
newline can precede a `<`. That is the same trick upstream already uses with
`_function_signature_automatic_semicolon`, which is likewise read and never
returned. Confining the change this way is what keeps `type A = B` followed by
`<number>` parsing exactly as it did.

**0002, type-only export star.** `export type * from './x'` and
`export type * as NS from './x'`, both valid since TypeScript 5.0, had no
alternative in `export_statement`. The patch adds the two the base JavaScript
grammar already spells for the untyped forms.

## Regenerating

The generated files were produced with tree-sitter CLI 0.24.4 and
tree-sitter-javascript 0.23.1, which are what upstream v0.23.2 pins. Regenerating
with those versions and no patches reproduces the published `parser.c` byte for
byte, so the diff in this directory is the patches and nothing else.

```sh
git clone --depth 1 --branch v0.23.2 \
  https://github.com/tree-sitter/tree-sitter-typescript.git upstream
cd upstream
npm install tree-sitter-javascript@0.23.1
git apply /path/to/patches/0001-*.patch /path/to/patches/0002-*.patch
(cd typescript && tree-sitter generate)   # tree-sitter CLI 0.24.4
(cd tsx        && tree-sitter generate)
```

Then copy `common/`, `queries/`, `tree-sitter.json`, and each dialect's
`grammar.js` and `src/` back under `grammar/`.

Changing anything here changes what a parse means, so bump
`kin_parser::PARSER_SEMANTICS_VERSION` in the same commit.
