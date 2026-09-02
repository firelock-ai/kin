# Kin

Claude Code reads this filename; the repository's agent contract lives in `AGENTS.md`, imported
below so both filenames load the same text. Edit `AGENTS.md`, never this file.

This is a regular file rather than a symlink to `AGENTS.md` on purpose. kin's source is archived
into a promotion bundle (`git archive --prefix=kin/` in kin-infra's `promote-image.yml`) and the
bundle validator refuses any non-regular entry, so a symlink here fails production image
promotion with `kin-contracts-source.tar: non-regular entry kin/CLAUDE.md` after the release has
already been tagged and published. Keep every tracked path in this repository a regular file.

@AGENTS.md
