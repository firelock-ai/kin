// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The Kin mark, drawn for a terminal.
//!
//! One implementation, three call sites: `kin --version`, the `kin init`
//! result, and the `kin doctor` header. Nothing else prints it. A mark on every
//! command is a mark nobody sees, and it would break every caller that reads a
//! command's first line.
//!
//! The shape comes from the brand kit's mark, `docs/brand/assets/svg/
//! kin-mark-gradient.svg` at v1.2. That file is two filled paths and no
//! vertical spine: an arm running from the upper right down to the left, and a
//! leg running from there down to the lower right, separated by a hairline
//! split. At terminal resolution the split is narrower than a cell, so the rows
//! below carry it as a one-column notch between the arm's last row and the
//! leg's first, which is the only way the two strokes stay legible as two.
//!
//! The colours are the kit's own `gradient/kin-arm` and `gradient/kin-leg`
//! stops. A terminal that advertises truecolor gets those hexes exactly; every
//! other coloured terminal gets four 256-colour indices chosen to hold the same
//! magenta-to-blue ramp, because a nearest-cube mapping of the four stops
//! collapses two of them onto one index and the ramp goes flat.
//!
//! Four ways out, in the order they are checked. Not a terminal: nothing is
//! drawn and the caller's text is returned untouched, so a redirected or piped
//! `kin --version` stays the single line every script already parses. Too
//! narrow: nothing is drawn, because seven columns of mark on a forty-column
//! terminal costs more than it gives. A locale that is not UTF-8: the ASCII
//! rows. Colour off, meaning `NO_COLOR`, `TERM=dumb`, or a pipe: the glyphs
//! without escapes. `NO_COLOR` is about colour and not about glyphs, so a
//! terminal under it still gets the mark, in plain text.

use std::io::IsTerminal;

/// The mark's four rows in box-drawing half blocks.
///
/// Rows 0 and 1 are the arm, rows 2 and 3 the leg. The leg is indented one
/// column past where the arm ends, and that offset is the split: without it the
/// arm's lower half-block and the leg's upper half-block share a column edge,
/// join into a solid bar, and the mark reads as a plain chevron.
const UNICODE_ROWS: [&str; 4] = [
    "  \u{2584}\u{2580}",
    "\u{2584}\u{2580}",
    " \u{2580}\u{2584}",
    "   \u{2580}\u{2584}",
];

/// The same shape where the locale cannot carry the block characters.
const ASCII_ROWS: [&str; 4] = ["  /", "/", " \\", "   \\"];

/// Columns reserved for the mark itself, wide enough for the longest row.
const MARK_COLUMNS: usize = 5;

/// Blank columns between the mark and the text beside it.
const GUTTER_COLUMNS: usize = 2;

/// Below this terminal width the mark is not drawn at all.
///
/// The mark plus its gutter takes [`MARK_COLUMNS`] + [`GUTTER_COLUMNS`] columns
/// away from every line beside it. On a terminal this narrow the text needs
/// them more than the mark does.
const MIN_TERMINAL_COLUMNS: usize = 40;

/// The brand kit's gradient stops, arm first then leg.
const TRUECOLOR_STOPS: [(u8, u8, u8); 4] = [
    (0xAE, 0x5A, 0xFF),
    (0x6C, 0x48, 0xFA),
    (0x5B, 0x55, 0xFD),
    (0x3B, 0x74, 0xFB),
];

/// The same ramp in the 256-colour cube.
///
/// Chosen rather than derived. Mapping the four stops to their nearest cube
/// entries yields 135, 63, 63 and 75: the arm's second stop and the leg's first
/// land on the same index, so the middle of the mark goes flat exactly where
/// the split is. These four hold the ramp and keep the four rows distinct.
const INDEXED_STOPS: [u8; 4] = [141, 99, 63, 69];

/// Which glyphs this terminal can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glyphs {
    /// Box-drawing half blocks.
    Unicode,
    /// Slashes, for a locale that is not UTF-8.
    Ascii,
}

/// How much colour this terminal takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paint {
    /// 24-bit escapes carrying the kit's hexes exactly.
    Truecolor,
    /// 256-colour indices holding the same ramp.
    Indexed,
    /// No escapes at all.
    None,
}

/// A decided way to draw the mark here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarkStyle {
    glyphs: Glyphs,
    paint: Paint,
}

impl MarkStyle {
    /// A style named outright, for tests and for a caller that already knows.
    pub fn new(glyphs: Glyphs, paint: Paint) -> Self {
        Self { glyphs, paint }
    }

    /// How the mark should be drawn on this process's stdout, or `None` when it
    /// should not be drawn at all.
    ///
    /// The two `None` cases are the ones that would do harm. A stdout that is
    /// not a terminal is being read by something, and four rows of art would
    /// break it. A terminal under [`MIN_TERMINAL_COLUMNS`] cannot spare the
    /// columns.
    pub fn for_stdout() -> Option<Self> {
        if !std::io::stdout().is_terminal() {
            return None;
        }
        if terminal_columns().is_some_and(|columns| columns < MIN_TERMINAL_COLUMNS) {
            return None;
        }
        Some(Self {
            glyphs: detect_glyphs(),
            paint: detect_paint(),
        })
    }

    fn rows(&self) -> [&'static str; 4] {
        match self.glyphs {
            Glyphs::Unicode => UNICODE_ROWS,
            Glyphs::Ascii => ASCII_ROWS,
        }
    }

    /// One row of the mark, painted if this style paints.
    fn paint_row(&self, index: usize, row: &str) -> String {
        if row.is_empty() {
            return String::new();
        }
        match self.paint {
            Paint::None => row.to_string(),
            Paint::Truecolor => {
                let (r, g, b) = TRUECOLOR_STOPS[index.min(TRUECOLOR_STOPS.len() - 1)];
                format!("\u{1b}[38;2;{r};{g};{b}m{row}\u{1b}[0m")
            }
            Paint::Indexed => {
                let code = INDEXED_STOPS[index.min(INDEXED_STOPS.len() - 1)];
                format!("\u{1b}[38;5;{code}m{row}\u{1b}[0m")
            }
        }
    }
}

/// The mark with `text` set beside it, one text line per mark row.
///
/// Index-aligned on purpose: the caller decides which row a line sits on by
/// where it puts the line, and an empty string leaves that row to the mark
/// alone. More text lines than mark rows is fine; they continue under the mark,
/// indented to the same column so the block stays one shape.
///
/// A row with no text ends at the last glyph. Trailing spaces on a mark row
/// would be invisible on screen and would show up in every captured transcript,
/// every snapshot, and every terminal that highlights them.
pub fn beside(style: MarkStyle, text: &[&str]) -> Vec<String> {
    let rows = style.rows();
    let indent = MARK_COLUMNS + GUTTER_COLUMNS;
    let height = rows.len().max(text.len());
    let mut out = Vec::with_capacity(height);
    for index in 0..height {
        let glyph = rows.get(index).copied().unwrap_or("");
        let line = text.get(index).copied().unwrap_or("");
        if line.is_empty() {
            out.push(style.paint_row(index, glyph));
            continue;
        }
        let pad = indent.saturating_sub(glyph.chars().count());
        out.push(format!(
            "{}{}{line}",
            style.paint_row(index, glyph),
            " ".repeat(pad)
        ));
    }
    out
}

/// [`beside`] under a style, and the text alone under none.
///
/// Split from the terminal check so both arms can be exercised without a
/// terminal. A test that asks for the no-style arm by reimplementing the filter
/// inline is a test that passes whatever this function does.
///
/// This deliberately keeps every non-empty line, which is right for a version
/// block whose lines are all content and wrong for a header whose title is
/// decoration. A caller with something that should vanish along with the mark
/// has to decide that before calling here; `report_header` in `commands/setup`
/// is what that looks like, and getting it wrong is what put a title into every
/// piped `kin doctor`.
///
/// The empty lines a caller used to place text against the mark's rows are
/// dropped here rather than printed as blanks: without the mark there is
/// nothing for them to align to, and a leading blank line would still change
/// what a reader of the output sees.
pub fn beside_or_plain(style: Option<MarkStyle>, text: &[&str]) -> Vec<String> {
    match style {
        Some(style) => beside(style, text),
        None => text
            .iter()
            .filter(|line| !line.is_empty())
            .map(|line| (*line).to_string())
            .collect(),
    }
}

/// This terminal's width, when it can be read.
fn terminal_columns() -> Option<usize> {
    let (_, columns) = console::Term::stdout().size_checked()?;
    Some(usize::from(columns))
}

/// The glyphs this locale can carry.
///
/// The first of the three locale variables that is set and non-empty decides
/// it, which is the order POSIX gives them. None set at all means Unicode:
/// Windows sets none of them and its console reads UTF-8, and the CLI already
/// prints check marks and arrows on every platform, so ASCII here would be a
/// fallback for a case that does not arise while making the common case worse.
fn detect_glyphs() -> Glyphs {
    let values: Vec<Option<String>> = ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .map(|name| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned()))
        .collect();
    glyphs_for_locale(&values)
}

/// The glyph choice for a given set of locale values, in POSIX precedence.
///
/// Split from the environment read so both arms are testable: no test in this
/// binary can set an environment variable without racing every other test in
/// it, and a test that asserts on a locale string it wrote itself proves
/// nothing about the function that reads one.
fn glyphs_for_locale(values: &[Option<String>]) -> Glyphs {
    for value in values {
        let Some(value) = value else { continue };
        if value.is_empty() {
            continue;
        }
        return if value.to_ascii_lowercase().contains("utf") {
            Glyphs::Unicode
        } else {
            Glyphs::Ascii
        };
    }
    Glyphs::Unicode
}

/// How much colour to use, deferring to the CLI's one colour decision.
fn detect_paint() -> Paint {
    if !crate::output_style::enabled() {
        return Paint::None;
    }
    match std::env::var("COLORTERM") {
        Ok(value)
            if value.eq_ignore_ascii_case("truecolor") || value.eq_ignore_ascii_case("24bit") =>
        {
            Paint::Truecolor
        }
        _ => Paint::Indexed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain mark, which every other rendering is a variation of.
    ///
    /// Written out rather than built from the constants: a snapshot that
    /// composes itself from the same source it is checking passes whatever that
    /// source becomes, and this one exists to notice the shape changing.
    #[test]
    fn the_unicode_mark_is_the_split_k() {
        let drawn = beside(MarkStyle::new(Glyphs::Unicode, Paint::None), &[]);
        assert_eq!(
            drawn,
            vec![
                "  \u{2584}\u{2580}".to_string(),
                "\u{2584}\u{2580}".to_string(),
                " \u{2580}\u{2584}".to_string(),
                "   \u{2580}\u{2584}".to_string(),
            ]
        );
    }

    /// The split is what separates the mark from a plain chevron.
    ///
    /// The arm's last row ends at column 1 and the leg's first row starts at
    /// column 1 with a half block on the opposite side, so the two strokes meet
    /// diagonally rather than sharing a column edge. Delete the leading space
    /// on row 2 and the mark becomes a solid `<`, which is the failure this
    /// pins.
    #[test]
    fn the_arm_and_the_leg_do_not_share_a_column() {
        let arm_last = UNICODE_ROWS[1];
        let leg_first = UNICODE_ROWS[2];
        let arm_end = arm_last.chars().count();
        let leg_start = leg_first
            .chars()
            .position(|character| character != ' ')
            .expect("the leg's first row draws something");
        assert!(
            leg_start >= arm_end - 1,
            "the leg starts at column {leg_start} and the arm ends at column {arm_end}, so the \
             two strokes share a column and the split is gone"
        );
    }

    /// The ASCII rows carry the same shape at the same columns.
    #[test]
    fn the_ascii_mark_holds_the_shape() {
        let drawn = beside(MarkStyle::new(Glyphs::Ascii, Paint::None), &[]);
        assert_eq!(
            drawn,
            vec![
                "  /".to_string(),
                "/".to_string(),
                " \\".to_string(),
                "   \\".to_string(),
            ]
        );
    }

    /// Truecolor paints the kit's own hexes, one stop per row.
    #[test]
    fn truecolor_paints_the_brand_stops() {
        let drawn = beside(MarkStyle::new(Glyphs::Unicode, Paint::Truecolor), &[]);
        assert_eq!(
            drawn,
            vec![
                "\u{1b}[38;2;174;90;255m  \u{2584}\u{2580}\u{1b}[0m".to_string(),
                "\u{1b}[38;2;108;72;250m\u{2584}\u{2580}\u{1b}[0m".to_string(),
                "\u{1b}[38;2;91;85;253m \u{2580}\u{2584}\u{1b}[0m".to_string(),
                "\u{1b}[38;2;59;116;251m   \u{2580}\u{2584}\u{1b}[0m".to_string(),
            ]
        );
    }

    /// The 256-colour ramp keeps four distinct indices.
    #[test]
    fn the_indexed_ramp_has_four_distinct_stops() {
        let drawn = beside(MarkStyle::new(Glyphs::Unicode, Paint::Indexed), &[]);
        assert_eq!(
            drawn,
            vec![
                "\u{1b}[38;5;141m  \u{2584}\u{2580}\u{1b}[0m".to_string(),
                "\u{1b}[38;5;99m\u{2584}\u{2580}\u{1b}[0m".to_string(),
                "\u{1b}[38;5;63m \u{2580}\u{2584}\u{1b}[0m".to_string(),
                "\u{1b}[38;5;69m   \u{2580}\u{2584}\u{1b}[0m".to_string(),
            ]
        );
        let mut seen: Vec<u8> = INDEXED_STOPS.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            INDEXED_STOPS.len(),
            "two rows of the mark share a 256-colour index, so the ramp is flat where they meet"
        );
    }

    /// Every text line starts at the same column, whatever its row draws.
    #[test]
    fn text_beside_the_mark_is_left_aligned() {
        let drawn = beside(
            MarkStyle::new(Glyphs::Unicode, Paint::None),
            &["one", "two", "three", "four"],
        );
        for line in &drawn {
            let at = line
                .char_indices()
                .find(|(_, character)| character.is_ascii_alphabetic())
                .map(|(index, _)| line[..index].chars().count())
                .expect("each line carries its text");
            // The literal, not `MARK_COLUMNS + GUTTER_COLUMNS`. Written
            // against the constants, this assertion recomputed its own
            // expectation whenever either moved, so it held for every value
            // they could take and guarded nothing. The mutation sweep found it:
            // dropping the gutter to one column left this test green while its
            // sibling, written against the literal, went red.
            assert_eq!(at, 7, "text starts at column {at} on line {line:?}");
        }
    }

    /// Text longer than the mark keeps the same indent under it.
    #[test]
    fn text_past_the_last_row_stays_indented() {
        let drawn = beside(
            MarkStyle::new(Glyphs::Unicode, Paint::None),
            &["", "", "", "", "fifth"],
        );
        assert_eq!(drawn.len(), 5);
        assert_eq!(drawn[4], format!("{}fifth", " ".repeat(7)));
    }

    /// A row the caller left to the mark carries no trailing spaces.
    #[test]
    fn a_mark_only_row_ends_at_its_last_glyph() {
        for style in [
            MarkStyle::new(Glyphs::Unicode, Paint::None),
            MarkStyle::new(Glyphs::Unicode, Paint::Truecolor),
            MarkStyle::new(Glyphs::Ascii, Paint::None),
        ] {
            for line in beside(style, &["", "", "", ""]) {
                assert!(
                    !line.ends_with(' '),
                    "the row {line:?} pads past its last glyph"
                );
            }
        }
    }

    /// The whole block fits the terminals the walk was measured at.
    ///
    /// Both widths, and the width the mark itself costs is checked separately
    /// so a regression says which of the two moved.
    #[test]
    fn the_block_fits_eighty_and_one_hundred_and_twenty_columns() {
        let text = [
            "",
            "kin 0.7.2",
            "The system of record for AI-written software.",
            "",
        ];
        for style in [
            MarkStyle::new(Glyphs::Unicode, Paint::None),
            MarkStyle::new(Glyphs::Unicode, Paint::Truecolor),
            MarkStyle::new(Glyphs::Unicode, Paint::Indexed),
            MarkStyle::new(Glyphs::Ascii, Paint::None),
        ] {
            for line in beside(style, &text) {
                let width = console::measure_text_width(&line);
                assert!(
                    width <= 80,
                    "the line {line:?} is {width} columns wide, so it wraps at 80"
                );
            }
        }
    }

    /// The mark never costs more than the columns it reserved.
    #[test]
    fn the_mark_stays_inside_its_own_columns() {
        for rows in [UNICODE_ROWS, ASCII_ROWS] {
            for row in rows {
                let width = console::measure_text_width(row);
                assert!(
                    width <= MARK_COLUMNS,
                    "the row {row:?} is {width} columns wide, past the {MARK_COLUMNS} reserved"
                );
            }
        }
    }

    /// Colour is escapes and nothing else.
    ///
    /// Stripping them from a painted block yields the unpainted block exactly,
    /// which is what lets a caller reason about width without knowing whether
    /// colour is on.
    #[test]
    fn stripping_the_escapes_yields_the_plain_block() {
        let text = ["", "kin 0.7.2", "", ""];
        let plain = beside(MarkStyle::new(Glyphs::Unicode, Paint::None), &text);
        for paint in [Paint::Truecolor, Paint::Indexed] {
            let painted = beside(MarkStyle::new(Glyphs::Unicode, paint), &text);
            let stripped: Vec<String> = painted
                .iter()
                .map(|line| console::strip_ansi_codes(line).into_owned())
                .collect();
            assert_eq!(stripped, plain, "painting changed more than the colour");
        }
    }

    /// With no style, the caller's text is all that is printed.
    ///
    /// This is the shape a pipe gets, and it is why `kin --version | cat` is
    /// still one line that a script can read. The empty rows a caller placed
    /// text against go with the mark, so no leading blank line survives either.
    #[test]
    fn without_a_style_only_the_text_survives() {
        assert_eq!(
            beside_or_plain(None, &["", "kin 0.7.2", "", ""]),
            vec!["kin 0.7.2".to_string()]
        );
        assert_eq!(
            beside_or_plain(None, &["", "one", "two", ""]),
            vec!["one".to_string(), "two".to_string()]
        );
    }

    /// A locale that names a non-UTF-8 charset takes the ASCII rows.
    #[test]
    fn a_non_utf8_locale_name_selects_ascii() {
        let set = |value: &str| vec![None, None, Some(value.to_string())];
        for name in ["en_US.ISO8859-1", "C", "POSIX", "ru_RU.KOI8-R"] {
            assert_eq!(
                glyphs_for_locale(&set(name)),
                Glyphs::Ascii,
                "{name} must not be read as UTF-8"
            );
        }
        for name in ["en_US.UTF-8", "C.utf8", "en_GB.UTF8"] {
            assert_eq!(
                glyphs_for_locale(&set(name)),
                Glyphs::Unicode,
                "{name} must be read as UTF-8"
            );
        }
    }

    /// The first locale value that is set decides, and an empty one does not.
    ///
    /// POSIX gives `LC_ALL` precedence over `LC_CTYPE` over `LANG`, and an
    /// empty value is unset rather than a charset name. A loop that returned on
    /// the first Some rather than the first non-empty Some would read an
    /// exported-but-empty `LC_ALL`, which is common, as a non-UTF-8 locale and
    /// hand every such terminal the ASCII rows.
    #[test]
    fn locale_precedence_skips_empty_values() {
        assert_eq!(
            glyphs_for_locale(&[
                Some("en_US.UTF-8".to_string()),
                Some("C".to_string()),
                Some("C".to_string())
            ]),
            Glyphs::Unicode,
            "LC_ALL must win"
        );
        assert_eq!(
            glyphs_for_locale(&[
                Some(String::new()),
                Some(String::new()),
                Some("en_US.UTF-8".to_string())
            ]),
            Glyphs::Unicode,
            "an empty value must be skipped rather than read as a charset"
        );
        assert_eq!(
            glyphs_for_locale(&[None, None, None]),
            Glyphs::Unicode,
            "no locale set at all is the Windows case, and its console reads UTF-8"
        );
    }
}
