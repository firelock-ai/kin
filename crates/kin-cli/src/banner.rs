// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The Kin logo, printed when a person starts working with Kin.
//!
//! Three moments print it: the start of an interactive `kin setup`, the start
//! of a human-mode `kin init`, and a bare `kin`, whose help screen is the first
//! thing a new user reads. Nothing else does. `kin --help` and every
//! subcommand's help stay plain text, because scripts and snapshot tests read
//! them, and the smaller mark in [`crate::mark`] already covers
//! `kin --version`, the `kin init` result and the `kin doctor` header.
//!
//! The logo is the Kin mark beside the KIN wordmark, with the brand line under
//! the wordmark: eight rows and at most [`WIDTH`] columns. The mark follows
//! `docs/assets/kin-icon.svg`, two filled bands, an arm and a leg, split by a
//! hairline. Each terminal row carries two pixel rows through the half-block
//! glyphs, which makes the pixels square, and the mark is sixteen of them
//! tall. The split survives as a one-pixel channel and no cell holds both
//! pieces, so the arm and the leg stay two shapes even without colour.
//!
//! It goes to stdout, only on a terminal, and at most once per process.
//! Nothing is printed when the caller's output is for a program (`--json`, a
//! non-interactive setup), when `CI` is set, when `KIN_NO_BANNER` is truthy,
//! or when the terminal is too narrow to hold it. `NO_COLOR` and `TERM=dumb`
//! take the colour away and leave the logo. The colour depth is
//! [`crate::mark`]'s decision: the brand gradients on a truecolor terminal,
//! one 256-colour index per piece, or ANSI magenta and bright blue.
//!
//! The half blocks are drawn only where the terminal reliably reads UTF-8: a
//! UTF-8 locale, or on Windows, Windows Terminal or a console on the UTF-8
//! code page. Anywhere else the logo is ASCII, with the arm hatched in `/` and
//! the leg in `\`, the directions the two bands run.

use std::io::{IsTerminal, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::mark::{Glyphs, Paint};

/// The logo in pixels, two to a terminal row.
///
/// `A` is the mark's arm, `L` its leg, `W` the wordmark and `.` background.
/// The mark fills the first twelve columns. The wordmark starts at
/// [`WORDMARK_COLUMN`] and three pixels down, which centres it against the
/// mark as the brand lockup does. The one-pixel gap between the arm's last
/// rows and the leg's first is the split.
const PIXELS: [&str; 16] = [
    "...AAAAAAA.............................",
    "..AAAAAAAA.............................",
    ".AAAAAAAA..............................",
    "AAAAAAAA..........W....W...W....W.....W",
    "AAAAAAA...........W...W....W....WW....W",
    "AAAAAA............W..W.....W....W.W...W",
    "AAAAA.............W.W......W....W.W...W",
    "AAAA..............WW.......W....W..W..W",
    "AAA...............W.W......W....W...W.W",
    "AA..LL............W..W.....W....W...W.W",
    "...LLLL...........W...W....W....W....WW",
    "..LLLLLL..........W....W...W....W.....W",
    ".LLLLLLLL..............................",
    "..LLLLLLLL.............................",
    "...LLLLLLLL............................",
    "....LLLLLLLL...........................",
];

/// The logo in ASCII, one string per terminal row.
///
/// Left of [`WORDMARK_COLUMN`], `/` is the arm and `\` the leg. From that
/// column on, every glyph is the wordmark.
const ASCII_ROWS: [&str; ROWS] = [
    r"   ///////",
    r"  ////////        |  /   |   |\    |",
    r" ///////          | /    |   | \   |",
    r" /////            |<     |   |  \  |",
    r" ///              | \    |   |   \ |",
    r"    \\\\          |  \   |   |    \|",
    r"   \\\\\\\",
    r"     \\\\\\\\",
];

/// Terminal rows the logo takes.
const ROWS: usize = PIXELS.len() / 2;

/// The column the wordmark, and the brand line under it, start at.
const WORDMARK_COLUMN: usize = 18;

/// Blank columns in front of the logo.
const MARGIN: usize = 2;

/// The brand line, verbatim from the brand canon.
const BRAND_LINE: &str = "A new foundation for code.";

/// The row the brand line sits on: the last, level with the foot of the leg.
const BRAND_LINE_ROW: usize = ROWS - 1;

/// The widest line the logo prints, margin included.
///
/// A terminal narrower than this gets no logo rather than a wrapped one.
pub const WIDTH: usize = MARGIN + WORDMARK_COLUMN + BRAND_LINE.len();

// The logo is sized for a narrow terminal, and a change that widens it past
// that budget fails the build rather than a reader's terminal.
const _: () = assert!(WIDTH <= 48, "the logo is wider than 48 columns");

/// The brand gradients' end points, in this grid's pixels.
///
/// `kin-icon.svg` runs the arm's gradient from (391, 52) to (105, 338) and the
/// leg's from (177, 309) to (436, 460). The mark's top-left corner there is
/// (105, 52) and it is 408.1 units tall, so at sixteen pixels one pixel is
/// 25.5 units.
const ARM_GRADIENT: [(f32, f32); 2] = [(11.21, 0.0), (0.0, 11.21)];
const LEG_GRADIENT: [(f32, f32); 2] = [(2.82, 10.08), (12.98, 16.0)];

/// One 256-colour index per piece: the cube's purple nearest the arm's first
/// stop, and its blue nearest the leg's last.
///
/// A two-step ramp inside each piece read as a crease across it, and the two
/// pieces' average colours land on neighbouring indices that barely tell the
/// arm from the leg, which is the one thing the mark has to show.
const INDEXED_ARM: u8 = 135;
const INDEXED_LEG: u8 = 69;

/// The brand line in the kit's secondary text colour, `#9BA1AC`.
const BRAND_LINE_TRUECOLOR: &str = "\u{1b}[38;2;155;161;172m";
/// The 256-colour grey nearest that colour.
const BRAND_LINE_INDEXED: &str = "\u{1b}[38;5;247m";
/// Faint, for sixteen colours: ANSI bright black is the background colour in
/// some palettes, and faint keeps the line readable in every one of them.
const BRAND_LINE_BASIC: &str = "\u{1b}[2m";

const RESET: &str = "\u{1b}[0m";

/// Set once the logo has printed, so a process prints it at most once.
static PRINTED: AtomicBool = AtomicBool::new(false);

/// Print the logo on stdout when this is a moment for it, and say whether it
/// printed.
///
/// `human_mode` is the caller's word that a person reads this command's output
/// as it runs. Pass `false` for `--json`, for a non-interactive setup, and for
/// any other output a program reads. Everything else, the terminal, `CI`,
/// `KIN_NO_BANNER`, the width and the colour depth, is checked here.
///
/// The logo brings a blank line above and below it, so a caller that opens
/// with a blank line of its own can drop that line when this returns `true`.
pub fn print_once(human_mode: bool) -> bool {
    if !human_mode || PRINTED.load(Ordering::SeqCst) {
        return false;
    }
    let read =
        |name: &str| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
    let surroundings = Surroundings {
        stdout_is_terminal: std::io::stdout().is_terminal(),
        columns: crate::mark::terminal_columns(),
        windows: cfg!(windows),
        utf8_console: console_output_is_utf8(),
        var: &read,
    };
    let Some(style) = plan(&surroundings, human_mode) else {
        return false;
    };
    if !claim(&PRINTED) {
        return false;
    }
    print!("{}", framed(&render(style)));
    let _ = std::io::stdout().flush();
    true
}

/// The logo's lines with a blank line above and below, as one write.
fn framed(lines: &[String]) -> String {
    let mut block = String::from("\n");
    for line in lines {
        block.push_str(line);
        block.push('\n');
    }
    block.push('\n');
    block
}

/// Take the once-per-process slot, `true` only for the first caller.
fn claim(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::SeqCst)
}

/// How the logo is drawn once it is decided that it is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Style {
    glyphs: Glyphs,
    paint: Paint,
}

/// What the decision reads, gathered in one place.
///
/// The decision is a pure function of this, so a test drives every branch
/// through `var` without setting a process environment variable, which no test
/// in this binary can do without racing the others.
struct Surroundings<'a> {
    stdout_is_terminal: bool,
    columns: Option<usize>,
    windows: bool,
    utf8_console: bool,
    var: &'a dyn Fn(&str) -> Option<String>,
}

impl Surroundings<'_> {
    /// The variable's value, empty included.
    fn raw(&self, name: &str) -> Option<String> {
        (self.var)(name)
    }

    /// The variable's value, with an empty value read as unset.
    fn set(&self, name: &str) -> Option<String> {
        self.raw(name).filter(|value| !value.is_empty())
    }
}

/// How to draw the logo here, or `None` when it should not be drawn.
fn plan(surroundings: &Surroundings<'_>, human_mode: bool) -> Option<Style> {
    if !human_mode || !surroundings.stdout_is_terminal {
        return None;
    }
    // A CI log is read after the fact, where eight rows of art are noise.
    // `CI=false` is how some runners say they are not one, so a falsy value
    // does not count.
    if surroundings
        .set("CI")
        .is_some_and(|value| !is_false(&value))
    {
        return None;
    }
    if surroundings
        .set("KIN_NO_BANNER")
        .is_some_and(|value| is_true(&value))
    {
        return None;
    }
    if surroundings.columns.is_some_and(|columns| columns < WIDTH) {
        return None;
    }
    let term = surroundings.raw("TERM");
    let windows_terminal = surroundings.set("WT_SESSION").is_some();
    let colour = crate::output_style::wanted(
        surroundings.stdout_is_terminal,
        surroundings.raw("NO_COLOR").is_some(),
        term.as_deref(),
    );
    let paint = crate::mark::paint_for(
        colour,
        surroundings.set("COLORTERM").as_deref(),
        term.as_deref(),
        windows_terminal,
    );
    let locale = [
        surroundings.raw("LC_ALL"),
        surroundings.raw("LC_CTYPE"),
        surroundings.raw("LANG"),
    ];
    let glyphs = glyphs_for(
        &locale,
        surroundings.windows,
        windows_terminal,
        surroundings.utf8_console,
    );
    Some(Style { glyphs, paint })
}

/// Whether this terminal reliably reads the half blocks.
///
/// A locale variable that is set decides, in POSIX precedence, through
/// [`crate::mark::glyphs_for_locale`]. With none set, a Unix process is in the
/// C locale, which is ASCII. Windows sets none of them, and there Windows
/// Terminal and a console on the UTF-8 code page read the blocks, while the
/// legacy code pages print them as question marks.
///
/// Stricter than the small mark's rule, which reads an unset locale as UTF-8:
/// four glyphs that come out wrong cost little, and a logo of them costs the
/// first thing a new user sees.
fn glyphs_for(
    locale: &[Option<String>],
    windows: bool,
    windows_terminal: bool,
    utf8_console: bool,
) -> Glyphs {
    let any_locale = locale
        .iter()
        .any(|value| value.as_deref().is_some_and(|value| !value.is_empty()));
    if any_locale {
        return crate::mark::glyphs_for_locale(locale);
    }
    if windows && (windows_terminal || utf8_console) {
        Glyphs::Unicode
    } else {
        Glyphs::Ascii
    }
}

/// Whether this process's console writes UTF-8, the code page `chcp 65001`
/// selects.
#[cfg(windows)]
fn console_output_is_utf8() -> bool {
    const CP_UTF8: u32 = 65001;
    // SAFETY: `GetConsoleOutputCP` takes no arguments and only reads the
    // calling process's console state. It returns 0 when there is no console.
    unsafe { windows_sys::Win32::System::Console::GetConsoleOutputCP() == CP_UTF8 }
}

#[cfg(not(windows))]
fn console_output_is_utf8() -> bool {
    false
}

/// `1`, `true`, `yes` or `on`, the environment registry's truthy values.
fn is_true(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// `0`, `false`, `no` or `off`, the environment registry's falsy values.
fn is_false(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Which part of the logo a glyph belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Piece {
    Arm,
    Leg,
    Wordmark,
}

fn pixel_piece(pixel: u8) -> Option<Piece> {
    match pixel {
        b'A' => Some(Piece::Arm),
        b'L' => Some(Piece::Leg),
        b'W' => Some(Piece::Wordmark),
        _ => None,
    }
}

/// One terminal cell: its glyph, and for an inked cell the piece and the
/// pixel-space point its colour is sampled at.
#[derive(Clone, Copy, Debug)]
struct Cell {
    glyph: char,
    ink: Option<(Piece, f32, f32)>,
}

/// One row of the half-block logo, built from the two pixel rows it carries.
///
/// A half block takes its colour at the centre of the pixel it draws, and a
/// full block at the centre of the cell.
fn unicode_row(row: usize) -> Vec<Cell> {
    let top = PIXELS[2 * row].as_bytes();
    let bottom = PIXELS[2 * row + 1].as_bytes();
    let y = (2 * row) as f32;
    top.iter()
        .zip(bottom)
        .enumerate()
        .map(|(column, (&upper, &lower))| {
            let x = column as f32 + 0.5;
            let (glyph, ink) = match (pixel_piece(upper), pixel_piece(lower)) {
                (Some(piece), Some(_)) => ('\u{2588}', Some((piece, x, y + 1.0))),
                (Some(piece), None) => ('\u{2580}', Some((piece, x, y + 0.5))),
                (None, Some(piece)) => ('\u{2584}', Some((piece, x, y + 1.5))),
                (None, None) => (' ', None),
            };
            Cell { glyph, ink }
        })
        .collect()
}

/// One row of the ASCII logo.
fn ascii_row(row: usize) -> Vec<Cell> {
    let y = (2 * row) as f32 + 1.0;
    ASCII_ROWS[row]
        .chars()
        .enumerate()
        .map(|(column, glyph)| {
            let piece = match glyph {
                ' ' => None,
                _ if column >= WORDMARK_COLUMN => Some(Piece::Wordmark),
                '/' => Some(Piece::Arm),
                '\\' => Some(Piece::Leg),
                _ => Some(Piece::Wordmark),
            };
            Cell {
                glyph,
                ink: piece.map(|piece| (piece, column as f32 + 0.5, y)),
            }
        })
        .collect()
}

/// The logo's lines, without the blank lines around it.
fn render(style: Style) -> Vec<String> {
    (0..ROWS)
        .map(|row| {
            let cells = match style.glyphs {
                Glyphs::Unicode => unicode_row(row),
                Glyphs::Ascii => ascii_row(row),
            };
            let drawn = cells
                .iter()
                .rposition(|cell| cell.glyph != ' ')
                .map_or(0, |last| last + 1);
            let mut line = " ".repeat(MARGIN);
            line.push_str(&paint_cells(&cells[..drawn], style.paint));
            if row == BRAND_LINE_ROW {
                line.push_str(&" ".repeat(WORDMARK_COLUMN.saturating_sub(drawn)));
                match brand_line_escape(style.paint) {
                    Some(escape) => line.push_str(&format!("{escape}{BRAND_LINE}{RESET}")),
                    None => line.push_str(BRAND_LINE),
                }
            }
            line
        })
        .collect()
}

/// A row's glyphs with their colour escapes.
///
/// An escape is written only where the colour changes, and a reset only where
/// colour stops, so the 256- and 16-colour rows carry one escape per run
/// rather than one per cell. The wordmark is never painted: it takes the
/// terminal's own foreground, which is light on a dark theme and dark on a
/// light one, as the brand's two lockups are.
fn paint_cells(cells: &[Cell], paint: Paint) -> String {
    let mut out = String::new();
    let mut open: Option<String> = None;
    for cell in cells {
        let escape = cell
            .ink
            .and_then(|(piece, x, y)| ink_escape(paint, piece, x, y));
        if escape != open {
            match &escape {
                Some(escape) => out.push_str(escape),
                None => out.push_str(RESET),
            }
            open = escape;
        }
        out.push(cell.glyph);
    }
    if open.is_some() {
        out.push_str(RESET);
    }
    out
}

/// The escape that colours one inked cell, or `None` when it stays uncoloured.
fn ink_escape(paint: Paint, piece: Piece, x: f32, y: f32) -> Option<String> {
    let stops = &crate::mark::TRUECOLOR_STOPS;
    match (paint, piece) {
        (Paint::None, _) | (_, Piece::Wordmark) => None,
        (Paint::Truecolor, Piece::Arm) => Some(truecolor(mix(
            stops[0],
            stops[1],
            along(ARM_GRADIENT, x, y),
        ))),
        (Paint::Truecolor, Piece::Leg) => Some(truecolor(mix(
            stops[2],
            stops[3],
            along(LEG_GRADIENT, x, y),
        ))),
        (Paint::Indexed, Piece::Arm) => Some(format!("\u{1b}[38;5;{INDEXED_ARM}m")),
        (Paint::Indexed, Piece::Leg) => Some(format!("\u{1b}[38;5;{INDEXED_LEG}m")),
        (Paint::Basic, Piece::Arm) => Some(crate::mark::BASIC_ARM.to_string()),
        (Paint::Basic, Piece::Leg) => Some(crate::mark::BASIC_LEG.to_string()),
    }
}

fn brand_line_escape(paint: Paint) -> Option<&'static str> {
    match paint {
        Paint::Truecolor => Some(BRAND_LINE_TRUECOLOR),
        Paint::Indexed => Some(BRAND_LINE_INDEXED),
        Paint::Basic => Some(BRAND_LINE_BASIC),
        Paint::None => None,
    }
}

/// How far along a linear gradient a point sits, from 0 at its start to 1 at
/// its end, as SVG measures it: by projection onto the gradient's vector.
fn along(gradient: [(f32, f32); 2], x: f32, y: f32) -> f32 {
    let [(x0, y0), (x1, y1)] = gradient;
    let (dx, dy) = (x1 - x0, y1 - y0);
    (((x - x0) * dx + (y - y0) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0)
}

/// The colour `t` of the way from one stop to the other, in sRGB as SVG
/// interpolates by default.
fn mix(from: (u8, u8, u8), to: (u8, u8, u8), t: f32) -> (u8, u8, u8) {
    let channel = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * t).round() as u8;
    (
        channel(from.0, to.0),
        channel(from.1, to.1),
        channel(from.2, to.2),
    )
}

fn truecolor((r, g, b): (u8, u8, u8)) -> String {
    format!("\u{1b}[38;2;{r};{g};{b}m")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ALL_STYLES: [Style; 8] = [
        Style {
            glyphs: Glyphs::Unicode,
            paint: Paint::Truecolor,
        },
        Style {
            glyphs: Glyphs::Unicode,
            paint: Paint::Indexed,
        },
        Style {
            glyphs: Glyphs::Unicode,
            paint: Paint::Basic,
        },
        Style {
            glyphs: Glyphs::Unicode,
            paint: Paint::None,
        },
        Style {
            glyphs: Glyphs::Ascii,
            paint: Paint::Truecolor,
        },
        Style {
            glyphs: Glyphs::Ascii,
            paint: Paint::Indexed,
        },
        Style {
            glyphs: Glyphs::Ascii,
            paint: Paint::Basic,
        },
        Style {
            glyphs: Glyphs::Ascii,
            paint: Paint::None,
        },
    ];

    /// An ordinary truecolor UTF-8 terminal on a Unix machine, with the
    /// variables a test names set on top. A name written `-NAME` unsets it.
    fn decide(vars: &[(&str, &str)]) -> Option<Style> {
        decide_with(true, Some(120), false, false, vars)
    }

    fn decide_with(
        stdout_is_terminal: bool,
        columns: Option<usize>,
        windows: bool,
        utf8_console: bool,
        vars: &[(&str, &str)],
    ) -> Option<Style> {
        let mut env: HashMap<String, String> = [
            ("TERM", "xterm-256color"),
            ("COLORTERM", "truecolor"),
            ("LANG", "en_US.UTF-8"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
        for (name, value) in vars {
            match name.strip_prefix('-') {
                Some(unset) => {
                    env.remove(unset);
                }
                None => {
                    env.insert((*name).to_string(), (*value).to_string());
                }
            }
        }
        let read = |name: &str| env.get(name).cloned();
        plan(
            &Surroundings {
                stdout_is_terminal,
                columns,
                windows,
                utf8_console,
                var: &read,
            },
            true,
        )
    }

    /// The logo as it prints with colour off, which is also every other
    /// rendering once its escapes are stripped.
    ///
    /// Written out rather than rebuilt from the pixel rows, so a change to the
    /// shape shows up here as the drawing a reviewer will see.
    #[test]
    fn the_unicode_logo_is_the_mark_beside_the_wordmark() {
        let drawn = render(Style {
            glyphs: Glyphs::Unicode,
            paint: Paint::None,
        });
        assert_eq!(
            drawn,
            vec![
                "    ▄███████",
                "  ▄███████▀         ▄    ▄   ▄    ▄     ▄",
                "  ██████▀           █  ▄▀    █    █▀▄   █",
                "  ████▀             █▄▀      █    █ ▀▄  █",
                "  ██▀ ▄▄            █ ▀▄     █    █   █ █",
                "    ▄████▄          █   ▀▄   █    █    ▀█",
                "   ▀███████▄",
                "     ▀███████▄      A new foundation for code.",
            ]
        );
    }

    #[test]
    fn the_ascii_logo_hatches_the_arm_and_the_leg() {
        let drawn = render(Style {
            glyphs: Glyphs::Ascii,
            paint: Paint::None,
        });
        assert_eq!(
            drawn,
            vec![
                r"     ///////",
                r"    ////////        |  /   |   |\    |",
                r"   ///////          | /    |   | \   |",
                r"   /////            |<     |   |  \  |",
                r"   ///              | \    |   |   \ |",
                r"      \\\\          |  \   |   |    \|",
                r"     \\\\\\\",
                r"       \\\\\\\\     A new foundation for code.",
            ]
        );
        for line in &drawn {
            assert!(line.is_ascii(), "{line:?} is not ASCII");
        }
    }

    /// Every rendering fits the width budget and the eight-row budget.
    #[test]
    fn every_line_fits_the_width_budget() {
        for style in ALL_STYLES {
            let drawn = render(style);
            assert!(drawn.len() <= 8, "{style:?} draws {} rows", drawn.len());
            for line in &drawn {
                let width = console::measure_text_width(line);
                assert!(
                    width <= WIDTH,
                    "{style:?} draws {line:?} {width} columns wide, past {WIDTH}"
                );
            }
        }
        let widest = render(ALL_STYLES[0])
            .iter()
            .map(|line| console::measure_text_width(line))
            .max();
        assert_eq!(widest, Some(WIDTH), "WIDTH no longer names the widest line");
    }

    /// Colour is escapes and nothing else.
    #[test]
    fn stripping_the_escapes_yields_the_plain_logo() {
        for style in ALL_STYLES {
            let plain = render(Style {
                glyphs: style.glyphs,
                paint: Paint::None,
            });
            let stripped: Vec<String> = render(style)
                .iter()
                .map(|line| console::strip_ansi_codes(line).into_owned())
                .collect();
            assert_eq!(stripped, plain, "{style:?} changed more than the colour");
        }
    }

    /// No colour means no escape bytes at all, whatever the glyphs.
    #[test]
    fn no_colour_writes_no_escapes() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            for line in render(Style {
                glyphs,
                paint: Paint::None,
            }) {
                assert!(!line.contains('\u{1b}'), "{line:?} carries an escape");
            }
        }
    }

    /// Every painted run is closed, so no colour leaks past the logo, and no
    /// line pads past its last glyph.
    #[test]
    fn every_painted_run_is_reset() {
        for style in ALL_STYLES {
            for line in render(style) {
                if let Some(last) = line.rfind('\u{1b}') {
                    assert!(
                        line[last..].starts_with(RESET),
                        "{style:?} leaves {line:?} painting"
                    );
                }
                assert!(!line.ends_with(' '), "{line:?} pads past its last glyph");
            }
        }
    }

    /// Truecolor paints the brand's stops at the ends of each gradient.
    #[test]
    fn truecolor_reaches_the_brand_stops() {
        let arm_start = ink_escape(Paint::Truecolor, Piece::Arm, 11.21, 0.0);
        let arm_end = ink_escape(Paint::Truecolor, Piece::Arm, 0.0, 11.21);
        let leg_start = ink_escape(Paint::Truecolor, Piece::Leg, 2.82, 10.08);
        let leg_end = ink_escape(Paint::Truecolor, Piece::Leg, 12.98, 16.0);
        assert_eq!(arm_start.as_deref(), Some("\u{1b}[38;2;174;90;255m"));
        assert_eq!(arm_end.as_deref(), Some("\u{1b}[38;2;108;72;250m"));
        assert_eq!(leg_start.as_deref(), Some("\u{1b}[38;2;91;85;253m"));
        assert_eq!(leg_end.as_deref(), Some("\u{1b}[38;2;59;116;251m"));
        assert_eq!(
            ink_escape(Paint::Truecolor, Piece::Wordmark, 20.0, 5.0),
            None
        );
    }

    /// Each lower colour depth keeps the arm and the leg apart.
    #[test]
    fn every_colour_depth_tells_the_arm_from_the_leg() {
        for paint in [Paint::Truecolor, Paint::Indexed, Paint::Basic] {
            let arm = ink_escape(paint, Piece::Arm, 3.0, 3.0);
            let leg = ink_escape(paint, Piece::Leg, 6.0, 13.0);
            assert!(
                arm.is_some() && leg.is_some(),
                "{paint:?} left a piece bare"
            );
            assert_ne!(arm, leg, "{paint:?} paints the arm and the leg alike");
        }
    }

    /// No terminal cell carries a pixel of the arm over a pixel of the leg.
    ///
    /// Such a cell would have to be one glyph in one colour, and the split
    /// would close there.
    #[test]
    fn no_cell_holds_both_pieces() {
        for row in 0..ROWS {
            let top = PIXELS[2 * row].as_bytes();
            let bottom = PIXELS[2 * row + 1].as_bytes();
            for column in 0..top.len() {
                if let (Some(upper), Some(lower)) =
                    (pixel_piece(top[column]), pixel_piece(bottom[column]))
                {
                    assert_eq!(upper, lower, "row {row}, column {column} mixes pieces");
                }
            }
        }
    }

    /// The split is a channel: no arm pixel touches a leg pixel, even at a
    /// corner.
    ///
    /// Corner contact is what a one-pixel diagonal gap degrades to when one
    /// pixel moves, and at terminal size it reads as the two bands joining.
    #[test]
    fn the_arm_and_the_leg_never_touch() {
        let at = |row: isize, column: isize| -> Option<Piece> {
            let row = usize::try_from(row).ok()?;
            let column = usize::try_from(column).ok()?;
            PIXELS
                .get(row)
                .and_then(|line| line.as_bytes().get(column))
                .and_then(|&pixel| pixel_piece(pixel))
        };
        for (row, line) in PIXELS.iter().enumerate() {
            for (column, &pixel) in line.as_bytes().iter().enumerate() {
                if pixel_piece(pixel) != Some(Piece::Arm) {
                    continue;
                }
                for dy in -1..=1 {
                    for dx in -1..=1 {
                        assert_ne!(
                            at(row as isize + dy, column as isize + dx),
                            Some(Piece::Leg),
                            "the arm at row {row}, column {column} touches the leg"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn every_pixel_row_is_the_same_width() {
        for line in PIXELS {
            assert_eq!(line.len(), PIXELS[0].len(), "{line:?}");
        }
    }

    /// An ordinary terminal gets the full logo.
    #[test]
    fn a_truecolor_utf8_terminal_gets_the_gradient_blocks() {
        assert_eq!(
            decide(&[]),
            Some(Style {
                glyphs: Glyphs::Unicode,
                paint: Paint::Truecolor,
            })
        );
    }

    /// A pipe or a file is being read by something, and gets nothing.
    #[test]
    fn a_pipe_gets_nothing() {
        assert_eq!(decide_with(false, None, false, false, &[]), None);
    }

    /// `--json`, and any other output a program reads, gets nothing.
    #[test]
    fn machine_output_gets_nothing() {
        let read = |_: &str| -> Option<String> { None };
        let surroundings = Surroundings {
            stdout_is_terminal: true,
            columns: Some(120),
            windows: false,
            utf8_console: false,
            var: &read,
        };
        assert_eq!(plan(&surroundings, false), None);
        assert!(!print_once(false), "a machine-mode caller printed the logo");
    }

    #[test]
    fn ci_gets_nothing() {
        for value in ["true", "1", "yes", "github"] {
            assert_eq!(decide(&[("CI", value)]), None, "CI={value}");
        }
        for value in ["false", "0", "no", "off", ""] {
            assert!(decide(&[("CI", value)]).is_some(), "CI={value:?}");
        }
    }

    #[test]
    fn kin_no_banner_opts_out() {
        for value in ["1", "true", "TRUE", "yes", "on", " On "] {
            assert_eq!(
                decide(&[("KIN_NO_BANNER", value)]),
                None,
                "KIN_NO_BANNER={value:?}"
            );
        }
        for value in ["0", "false", "no", "off", ""] {
            assert!(
                decide(&[("KIN_NO_BANNER", value)]).is_some(),
                "KIN_NO_BANNER={value:?}"
            );
        }
    }

    /// `NO_COLOR` is about colour, so the logo stays and only the escapes go.
    #[test]
    fn no_color_keeps_the_logo_without_colour() {
        for value in ["1", ""] {
            assert_eq!(
                decide(&[("NO_COLOR", value)]),
                Some(Style {
                    glyphs: Glyphs::Unicode,
                    paint: Paint::None,
                }),
                "NO_COLOR={value:?}"
            );
        }
        assert_eq!(
            decide(&[("TERM", "dumb"), ("-COLORTERM", "")]),
            Some(Style {
                glyphs: Glyphs::Unicode,
                paint: Paint::None,
            })
        );
    }

    #[test]
    fn colour_depth_follows_the_terminal() {
        let paint = |vars: &[(&str, &str)]| decide(vars).map(|style| style.paint);
        assert_eq!(paint(&[]), Some(Paint::Truecolor));
        assert_eq!(
            paint(&[("-COLORTERM", ""), ("TERM", "xterm-256color")]),
            Some(Paint::Indexed)
        );
        assert_eq!(
            paint(&[("-COLORTERM", ""), ("TERM", "xterm")]),
            Some(Paint::Basic)
        );
        assert_eq!(
            paint(&[("-COLORTERM", ""), ("-TERM", ""), ("WT_SESSION", "1")]),
            Some(Paint::Truecolor)
        );
    }

    /// A terminal too narrow for the logo gets none; an unknown width is
    /// given the benefit of the doubt.
    #[test]
    fn a_narrow_terminal_gets_nothing() {
        assert_eq!(decide_with(true, Some(WIDTH - 1), false, false, &[]), None);
        assert!(decide_with(true, Some(WIDTH), false, false, &[]).is_some());
        assert!(decide_with(true, None, false, false, &[]).is_some());
    }

    #[test]
    fn a_utf8_locale_gets_blocks_and_any_other_gets_ascii() {
        let glyphs = |vars: &[(&str, &str)]| decide(vars).map(|style| style.glyphs);
        assert_eq!(glyphs(&[("LANG", "en_US.UTF-8")]), Some(Glyphs::Unicode));
        assert_eq!(glyphs(&[("LANG", "C")]), Some(Glyphs::Ascii));
        assert_eq!(
            glyphs(&[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")]),
            Some(Glyphs::Ascii),
            "LC_ALL outranks LANG"
        );
        assert_eq!(
            glyphs(&[("LC_CTYPE", "C.UTF-8"), ("LANG", "C")]),
            Some(Glyphs::Unicode),
            "LC_CTYPE outranks LANG"
        );
        assert_eq!(
            glyphs(&[("-LANG", "")]),
            Some(Glyphs::Ascii),
            "a Unix process with no locale is in the C locale"
        );
    }

    /// Windows sets no locale, so the console itself decides.
    #[test]
    fn windows_draws_blocks_only_where_the_console_reads_utf8() {
        let glyphs = |utf8_console: bool, vars: &[(&str, &str)]| {
            decide_with(true, Some(120), true, utf8_console, vars).map(|style| style.glyphs)
        };
        assert_eq!(
            glyphs(false, &[("-LANG", ""), ("WT_SESSION", "{guid}")]),
            Some(Glyphs::Unicode),
            "Windows Terminal"
        );
        assert_eq!(
            glyphs(true, &[("-LANG", "")]),
            Some(Glyphs::Unicode),
            "a console on code page 65001"
        );
        assert_eq!(
            glyphs(false, &[("-LANG", "")]),
            Some(Glyphs::Ascii),
            "a console on a legacy code page"
        );
        assert_eq!(
            glyphs(false, &[("LANG", "en_US.UTF-8")]),
            Some(Glyphs::Unicode),
            "a shell that sets a UTF-8 locale, such as Git Bash"
        );
    }

    /// The first moment takes the slot and every later one finds it taken.
    #[test]
    fn the_logo_prints_once_per_process() {
        let flag = AtomicBool::new(false);
        assert!(claim(&flag));
        assert!(!claim(&flag));
        assert!(!claim(&flag));
    }

    /// The frame is one blank line above and one below.
    #[test]
    fn the_logo_is_framed_by_blank_lines() {
        let block = framed(&render(ALL_STYLES[3]));
        assert!(block.starts_with("\n    ▄"), "{block:?}");
        assert!(block.ends_with("code.\n\n"), "{block:?}");
        assert_eq!(block.lines().count(), ROWS + 2);
    }
}
