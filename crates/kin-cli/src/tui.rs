// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The live frame `kin setup` asks its questions in.
//!
//! A bounded block of lines drawn under whatever the terminal already shows,
//! redrawn in place on every key: a compact header with the step, the answers
//! so far, one focused question with its consent text above its choices, and a
//! line naming the keys. Nothing uses the alternate screen, so everything the
//! run prints after the frame stays in the scrollback.
//!
//! Every line is cut to the terminal's width less one column, so no line
//! wraps and the next redraw knows exactly how many rows to take back. A
//! terminal narrowed between two draws reflows the old lines, and the rows that
//! reflow made are counted too, so a resize leaves no debris.
//!
//! A terminal that cannot move its cursor (`TERM=dumb`) gets the same
//! questions one after another as numbered lines read from stdin. Nothing
//! redraws, which is also what a screen reader reads best.

use std::io::{self, BufRead};

use console::{Key, Term};

use crate::screen::{self, Status, Style, INDENT};

/// One choice under a question.
#[derive(Debug, Clone)]
pub struct Choice {
    /// What the option says.
    pub label: String,
    /// The answer it gives.
    pub value: bool,
    /// What the answered row says once it is chosen.
    pub answered: String,
}

/// One question.
#[derive(Debug, Clone)]
pub struct Question {
    /// The answered row's label.
    pub label: &'static str,
    /// The question itself.
    pub title: String,
    /// What saying yes does, shown before the choice. Full contrast, because
    /// it is what a person consents to.
    pub consent: Vec<String>,
    /// Secondary detail, such as the names it applies to.
    pub note: Option<String>,
    pub choices: Vec<Choice>,
    /// The choice Enter takes.
    pub default: usize,
}

impl Question {
    /// A yes/no question, yes first.
    pub fn yes_no(
        label: &'static str,
        title: impl Into<String>,
        yes: (&str, &str),
        no: (&str, &str),
        default_yes: bool,
    ) -> Self {
        Self {
            label,
            title: title.into(),
            consent: Vec::new(),
            note: None,
            choices: vec![
                Choice {
                    label: yes.0.to_string(),
                    value: true,
                    answered: yes.1.to_string(),
                },
                Choice {
                    label: no.0.to_string(),
                    value: false,
                    answered: no.1.to_string(),
                },
            ],
            default: if default_yes { 0 } else { 1 },
        }
    }

    /// Add what saying yes does.
    pub fn consent(mut self, text: impl Into<String>) -> Self {
        self.consent.push(text.into());
        self
    }

    /// Add a secondary note.
    pub fn note(mut self, text: impl Into<String>) -> Self {
        self.note = Some(text.into());
        self
    }
}

/// How the questions end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The index of the choice taken for each question, in order.
    Answered(Vec<usize>),
    /// The person pressed Ctrl-C.
    Cancelled,
}

/// Whether this terminal can redraw a frame in place.
pub fn can_redraw() -> bool {
    can_redraw_for(std::env::var("TERM").ok().as_deref())
}

/// The rule behind [`can_redraw`], for a given `TERM`.
fn can_redraw_for(term: Option<&str>) -> bool {
    term != Some("dumb")
}

/// Ask every question, in a live frame where the terminal can redraw one and
/// as numbered lines where it cannot.
pub fn ask_all(style: Style, questions: &[Question]) -> Outcome {
    if questions.is_empty() {
        return Outcome::Answered(Vec::new());
    }
    if can_redraw() {
        ask_live(style, questions)
    } else {
        ask_linear(questions)
    }
}

/// The bytes that give a terminal its cursor back.
const SHOW_CURSOR: &str = "\u{1b}[?25h";

/// Restore the cursor, then die of the signal as the process would have.
///
/// Only async-signal-safe calls: a write of a constant, then the default
/// action re-raised. It covers a SIGINT that arrives outside a key read, such
/// as one sent from another process, while the frame has the cursor hidden.
#[cfg(unix)]
extern "C" fn restore_cursor_and_die(signal: libc::c_int) {
    const SHOW: &[u8] = b"\x1b[?25h\r\n";
    // SAFETY: `write` and `signal`/`raise` are async-signal-safe, and the
    // buffer is a constant that outlives the call.
    unsafe {
        libc::write(1, SHOW.as_ptr().cast(), SHOW.len());
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

/// How many rows the first question's frame takes at `width` columns, so a
/// caller can leave room for it under what it prints first.
pub fn first_frame_rows(questions: &[Question], width: usize) -> usize {
    if questions.is_empty() {
        return 0;
    }
    frame_lines(Style::plain(), questions, &[], questions[0].default, width).len()
}

/// The frame, drawn and redrawn in place.
struct Frame {
    term: Term,
    /// The visible width of each line last drawn.
    drawn: Vec<usize>,
    /// The width they were drawn at.
    width: usize,
    /// The SIGINT disposition to put back when the frame ends.
    #[cfg(unix)]
    previous_sigint: libc::sighandler_t,
}

impl Frame {
    fn new() -> Self {
        let term = Term::stdout();
        let _ = term.hide_cursor();
        Self {
            term,
            drawn: Vec::new(),
            width: screen::terminal_width(),
            // SAFETY: installs a handler that only makes async-signal-safe
            // calls; the previous one is restored when the frame ends.
            #[cfg(unix)]
            previous_sigint: unsafe {
                libc::signal(
                    libc::SIGINT,
                    restore_cursor_and_die as extern "C" fn(libc::c_int) as libc::sighandler_t,
                )
            },
        }
    }

    /// Rows the last draw takes up at the current width.
    fn rows_back(&self, width: usize) -> usize {
        self.drawn
            .iter()
            .map(|&visible| {
                if width < self.width && visible > 0 {
                    visible.div_ceil(width.max(1))
                } else {
                    1
                }
            })
            .sum()
    }

    fn erase(&mut self, width: usize) -> String {
        let rows = self.rows_back(width);
        self.drawn.clear();
        if rows == 0 {
            String::new()
        } else {
            format!("\r\u{1b}[{rows}A\u{1b}[J")
        }
    }

    fn draw(&mut self, lines: &[String]) {
        let width = screen::terminal_width();
        let mut out = self.erase(width);
        let cut = width.saturating_sub(1).max(10);
        let mut drawn = Vec::with_capacity(lines.len());
        for line in lines {
            let line = console::truncate_str(line, cut, "");
            drawn.push(console::measure_text_width(&line));
            out.push_str(&line);
            out.push('\n');
        }
        let _ = self.term.write_str(&out);
        let _ = self.term.flush();
        self.drawn = drawn;
        self.width = width;
    }

    fn clear(&mut self) {
        let width = screen::terminal_width();
        let out = self.erase(width);
        let _ = self.term.write_str(&out);
        let _ = self.term.flush();
    }

    /// Take the frame off the screen and give the cursor back, in one write,
    /// for a person who pressed Ctrl-C.
    fn cancel(&mut self) {
        let width = screen::terminal_width();
        let out = cancel_bytes(self.erase(width));
        let _ = self.term.write_str(&out);
        let _ = self.term.flush();
    }
}

/// What a cancelled frame writes: its erase, then the cursor shown.
fn cancel_bytes(erase: String) -> String {
    format!("{erase}{SHOW_CURSOR}")
}

impl Drop for Frame {
    fn drop(&mut self) {
        let _ = self.term.show_cursor();
        // SAFETY: puts back the disposition `new` replaced.
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGINT, self.previous_sigint);
        }
    }
}

fn ask_live(style: Style, questions: &[Question]) -> Outcome {
    let term = Term::stdout();
    let mut frame = Frame::new();
    let mut answers: Vec<usize> = Vec::new();
    let mut selected = questions[0].default;
    loop {
        let current = answers.len();
        let question = &questions[current];
        frame.draw(&frame_lines(
            style,
            questions,
            &answers,
            selected,
            screen::terminal_width(),
        ));
        let count = question.choices.len();
        // `read_key_raw`, so Ctrl-C arrives here as a key rather than as a
        // SIGINT that ends the process with the cursor still hidden.
        let key = match term.read_key_raw() {
            Ok(key) => key,
            Err(_) => {
                frame.clear();
                return Outcome::Cancelled;
            }
        };
        let confirm = match key {
            Key::ArrowUp | Key::BackTab | Key::Char('k') => {
                selected = (selected + count - 1) % count;
                false
            }
            Key::ArrowDown | Key::Tab | Key::Char('j') => {
                selected = (selected + 1) % count;
                false
            }
            Key::Char('y') | Key::Char('Y') => {
                match question.choices.iter().position(|choice| choice.value) {
                    Some(index) => {
                        selected = index;
                        true
                    }
                    None => false,
                }
            }
            Key::Char('n') | Key::Char('N') => {
                match question.choices.iter().position(|choice| !choice.value) {
                    Some(index) => {
                        selected = index;
                        true
                    }
                    None => false,
                }
            }
            Key::Enter | Key::Char(' ') => true,
            Key::Escape | Key::Backspace | Key::ArrowLeft | Key::Char('h') => {
                if let Some(previous) = answers.pop() {
                    selected = previous;
                }
                false
            }
            Key::CtrlC => {
                frame.cancel();
                return Outcome::Cancelled;
            }
            _ => false,
        };
        if confirm {
            answers.push(selected);
            if answers.len() == questions.len() {
                frame.clear();
                return Outcome::Answered(answers);
            }
            selected = questions[answers.len()].default;
        }
    }
}

/// The frame's lines for one moment: the header, the answers so far, the
/// focused question and the keys.
fn frame_lines(
    style: Style,
    questions: &[Question],
    answers: &[usize],
    selected: usize,
    width: usize,
) -> Vec<String> {
    let edge = screen::right_edge_for(width);
    let text_width = edge.saturating_sub(INDENT.len());
    let current = answers.len();
    let question = &questions[current];
    let mut lines = Vec::new();

    let title = format!("{} {}", style.lilac("◆"), style.bold("Kin setup"));
    let step = format!("{} of {}", current + 1, questions.len());
    let pad = edge
        .saturating_sub(INDENT.len() + console::measure_text_width(&title) + step.len())
        .max(2);
    lines.push(format!(
        "{INDENT}{title}{}{}",
        " ".repeat(pad),
        style.faint(&step)
    ));
    lines.push(format!(
        "{INDENT}{}",
        style.faint(&"─".repeat(edge.saturating_sub(INDENT.len())))
    ));
    for (index, &answer) in answers.iter().enumerate() {
        let asked = &questions[index];
        let chosen = &asked.choices[answer];
        lines.push(screen::row_to(
            style,
            INDENT,
            if chosen.value {
                Status::Chosen
            } else {
                Status::Off
            },
            asked.label,
            &asked.choices[answer].answered,
            None,
            edge,
        ));
    }
    lines.push(String::new());
    for line in screen::wrap(&question.title, text_width) {
        lines.push(format!("{INDENT}{}", style.bold(&line)));
    }
    for paragraph in &question.consent {
        for line in screen::wrap(paragraph, text_width) {
            lines.push(format!("{INDENT}{line}"));
        }
    }
    if let Some(note) = &question.note {
        for line in screen::wrap(note, text_width) {
            lines.push(format!("{INDENT}{}", style.faint(&line)));
        }
    }
    lines.push(String::new());
    for (index, choice) in question.choices.iter().enumerate() {
        if index == selected {
            lines.push(format!(
                "{INDENT}{} {}",
                style.marker(),
                style.bold(&choice.label)
            ));
        } else {
            lines.push(format!("{INDENT}  {}", choice.label));
        }
    }
    lines.push(String::new());
    let back = if current > 0 { " · esc back" } else { "" };
    let keys = if width >= 64 {
        format!("↑↓ choose · enter confirm{back} · ctrl-c quit")
    } else {
        format!(
            "↑↓ · enter{} · ctrl-c",
            if current > 0 { " · esc" } else { "" }
        )
    };
    lines.push(format!("{INDENT}{}", style.faint(&keys)));
    lines
}

/// The questions as numbered lines, for a terminal that cannot redraw.
fn ask_linear(questions: &[Question]) -> Outcome {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stdout();
    ask_linear_from(questions, &mut input, &mut output)
}

/// [`ask_linear`] over any input and output, so a test can answer it.
///
/// End of input or a read error cancels. Taking the default there would let
/// Ctrl-D, or a closed pipe, accept every default-yes install and config change
/// that nobody answered.
fn ask_linear_from(
    questions: &[Question],
    input: &mut dyn BufRead,
    output: &mut dyn io::Write,
) -> Outcome {
    let mut answers = Vec::with_capacity(questions.len());
    for (step, question) in questions.iter().enumerate() {
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "{INDENT}Question {} of {}: {}",
            step + 1,
            questions.len(),
            question.title
        );
        for paragraph in question.consent.iter().chain(question.note.as_ref()) {
            for line in screen::wrap(paragraph, 76) {
                let _ = writeln!(output, "{INDENT}{line}");
            }
        }
        for (index, choice) in question.choices.iter().enumerate() {
            let default = if index == question.default {
                " (default)"
            } else {
                ""
            };
            let _ = writeln!(output, "{INDENT}  {}. {}{default}", index + 1, choice.label);
        }
        let answer = loop {
            let _ = write!(
                output,
                "{INDENT}Choose 1 to {}, or press Enter for {}: ",
                question.choices.len(),
                question.default + 1
            );
            let _ = output.flush();
            let mut line = String::new();
            match input.read_line(&mut line) {
                Ok(0) | Err(_) => return Outcome::Cancelled,
                Ok(_) => {}
            }
            let line = line.trim();
            if line.is_empty() {
                break question.default;
            }
            if let Some(index) = line
                .parse::<usize>()
                .ok()
                .filter(|index| (1..=question.choices.len()).contains(index))
            {
                break index - 1;
            }
            let wanted = match line.to_ascii_lowercase().as_str() {
                "y" | "yes" => Some(true),
                "n" | "no" => Some(false),
                _ => None,
            };
            if let Some(index) =
                wanted.and_then(|value| question.choices.iter().position(|c| c.value == value))
            {
                break index;
            }
        };
        answers.push(answer);
    }
    let _ = writeln!(output);
    Outcome::Answered(answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn questions() -> Vec<Question> {
        vec![
            Question::yes_no(
                "AI clients",
                "Connect Kin to your AI clients?",
                ("Yes, connect them", "will connect all 4"),
                ("No, not now", "not now"),
                true,
            )
            .consent(
                "Kin adds its MCP server to each client's config and a short note to \
                 ~/.claude/CLAUDE.md.",
            )
            .note("Claude Code, Cursor, Gemini CLI and LM Studio"),
            Question::yes_no(
                "PATH",
                "Put kin on your PATH?",
                ("Yes, add it to ~/.zshenv", "will add to ~/.zshenv"),
                ("No, leave my shell alone", "left alone"),
                true,
            )
            .consent("One line in ~/.zshenv, so a new terminal finds kin."),
        ]
    }

    /// A frame fits a default 80x24 terminal, and at 60 columns no line
    /// reaches the edge, so nothing wraps and a redraw leaves no debris.
    #[test]
    fn a_frame_fits_the_terminal_it_is_drawn_for() {
        for width in [60, 80, 120] {
            let lines = frame_lines(Style::plain(), &questions(), &[0], 0, width);
            assert!(lines.len() <= 24, "{width}: {} lines", lines.len());
            for line in &lines {
                assert!(
                    console::measure_text_width(line) < width,
                    "{width}: {line:?} reaches the edge"
                );
            }
        }
    }

    /// Consent comes before the choice, the choice under focus is marked, and
    /// the answer already given stays on screen.
    #[test]
    fn consent_comes_before_the_choice() {
        let lines = frame_lines(Style::plain(), &questions(), &[0], 1, 80);
        let consent = lines
            .iter()
            .position(|line| line.contains("One line in ~/.zshenv"))
            .expect("consent shown");
        let choice = lines
            .iter()
            .position(|line| line.contains("No, leave my shell alone"))
            .expect("choice shown");
        assert!(consent < choice, "{lines:#?}");
        assert!(lines[choice].contains('›'), "the focused choice is marked");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("AI clients") && line.contains('•')),
            "the first answer stays: {lines:#?}"
        );
        assert!(lines[0].contains("2 of 2"), "{}", lines[0]);
        assert!(lines.last().unwrap().contains("esc back"));
    }

    /// The first question has nothing to go back to, and a narrow terminal
    /// gets the short key line.
    #[test]
    fn the_key_line_says_only_what_works() {
        let first = frame_lines(Style::plain(), &questions(), &[], 0, 80);
        assert!(!first.last().unwrap().contains("esc"));
        let narrow = frame_lines(Style::plain(), &questions(), &[0], 0, 60);
        assert!(narrow.last().unwrap().contains("esc"));
        assert!(!narrow.last().unwrap().contains("confirm"));
    }

    /// A frame drawn at 80 columns and taken back at 40 counts the rows the
    /// terminal's reflow made of its longer lines.
    #[test]
    fn a_narrowed_terminal_takes_back_the_reflowed_rows() {
        let frame = Frame {
            term: Term::stdout(),
            drawn: vec![70, 10, 0],
            width: 80,
            #[cfg(unix)]
            previous_sigint: libc::SIG_DFL,
        };
        assert_eq!(frame.rows_back(80), 3);
        assert_eq!(frame.rows_back(40), 2 + 1 + 1);
        std::mem::forget(frame);
    }

    /// Ctrl-C takes the frame off the screen and always gives the cursor
    /// back, in that order, so a cancelled setup never leaves the terminal
    /// without one.
    #[test]
    fn a_cancel_erases_the_frame_and_restores_the_cursor() {
        let mut frame = Frame {
            term: Term::stdout(),
            drawn: vec![20, 20, 20],
            width: 80,
            #[cfg(unix)]
            previous_sigint: libc::SIG_DFL,
        };
        let out = cancel_bytes(frame.erase(80));
        assert!(out.starts_with("\r\u{1b}[3A\u{1b}[J"), "{out:?}");
        assert!(out.ends_with(SHOW_CURSOR), "{out:?}");
        std::mem::forget(frame);
    }

    /// End of input cancels rather than taking the defaults, so Ctrl-D on a
    /// dumb terminal accepts nothing nobody answered.
    #[test]
    fn end_of_input_cancels_the_linear_questions() {
        let mut out = Vec::new();
        let mut eof = io::Cursor::new(Vec::<u8>::new());
        assert_eq!(
            ask_linear_from(&questions(), &mut eof, &mut out),
            Outcome::Cancelled
        );
        // Answering the first and then ending input still cancels.
        let mut partial = io::Cursor::new(b"1\n".to_vec());
        assert_eq!(
            ask_linear_from(&questions(), &mut partial, &mut out),
            Outcome::Cancelled
        );
    }

    /// Numbers, y or n, and Enter for the default all answer; anything else
    /// asks again. The consent text is printed before the choices.
    #[test]
    fn the_linear_questions_take_numbers_words_and_enter() {
        let mut out = Vec::new();
        let mut input = io::Cursor::new(b"maybe\n2\n\n".to_vec());
        assert_eq!(
            ask_linear_from(&questions(), &mut input, &mut out),
            Outcome::Answered(vec![1, 0])
        );
        let mut input = io::Cursor::new(b"n\nyes\n".to_vec());
        assert_eq!(
            ask_linear_from(&questions(), &mut input, &mut out),
            Outcome::Answered(vec![1, 0])
        );
        let printed = String::from_utf8(out).unwrap();
        let consent = printed.find("One line in ~/.zshenv").unwrap();
        let choice = printed.find("1. Yes, add it to ~/.zshenv").unwrap();
        assert!(consent < choice, "{printed}");
        assert!(
            !printed.contains('\u{1b}'),
            "no escapes on a dumb terminal: {printed}"
        );
    }

    #[test]
    fn only_a_dumb_terminal_gets_numbered_lines() {
        assert!(!can_redraw_for(Some("dumb")));
        assert!(can_redraw_for(Some("xterm-256color")));
        assert!(can_redraw_for(None));
    }
}
