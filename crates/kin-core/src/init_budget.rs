// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a conversion will hold, read before it starts holding it.
//!
//! A conversion's peak follows history depth multiplied by tree size, because
//! the import plan materializes one resolved tree per commit and keeps every
//! one of them live until proof 1 releases the plan's bodies five phases later.
//! `build_semantic_git_import_plan` derives that history under
//! `TreeRetention::Whole` precisely so the plan can carry all of them, and the
//! `commit_trees` field says in its own doc comment that it is the largest
//! whole-history structure a conversion holds.
//!
//! On a repository whose product of the two is larger than the machine, that
//! peak ends the run at phase 4 and says nothing at all. `SIGKILL` runs no
//! destructor and writes no message, so the operator sees four phase lines and
//! a shell that prints `Killed`. The post-mortem this crate already writes is
//! excellent and arrives one run too late, because it is read off disk by the
//! NEXT command; the run that dies is the run a first-time user has.
//!
//! So the ladder asks the cheap question first. Counting a repository's commits
//! and its tracked artifacts costs a rev-walk and one index read, both of which
//! finish before phase 2 would have started copying anything, and the two
//! numbers are the whole driver. When their product forecasts more than this
//! process can read as a ceiling, the conversion refuses in words instead of
//! dying in silence.
//!
//! # What the forecast is, and what it is not
//!
//! It is a floor, not a prediction. Each coefficient below is the LOWEST demand
//! per unit of work observed across measured conversions, and the forecast takes
//! the larger of the two terms rather than their sum, so a forecast that exceeds
//! the ceiling is a statement that the real demand exceeds it too. Nothing here
//! forecasts how long a conversion takes, and a forecast under the ceiling is
//! not a promise the conversion fits: a repository can be unusual in ways two
//! numbers do not capture, and the machine's free memory moves while the
//! conversion runs.
//!
//! That asymmetry is deliberate. A refusal that fires wrongly costs a user a
//! conversion that would have worked, and the only way back is an environment
//! variable. A refusal that fails to fire costs nothing that is not already
//! being paid today, because dying at phase 4 is the current behaviour.

use std::path::Path;

use crate::init_attempt::human_bytes;
use crate::memory_pressure;

/// Name an operator uses to tell a conversion what ceiling it really has.
///
/// Two audiences, one lever. A machine whose ceiling Kin reads wrongly, which
/// is a live defect where a container's probe can see the host's free memory
/// rather than its own cap, needs a way to say the true number. And an operator
/// who has judged the forecast wrong for their repository needs a way past the
/// refusal that does not mean editing the binary.
pub const INIT_MEMORY_CEILING_ENV: &str = "KIN_INIT_MEMORY_CEILING_BYTES";

/// Bytes a conversion holds for each commit, whatever its trees are like.
///
/// One `SemanticChange` and one `ExternalChangeAlias` per commit, plus the
/// parsed commit, its identity entry and its ordering slot, and everything the
/// bootstrap transaction later carries for it.
///
/// The value is the SMALLEST per-commit demand measured across full
/// conversions, so it understates every one of them rather than fitting any.
const BYTES_PER_COMMIT: u64 = 1_200_000;

/// Bytes a conversion holds per commit for each artifact in that commit's tree.
///
/// `build_semantic_git_import_plan` derives history under `TreeRetention::Whole`
/// and keeps one `ResolvedTree` per commit, each a pair of maps over every
/// artifact in that tree, so this term is O(commits x tree width) by
/// construction. Same discipline as the term above: the smallest measured, not
/// the best fitted.
const BYTES_PER_COMMIT_ARTIFACT: u64 = 4_000;

/// Fraction of the ceiling a forecast may reach before the conversion says so.
///
/// Under it the conversion is silent, because a line about memory on a
/// conversion that had room to spare is noise that trains an operator to skip
/// the line that matters.
///
/// Set where the measured subjects fall on the right side of it: on an 8 GiB
/// ceiling the forecast puts axum at 46 percent and stays silent, and puts flask
/// at 78 percent and requests at 91 percent and says so. Those are the two whose
/// real conversions went to 78 and 100 percent of that cap, and the second of
/// them hit the ceiling 883 times without being killed.
const TIGHT_FRACTION: f64 = 0.7;

/// How far past the ceiling a forecast has to reach before the conversion is
/// refused rather than warned about.
///
/// Not 1.0, and the reason is the measurement rather than timidity. The
/// per-unit demand behind these coefficients varies by 1.7x across the measured
/// per-commit term and by at least 2.5x across the per-artifact term, so a
/// refusal decided at exactly the ceiling would be decided inside the noise of
/// its own calibration. A false refusal costs a user a conversion that would
/// have worked and sends them to an environment variable; a warning costs them
/// a line of text and tells them the same thing.
///
/// The case this exists for is not marginal. prometheus forecasts 14 times an
/// 8 GiB ceiling, so it refuses under any threshold in this range, and the
/// repositories that sit just over the line get the warning instead, before the
/// work rather than after it.
const REFUSE_MULTIPLE: f64 = 1.5;

/// The two numbers that drive a conversion's peak, counted from the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistorySurvey {
    /// Commits reachable from HEAD. One resolved tree is materialized for each.
    pub commits: u64,
    /// Artifacts the index tracks, which is the width of each of those trees.
    pub tracked_artifacts: u64,
}

impl HistorySurvey {
    /// Tree entries the plan materializes across the whole conversion.
    ///
    /// Saturating rather than wrapping: the product is what the forecast is
    /// built on, and a repository large enough to overflow it is a repository
    /// that should refuse rather than be forecast at zero.
    pub fn tree_entries(&self) -> u64 {
        self.commits.saturating_mul(self.tracked_artifacts)
    }

    /// Bytes a conversion of this repository is expected to hold at its peak.
    ///
    /// The larger of two floors rather than their sum. Both terms are real and
    /// a conversion pays both, so the sum is the better prediction; but each
    /// coefficient is already the smallest value any measured conversion
    /// justified, and summing two independently minimised terms is how a floor
    /// stops being one. Taking the larger keeps the guarantee that matters:
    /// whatever this returns, every conversion measured at that scale needed at
    /// least that much.
    pub fn forecast_peak_bytes(&self) -> u64 {
        let by_commit = self.commits.saturating_mul(BYTES_PER_COMMIT);
        let by_tree = self
            .tree_entries()
            .saturating_mul(BYTES_PER_COMMIT_ARTIFACT);
        by_commit.max(by_tree)
    }
}

/// What the ladder decided about this conversion's memory before running it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// Nothing is claimed, and the conversion proceeds exactly as before.
    ///
    /// Carries why rather than a bare absence, because "this machine has no
    /// readable ceiling" and "this repository could not be surveyed" send an
    /// operator to different places.
    Unmeasured { reason: String },
    /// The operator set a ceiling this cannot read, so nothing is judged.
    ///
    /// Its own verdict rather than an [`Self::Unmeasured`], because the two
    /// differ in who can act. A machine with no readable ceiling is Kin's
    /// problem and the conversion should carry on. A ceiling an operator typed
    /// and Kin could not parse is the operator's, and treating it as absent
    /// turns one typo into a silently disarmed guard, which is the same silence
    /// this module exists to end.
    InvalidCeilingOverride { raw: String },
    /// The forecast is comfortably under the ceiling. Nothing is printed.
    Fits {
        survey: HistorySurvey,
        forecast_bytes: u64,
        ceiling_bytes: u64,
    },
    /// The forecast is under the ceiling but close enough to say so.
    Tight {
        survey: HistorySurvey,
        forecast_bytes: u64,
        ceiling_bytes: u64,
    },
    /// The forecast is over the ceiling. The conversion refuses here.
    Exceeds {
        survey: HistorySurvey,
        forecast_bytes: u64,
        ceiling_bytes: u64,
    },
}

impl BudgetVerdict {
    /// Whether the conversion must not start.
    pub fn refuses(&self) -> bool {
        matches!(
            self,
            Self::Exceeds { .. } | Self::InvalidCeilingOverride { .. }
        )
    }

    /// The one line a conversion that had room but not much of it prints.
    ///
    /// `None` for every other verdict, including the refusal, whose prose is
    /// several lines and lives in [`Self::refusal_lines`].
    pub fn advisory_line(&self) -> Option<String> {
        let Self::Tight {
            survey,
            forecast_bytes,
            ceiling_bytes,
        } = self
        else {
            return None;
        };
        // One sentence for the whole band, because the band spans both sides of
        // the ceiling: a forecast at 91 percent of the limit and one at 130
        // percent are both cases where the conversion probably runs and might
        // not, and wording that read "N of the M allowed" would be nonsense on
        // the second. So it states both figures and lets the reader compare
        // them, and it carries the remedy, because being warned and given
        // nothing to do is most of the way back to being told nothing.
        Some(format!(
            "  this conversion is expected to hold about {}, against the {} this {} allows, \
             because {} commits over {} tracked files is a large history. It will probably \
             finish. If the kernel stops it you will get no message from this run, and the next \
             one will say what happened; to be sure instead, give it more than {} or convert a \
             repository with less history",
            human_bytes(*forecast_bytes),
            human_bytes(*ceiling_bytes),
            ceiling_noun(),
            survey.commits,
            survey.tracked_artifacts,
            human_bytes(*forecast_bytes),
        ))
    }

    /// The refusal, as the lines an operator reads.
    ///
    /// Split from the writing so the wording is pinned by tests rather than by
    /// converting a repository nobody has.
    pub fn refusal_lines(&self) -> Vec<String> {
        if let Self::InvalidCeilingOverride { raw } = self {
            return vec![
                format!(
                    "{INIT_MEMORY_CEILING_ENV} is set to {raw:?}, which is not a positive whole \
                     number of bytes"
                ),
                "  that variable names the memory ceiling this conversion is judged against, so a \
                 value Kin cannot read would disarm the check that stops a conversion being \
                 killed with no message"
                    .to_string(),
                format!(
                    "  set it to a byte count, for example {INIT_MEMORY_CEILING_ENV}=17179869184 \
                     for 16 GB, or unset it to let Kin measure this machine"
                ),
            ];
        }
        let Self::Exceeds {
            survey,
            forecast_bytes,
            ceiling_bytes,
        } = self
        else {
            return Vec::new();
        };
        let times = *forecast_bytes / (*ceiling_bytes).max(1);
        vec![
            format!(
                "this conversion needs more memory than this {} has: at least {}, about {} times \
                 the {} here",
                ceiling_noun(),
                human_bytes(*forecast_bytes),
                times.max(1),
                human_bytes(*ceiling_bytes),
            ),
            format!(
                "  {} commits over {} tracked files is what drives it: a conversion materializes \
                 one resolved tree per commit and holds every one of them, so its peak follows \
                 the two multiplied together",
                survey.commits, survey.tracked_artifacts,
            ),
            "  that figure is a floor, taken from the least any measured conversion needed at a \
             smaller size, so read it as an order of magnitude rather than as a target"
                .to_string(),
            format!(
                "  give it more than {}, on a larger machine or by raising this {}'s memory limit",
                human_bytes(*forecast_bytes),
                ceiling_noun(),
            ),
            "  or convert a repository with less history. Note that a shallow clone is not that \
             repository: `git clone --depth` leaves a boundary Kin refuses, because a history \
             whose oldest commits have absent parents cannot be captured losslessly"
                .to_string(),
            format!(
                "  if this {} really has more memory than Kin could read, set {} to the true \
                 ceiling in bytes and run again",
                ceiling_noun(),
                INIT_MEMORY_CEILING_ENV,
            ),
            "  nothing was written: this refusal happens before any capture, so there is no \
             staging to reclaim and no partial store to clean up"
                .to_string(),
        ]
    }
}

/// Whether the ceiling this process reads belongs to a container or a machine.
///
/// The same word the post-mortem uses for the same ceiling, taken from the same
/// method, so a refusal and the post-mortem that would have followed it cannot
/// disagree about what kind of limit stopped the run. Read fresh rather than
/// carried on the verdict, because a verdict pinned in a test should not have to
/// fabricate a pressure source in order to render.
fn ceiling_noun() -> &'static str {
    memory_pressure::read()
        .reading()
        .map_or("machine", |reading| reading.source.as_str())
}

/// Where the ceiling came from, or why there is none to judge against.
enum Ceiling {
    /// A usable ceiling, from the operator or from the machine.
    Bytes(u64),
    /// The operator named one this cannot read.
    Invalid(String),
    /// Nothing named one, and the machine could not be measured.
    Unreadable(String),
}

/// The ceiling this conversion is judged against.
///
/// The operator's value wins outright and is not clamped, for the same reason
/// the footprint budget's does: a person who has measured their own machine is
/// a better source than a probe that could not. What it does NOT do is fall
/// back to the measured ceiling when the operator's value will not parse,
/// because an operator who set the variable is an operator who believes it took
/// effect.
fn ceiling() -> Ceiling {
    if let Ok(raw) = std::env::var(INIT_MEMORY_CEILING_ENV) {
        let trimmed = raw.trim();
        return match trimmed.parse::<u64>() {
            Ok(bytes) if bytes > 0 => Ceiling::Bytes(bytes),
            _ => Ceiling::Invalid(trimmed.to_string()),
        };
    }
    match memory_pressure::ceiling_bytes() {
        Some(bytes) if bytes > 0 => Ceiling::Bytes(bytes),
        _ => Ceiling::Unreadable(
            "no memory ceiling could be read for this machine, so this conversion's peak was not \
             forecast"
                .to_string(),
        ),
    }
}

/// Count the commits reachable from HEAD and the artifacts the index tracks.
///
/// Both reads are deliberately cheap and deliberately fallible. This runs
/// before a conversion has committed to anything, so a repository shape neither
/// read understands must leave the conversion exactly as it was rather than
/// refuse it: every error here becomes [`BudgetVerdict::Unmeasured`].
pub fn survey_history(source: &Path) -> Result<HistorySurvey, String> {
    // Opened the way capture opens it, not the way a convenience helper would.
    // `gix::open` honours ambient Git configuration and replacement objects, so
    // on a machine with replace refs configured this would count a different
    // history than the one phase 2 goes on to capture, and the forecast would be
    // about a repository nobody is converting.
    let options = gix::open::Options::isolated()
        .strict_config(true)
        .config_overrides(["core.useReplaceRefs=true"]);
    let repo = gix::open_opts(source, options)
        .map_err(|error| format!("open {}: {error}", source.display()))?;

    let head = repo
        .head_id()
        .map_err(|error| format!("resolve HEAD: {error}"))?;
    let walk = repo
        .rev_walk([head.detach()])
        .all()
        .map_err(|error| format!("walk history: {error}"))?;
    let mut commits: u64 = 0;
    for step in walk {
        step.map_err(|error| format!("walk history: {error}"))?;
        commits += 1;
    }

    let index_path = repo.git_dir().join("index");
    let index = gix::index::File::at_or_default(
        &index_path,
        repo.object_hash(),
        false,
        gix::index::decode::Options::default(),
    )
    .map_err(|error| format!("open Git index: {error}"))?;
    let tracked_artifacts = index.entries().len() as u64;

    Ok(HistorySurvey {
        commits,
        tracked_artifacts,
    })
}

/// Decide, before any capture, whether this conversion fits.
pub fn assess(source: &Path) -> BudgetVerdict {
    let ceiling_bytes = match ceiling() {
        Ceiling::Bytes(bytes) => bytes,
        Ceiling::Invalid(raw) => return BudgetVerdict::InvalidCeilingOverride { raw },
        Ceiling::Unreadable(reason) => return BudgetVerdict::Unmeasured { reason },
    };
    let survey = match survey_history(source) {
        Ok(survey) => survey,
        Err(reason) => return BudgetVerdict::Unmeasured { reason },
    };
    verdict_for(survey, ceiling_bytes)
}

/// The decision itself, over numbers rather than over a repository.
///
/// Separated so the thresholds are testable without a Git repository and
/// without a machine of any particular size.
pub fn verdict_for(survey: HistorySurvey, ceiling_bytes: u64) -> BudgetVerdict {
    let forecast_bytes = survey.forecast_peak_bytes();
    if forecast_bytes as f64 > ceiling_bytes as f64 * REFUSE_MULTIPLE {
        return BudgetVerdict::Exceeds {
            survey,
            forecast_bytes,
            ceiling_bytes,
        };
    }
    if forecast_bytes as f64 > ceiling_bytes as f64 * TIGHT_FRACTION {
        return BudgetVerdict::Tight {
            survey,
            forecast_bytes,
            ceiling_bytes,
        };
    }
    BudgetVerdict::Fits {
        survey,
        forecast_bytes,
        ceiling_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn survey(commits: u64, tracked_artifacts: u64) -> HistorySurvey {
        HistorySurvey {
            commits,
            tracked_artifacts,
        }
    }

    #[test]
    fn a_forecast_over_the_ceiling_refuses() {
        let verdict = verdict_for(survey(18_514, 1_676), 8 * 1024 * 1024 * 1024);
        assert!(verdict.refuses(), "expected a refusal, got {verdict:?}");
        assert!(matches!(verdict, BudgetVerdict::Exceeds { .. }));
    }

    #[test]
    fn a_small_repository_is_silent() {
        let verdict = verdict_for(survey(200, 40), 8 * 1024 * 1024 * 1024);
        assert!(!verdict.refuses());
        assert!(matches!(verdict, BudgetVerdict::Fits { .. }));
        assert_eq!(verdict.advisory_line(), None);
        assert!(verdict.refusal_lines().is_empty());
    }

    /// The band between silence and refusal exists and is reachable, which a
    /// threshold nothing ever lands in would not be.
    #[test]
    fn a_forecast_just_under_the_ceiling_says_so_and_continues() {
        let survey = survey(4_000, 1_000);
        let ceiling = survey.forecast_peak_bytes() + 1;
        let verdict = verdict_for(survey, ceiling);
        assert!(!verdict.refuses());
        let line = verdict
            .advisory_line()
            .expect("a tight verdict states its forecast");
        assert!(line.contains("4000 commits"), "line was: {line}");
        assert!(verdict.refusal_lines().is_empty());
    }

    /// The refusal boundary is where the constant says it is, to the byte.
    #[test]
    fn the_refusal_boundary_is_exact() {
        let survey = survey(4_000, 1_000);
        let forecast = survey.forecast_peak_bytes() as f64;
        let at = (forecast / REFUSE_MULTIPLE).ceil() as u64;
        assert!(
            !verdict_for(survey, at).refuses(),
            "a ceiling exactly at the multiple must not refuse"
        );
        assert!(
            verdict_for(survey, at - 1).refuses(),
            "one byte tighter than the multiple must refuse"
        );
    }

    /// A forecast OVER the ceiling but under the refusal multiple warns and
    /// carries on.
    ///
    /// This is the band the coefficients' own spread buys, and it needs its own
    /// guard because it is invisible to every other test here: raising the
    /// refusal back to the ceiling leaves the refusal tests green, the floor
    /// test green and the calibration test green, and only this one goes red.
    /// A conversion this close is one the calibration cannot resolve, so it is
    /// told what to expect rather than stopped.
    #[test]
    fn a_forecast_just_over_the_ceiling_warns_rather_than_refusing() {
        let survey = survey(4_000, 1_000);
        let forecast = survey.forecast_peak_bytes();
        let ceiling = forecast - forecast / 5; // forecast is 1.25x this ceiling
        let verdict = verdict_for(survey, ceiling);
        assert!(
            !verdict.refuses(),
            "a forecast 1.25x the ceiling is inside the calibration's own spread and must not \
             refuse, got {verdict:?}"
        );
        let line = verdict
            .advisory_line()
            .expect("a conversion over its ceiling has to say so before it starts");
        assert!(line.contains("expected to hold about"), "line was: {line}");
        assert!(
            line.contains("give it more than"),
            "a warning with no remedy is most of the way back to silence: {line}"
        );
    }

    /// Every remedy the refusal offers has to be in the words it prints, or the
    /// operator meets the same dead end the silence left them in.
    #[test]
    fn the_refusal_names_both_remedies_and_the_shallow_dead_end() {
        let verdict = verdict_for(survey(18_514, 1_676), 8 * 1024 * 1024 * 1024);
        let text = verdict.refusal_lines().join("\n");
        assert!(text.contains("18514 commits"), "text was:\n{text}");
        assert!(text.contains("1676 tracked files"), "text was:\n{text}");
        assert!(text.contains("8.0 GB"), "text was:\n{text}");
        assert!(text.contains("give it more than"), "text was:\n{text}");
        assert!(
            text.contains("convert a repository with less history"),
            "text was:\n{text}"
        );
        assert!(text.contains("git clone --depth"), "text was:\n{text}");
        assert!(text.contains(INIT_MEMORY_CEILING_ENV), "text was:\n{text}");
        assert!(text.contains("no staging to reclaim"), "text was:\n{text}");
    }

    /// A repository large enough to overflow the product saturates high rather
    /// than wrapping to a forecast of nothing.
    ///
    /// Wrapping is the failure that matters and it fails silently: a product
    /// that wraps produces a small number, the verdict reads `Fits`, and the
    /// largest repository anyone could hand Kin is the one it says nothing
    /// about. So the assertion is on the saturated value and on the verdict
    /// against a ceiling a real machine could have, rather than against a
    /// ceiling near `u64::MAX`, which no machine has and where a saturated
    /// forecast is legitimately not a refusal.
    #[test]
    fn an_overflowing_product_saturates_instead_of_wrapping() {
        let huge = survey(u64::MAX, u64::MAX);
        assert_eq!(
            huge.tree_entries(),
            u64::MAX,
            "the product wrapped instead of saturating"
        );
        assert_eq!(
            huge.forecast_peak_bytes(),
            u64::MAX,
            "the forecast wrapped instead of saturating"
        );
        assert!(
            verdict_for(huge, 64 * 1024 * 1024 * 1024).refuses(),
            "a saturated forecast must refuse against any ceiling a machine really has"
        );
    }

    /// The forecast has to move with each of its two inputs, or one of them is
    /// decoration.
    ///
    /// Both are asserted because the forecast takes the larger of two terms,
    /// and a term that never wins for any input is a term that could be deleted
    /// without changing an answer. The tree-width case is chosen wide enough
    /// that its term is the one that decides, and the depth case narrow enough
    /// that the other is.
    #[test]
    fn both_inputs_move_the_forecast() {
        let deep = survey(1_000, 1).forecast_peak_bytes();
        assert!(
            survey(2_000, 1).forecast_peak_bytes() > deep,
            "depth did not move a forecast whose width term cannot win"
        );
        let wide = survey(1_000, 1_000).forecast_peak_bytes();
        assert!(
            survey(1_000, 2_000).forecast_peak_bytes() > wide,
            "width did not move a forecast whose width term does win"
        );
    }

    /// Every conversion this forecast was calibrated on, and the one that could
    /// not finish, land on the side of the ceiling they actually landed on.
    ///
    /// This is the check that stops the coefficients drifting into a forecast
    /// nobody measured. The four rows are full `kin init` runs of the shipped
    /// 0.6.0 inside one Debian 12 container hard-capped at 8 GiB, with the peak
    /// taken by sampling the cgroup's `memory.current` beside the run rather
    /// than by reading `memory.peak`, which reports the cap exactly on any run
    /// the cap actually stopped.
    ///
    /// Two properties are asserted, and they pull in opposite directions, which
    /// is the point. The forecast must never exceed what a conversion really
    /// held, or it is not a floor and it will refuse work that would have
    /// finished. And it must still refuse the one repository that could not be
    /// converted, or it is a check that cannot fire.
    #[test]
    fn the_forecast_is_a_floor_on_every_conversion_it_was_measured_against() {
        const CEILING: u64 = 8 * 1024 * 1024 * 1024;
        // (name, commits, tracked files, bytes actually held, did it convert)
        let measured = [
            ("axum", 1_983_u64, 503_u64, 4_067_635_200_u64, true),
            ("flask", 5_556, 236, 6_731_427_840, true),
            // Held 8,589,705,216 of an 8,589,934,592 cap and survived, so its
            // reading is the ceiling rather than its demand. It is a floor on
            // the demand, which is all this assertion needs.
            ("requests", 6_493, 130, 8_589_705_216, true),
            // Killed at phase 4 of 17, twice, so nothing was measured beyond
            // "more than the cap". Recorded at the cap for the same reason.
            ("prometheus", 18_514, 1_676, 8_589_934_592, false),
        ];
        for (name, commits, artifacts, held_bytes, converted) in measured {
            let survey = survey(commits, artifacts);
            let forecast = survey.forecast_peak_bytes();
            // The floor property is asserted only where the reading IS the
            // demand. A conversion the cap stopped read the cap, so its figure
            // bounds its demand from below, and requiring the forecast to stay
            // under it would be requiring the forecast not to exceed a number it
            // exists to exceed.
            let reading_is_the_demand = converted;
            if reading_is_the_demand {
                assert!(
                    forecast <= held_bytes,
                    "{name}: forecast {forecast} exceeds the {held_bytes} it really held, so the \
                     forecast is not a floor"
                );
            }
            let verdict = verdict_for(survey, CEILING);
            assert_eq!(
                verdict.refuses(),
                !converted,
                "{name}: refuses() is {} for a repository that {} convert under 8 GiB",
                verdict.refuses(),
                if converted { "did" } else { "did not" }
            );
        }
    }

    /// The advisory band caught the two conversions that ran close to the cap
    /// and left the one with room alone.
    ///
    /// Separated from the floor test above because it grades a different thing:
    /// that test proves the forecast never over-claims, this one proves the
    /// threshold over it is set somewhere useful. A band nothing ever lands in
    /// would pass every assertion above.
    #[test]
    fn the_advisory_band_separates_the_measured_conversions() {
        const CEILING: u64 = 8 * 1024 * 1024 * 1024;
        assert!(
            matches!(
                verdict_for(survey(1_983, 503), CEILING),
                BudgetVerdict::Fits { .. }
            ),
            "axum used 47 percent of this cap and should convert without comment"
        );
        for (name, commits, artifacts) in [("flask", 5_556_u64, 236_u64), ("requests", 6_493, 130)]
        {
            let verdict = verdict_for(survey(commits, artifacts), CEILING);
            assert!(
                matches!(verdict, BudgetVerdict::Tight { .. }),
                "{name} ran close to this cap and should say so, got {verdict:?}"
            );
            assert!(
                verdict
                    .advisory_line()
                    .is_some_and(|line| line.contains("expected to hold")),
                "{name}'s advisory does not state what it expects to hold"
            );
        }
    }

    /// An operator ceiling Kin cannot read refuses rather than falling back.
    ///
    /// Falling back to the measured ceiling is the tempting behaviour and the
    /// wrong one: an operator who set the variable believes it took effect, and
    /// a typo would quietly restore exactly the conversion they were trying to
    /// avoid.
    #[test]
    fn an_unreadable_ceiling_override_refuses_and_says_which_variable() {
        let verdict = BudgetVerdict::InvalidCeilingOverride {
            raw: "eight gigabytes".to_string(),
        };
        assert!(verdict.refuses());
        let text = verdict.refusal_lines().join("\n");
        assert!(text.contains(INIT_MEMORY_CEILING_ENV), "text was:\n{text}");
        assert!(text.contains("eight gigabytes"), "text was:\n{text}");
        assert!(
            text.contains("not a positive whole number"),
            "text was:\n{text}"
        );
        assert_eq!(verdict.advisory_line(), None);
    }

    /// A machine with no readable ceiling changes nothing.
    ///
    /// The conversion that ran before this module existed must still run, since
    /// refusing over a ceiling nobody could read would invent a limit from an
    /// absence.
    #[test]
    fn an_unreadable_machine_neither_refuses_nor_speaks() {
        let verdict = BudgetVerdict::Unmeasured {
            reason: "no memory ceiling could be read for this machine".to_string(),
        };
        assert!(!verdict.refuses());
        assert_eq!(verdict.advisory_line(), None);
        assert!(verdict.refusal_lines().is_empty());
    }
}
