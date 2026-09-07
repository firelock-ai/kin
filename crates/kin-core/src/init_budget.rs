// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a conversion will hold, read before it starts holding it.
//!
//! A conversion's peak follows history depth, because every commit's entity and
//! relation deltas are derived in phase 5 and held from there until the store
//! holds them at phase 13, and beside them the store itself is built and then
//! opened. Tree width sets the peak instead when the tree is wide enough:
//! the tree a conversion admits is parsed whole to derive its semantics. What a
//! conversion no longer holds is one resolved tree per commit. The history
//! derivation resolves each commit's tree from its first parent's and the
//! leaves that differ, hands it to every reader that needs it while it is
//! live, keeps a hash and a content observation in its place, and drops it once
//! nothing later resolves against it, so history depth multiplied by tree
//! width is no longer a term here.
//!
//! On a repository whose demand is larger than the machine, the peak ends the
//! run at phase 5 or 13 and says nothing at all. `SIGKILL` runs no destructor
//! and writes no message, so the operator sees a few phase lines and a shell
//! that prints `Killed`. The post-mortem this crate already writes is excellent
//! and arrives one run too late, because it is read off disk by the NEXT
//! command; the run that dies is the run a first-time user has.
//!
//! So the ladder asks the cheap question first. Counting a repository's commits
//! and its tracked artifacts costs a rev-walk and one index read, both of which
//! finish before phase 2 would have started copying anything. When those
//! forecast more than this process can read as a ceiling, the conversion
//! refuses in words instead of dying in silence.
//!
//! # What the forecast is, and what it is not
//!
//! It is a floor, not a prediction. Each coefficient below is the LOWEST demand
//! per unit of work observed across measured conversions, and the forecast takes
//! the larger of its terms rather than their sum, so a forecast that exceeds the
//! ceiling is a statement that the real demand exceeds it too. Nothing here
//! forecasts how long a conversion takes, and a forecast under the ceiling is
//! not a promise the conversion fits: a repository can be unusual in ways two
//! numbers do not capture, and the machine's free memory moves while the
//! conversion runs.
//!
//! That asymmetry is deliberate. A refusal that fires wrongly costs a user a
//! conversion that would have worked, and the only way back is an environment
//! variable. A refusal that fails to fire costs nothing that is not already
//! being paid today, because dying mid-ladder is the behaviour it replaces.

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
/// The enriched entity and relation deltas of one commit, resident from the
/// phase that derives them through the admitted plan, the transaction and the
/// store's own copy, plus one `SemanticChange`, one alias, the parsed commit,
/// its tree hash and its content observation.
///
/// The value is the SMALLEST per-commit demand measured across full
/// conversions, so it understates every one of them rather than fitting any.
/// Measured on psf/requests at 6,493 commits over 130 files on kin 0.7.3, a
/// scratch store and `--no-enrich`, resident set sampled once a second from
/// outside the process: peak 4,800,708,608 bytes, 739,368 per commit. This
/// rounds under it.
const BYTES_PER_COMMIT: u64 = 700_000;

/// Bytes the repository daemon holds for each commit of the store it loads.
///
/// Not the conversion's demand. `kin init` does not end when the conversion
/// ends: it starts a repository daemon on the store it just wrote, and that
/// daemon loads the store whole. Measured on the same psf/requests store at
/// three ceilings, the load came back 8.351 GiB by resident set at 9 GiB,
/// 8.0 GiB by the daemon's own footprint accounting at 12 GiB, and 7.9 GiB by
/// the same accounting at 16 GiB, the last of those being the only one taken
/// with room to spare. Per commit that is 1.22 MB at the least, and this rounds
/// under it.
///
/// A separate coefficient from [`BYTES_PER_COMMIT`] on purpose. One number used
/// to serve both, and the conversion's own demand has since come down while
/// the daemon's has not, so a single floor on the conversion would have
/// stopped speaking about a daemon it still cannot describe.
const DAEMON_BYTES_PER_COMMIT: u64 = 1_200_000;

/// Fraction of the ceiling a forecast may reach before the conversion says so.
///
/// Under it the conversion is silent, because a line about memory on a
/// conversion that had room to spare is noise that trains an operator to skip
/// the line that matters.
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
const REFUSE_MULTIPLE: f64 = 1.5;

/// Bytes a conversion holds for each artifact in the head tree it admits.
///
/// Deriving semantics from the admitted tree is where a wide tree's memory
/// goes: on a measured 18,508-file snapshot the conversion reached 13.68 GiB
/// inside phase 5, before a single byte of it had been staged.
///
/// Same discipline as the coefficients above: the SMALLEST demand per head
/// artifact measured across snapshot conversions, so the forecast understates
/// every one of them rather than fitting any. Measured on three one-commit
/// snapshots, peak resident bytes per head artifact: react 254,734 over 7,210
/// files, redis 947,678 over 1,857, vscode 968,025 over 18,508. React is the
/// floor and this rounds under it.
const BYTES_PER_HEAD_ARTIFACT: u64 = 250_000;

/// Bytes a conversion holds for each byte of source it admits.
///
/// Paired with [`BYTES_PER_HEAD_ARTIFACT`] and taken as the larger of the two,
/// because neither alone survives both shapes: a tree of many tiny files is
/// driven by its file count, and a tree of few large files by its bytes. A
/// repository that is extreme in either direction is one the other term
/// forecasts at nothing, and the measured subjects sit on opposite sides of
/// that line: react's projection comes from its file count and vscode's from
/// its bytes.
///
/// Same floor discipline. Peak resident bytes per byte of captured object:
/// redis 82.76, react 45.37, vscode 33.69. Vscode is the floor and this rounds
/// under it. Phase 1 has no byte count, so only the phase-4 projection carries
/// this term.
const BYTES_PER_SOURCE_BYTE: u64 = 33;

/// The two numbers that drive a conversion's peak, counted from the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistorySurvey {
    /// Commits reachable from HEAD. One set of semantic deltas is derived and
    /// held for each.
    pub commits: u64,
    /// Artifacts the index tracks, which is the width of the tree the
    /// conversion parses whole.
    pub tracked_artifacts: u64,
}

impl HistorySurvey {
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
        let by_head = self
            .tracked_artifacts
            .saturating_mul(BYTES_PER_HEAD_ARTIFACT);
        by_commit.max(by_head)
    }

    /// Bytes the repository daemon is expected to hold once it loads the store
    /// this conversion writes.
    pub fn daemon_load_bytes(&self) -> u64 {
        self.commits.saturating_mul(DAEMON_BYTES_PER_COMMIT)
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
    /// The conversion fits the ceiling, but the store it writes is forecast
    /// past the daemon's share of it.
    ///
    /// `kin init` does not end when the conversion ends. It starts a repository
    /// daemon on the store it just wrote, and that daemon is allowed half this
    /// same ceiling by [`memory_pressure::FootprintBudget`]. A daemon load over
    /// that half is the band where the conversion succeeds and the daemon it
    /// starts arrives already past what it is allowed to hold.
    ///
    /// Measured on psf/requests at 6493 commits inside a 12 GiB container: the
    /// conversion completed all seventeen phases, and the daemon was then
    /// killed four times across `kin init` and three `kin graph status`
    /// attempts. The same corpus in a 9 GiB container held 8.351 GiB of
    /// resident set in the daemon against 5.518 GiB in the conversion, so the
    /// daemon is the larger of the two and it is the one this band describes.
    DaemonAllowance {
        survey: HistorySurvey,
        forecast_bytes: u64,
        daemon_load_bytes: u64,
        ceiling_bytes: u64,
        allowance_bytes: u64,
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
        if let Self::DaemonAllowance {
            survey,
            forecast_bytes,
            daemon_load_bytes,
            ceiling_bytes,
            allowance_bytes,
        } = self
        {
            return Some(Self::daemon_allowance_line(
                survey,
                *forecast_bytes,
                *daemon_load_bytes,
                *ceiling_bytes,
                *allowance_bytes,
            ));
        }
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

    /// The line for a conversion that fits the machine while the store it
    /// writes does not fit the daemon's share of it.
    ///
    /// Its own wording rather than the [`Self::Tight`] sentence, because the
    /// two say different things. Tight says the conversion might not finish.
    /// This says the conversion will finish and the thing that serves it
    /// afterward may not start, which is a worse outcome to be surprised by: it
    /// leaves a store on disk that reports success and answers nothing.
    ///
    /// The sentence states the allowance as a number and does not say where the
    /// number came from. It is half the ceiling when Kin derived it and it is
    /// whatever an operator typed when they set
    /// `KIN_DAEMON_MEMORY_BUDGET_BYTES`, so a sentence that named one of those
    /// provenances would be false in the other case.
    ///
    /// The remedy is stated as a number the reader can act on rather than as a
    /// direction. Below the derived budget's own ceiling the allowance is half
    /// the machine, so twice the daemon's load is the size that leaves it room.
    /// Above it the allowance is capped whatever the machine has, so more
    /// memory is not a remedy and the line says so instead of sending a reader
    /// to buy some. Nothing here offers `KIN_DAEMON_MEMORY_BUDGET_BYTES`:
    /// raising a self-imposed allowance does not create memory, and advice that
    /// cannot work is the defect this product already has one ticket for.
    fn daemon_allowance_line(
        survey: &HistorySurvey,
        forecast_bytes: u64,
        daemon_load_bytes: u64,
        ceiling_bytes: u64,
        allowance_bytes: u64,
    ) -> String {
        let remedy = if daemon_load_bytes <= memory_pressure::DERIVED_BUDGET_CEILING_BYTES {
            format!(
                "give this {} more than {}",
                ceiling_noun(),
                human_bytes(daemon_load_bytes.saturating_mul(2))
            )
        } else {
            format!(
                "no machine size fixes this, because one repository daemon is never allowed more \
                 than {}, so this store needs less history",
                human_bytes(memory_pressure::DERIVED_BUDGET_CEILING_BYTES)
            )
        };
        format!(
            "  this conversion is expected to hold about {}, which fits the {} this {} allows. \
             The daemon `kin init` starts on the finished store is a different matter: one \
             repository daemon here is allowed {}, and loading the store that {} commits over \
             {} tracked files write is expected to take about {}, above that. So the conversion \
             will probably finish and the daemon that serves it afterward starts already past \
             its allowance, which stops its background work and can end with the kernel stopping \
             the daemon, leaving a store that reports success and answers nothing. To leave it \
             room, {}, or convert a repository with less history",
            human_bytes(forecast_bytes),
            human_bytes(ceiling_bytes),
            ceiling_noun(),
            human_bytes(allowance_bytes),
            survey.commits,
            survey.tracked_artifacts,
            human_bytes(daemon_load_bytes),
            remedy,
        )
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
                "  {} commits over {} tracked files is what drives it: a conversion holds every \
                 commit's entity and relation deltas from the phase that derives them until the \
                 store holds them, so its peak follows the commit count, and it parses the whole \
                 tree it admits, so a wide enough tree sets the peak instead",
                survey.commits, survey.tracked_artifacts,
            ),
            "  that figure is a floor and not a prediction, taken from the least any measured \
             conversion needed per commit and per file; the change one commit carries varies \
             sixfold across measured repositories, so a conversion can need several times this"
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
    // The allowance the daemon will actually run under, not merely the one
    // this ceiling would derive. An operator who set
    // `KIN_DAEMON_MEMORY_BUDGET_BYTES` has named the daemon's share outright,
    // and forecasting against a number the daemon will not use would be a
    // check measuring a machine nobody is running on.
    let allowance_bytes = memory_pressure::FootprintBudget::resolve(Some(ceiling_bytes))
        .map(|budget| budget.bytes)
        .unwrap_or_else(|| memory_pressure::FootprintBudget::derived_from(ceiling_bytes));
    verdict_for_with_allowance(survey, ceiling_bytes, allowance_bytes)
}

/// The decision itself, over numbers rather than over a repository.
///
/// Separated so the thresholds are testable without a Git repository and
/// without a machine of any particular size.
pub fn verdict_for(survey: HistorySurvey, ceiling_bytes: u64) -> BudgetVerdict {
    verdict_for_with_allowance(
        survey,
        ceiling_bytes,
        memory_pressure::FootprintBudget::derived_from(ceiling_bytes),
    )
}

/// The same decision, with the daemon's allowance named rather than derived.
///
/// Separate from [`verdict_for`] so that function stays a pure function of two
/// numbers and its tests keep needing no environment. Only [`assess`] passes an
/// allowance it read from the environment, because only [`assess`] is running on
/// the machine the daemon will start on.
pub fn verdict_for_with_allowance(
    survey: HistorySurvey,
    ceiling_bytes: u64,
    allowance_bytes: u64,
) -> BudgetVerdict {
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
    // The conversion is not the whole command. Below TIGHT_FRACTION the
    // conversion has room, and the question that remains is whether the daemon
    // this command starts on the finished store has any. A daemon load over
    // the allowance describes a store that daemon cannot hold within its own
    // share of this machine. The share is half the ceiling when Kin derived it
    // and whatever an operator named when they set the budget outright, which
    // is why it arrives as an argument rather than being computed here.
    let daemon_load_bytes = survey.daemon_load_bytes();
    if daemon_load_bytes > allowance_bytes {
        return BudgetVerdict::DaemonAllowance {
            survey,
            forecast_bytes,
            daemon_load_bytes,
            ceiling_bytes,
            allowance_bytes,
        };
    }
    BudgetVerdict::Fits {
        survey,
        forecast_bytes,
        ceiling_bytes,
    }
}

// ------------------------------------------------- the plan's own projection

/// What the import plan knows about the conversion it has just planned.
///
/// Distinct from [`HistorySurvey`], which is counted from the source before
/// anything is read and can therefore see the tree only as a file count. By
/// phase 4 the plan holds the head tree it is going to admit and a size for
/// every object it captured, so the bytes of the tree are finally a number
/// rather than a guess. Both are needed: the survey refuses a deep history
/// before capture spends minutes on it, and this one describes the shape the
/// survey is blind to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSurvey {
    /// Changes the plan carries, one per admitted commit.
    pub commits: u64,
    /// Artifacts in the head tree the workspace seed admits.
    pub head_artifacts: u64,
    /// Bytes of captured Git objects the plan records.
    pub object_bytes: u64,
}

impl ImportSurvey {
    /// Bytes this conversion is projected to hold at its peak.
    ///
    /// The largest of three floors rather than their sum, for the reason
    /// [`HistorySurvey::forecast_peak_bytes`] gives: each coefficient is
    /// already the smallest any measured conversion justified, and adding
    /// independently minimised terms is how a floor stops being one.
    ///
    /// The first two terms are the phase-1 forecast repeated, so a repository
    /// is never projected LOWER at phase 4 than it was forecast at phase 1.
    /// The third is the bytes term, and it is the one that fires on a tree of
    /// few large files.
    pub fn projected_peak_bytes(&self) -> u64 {
        let by_commit = self.commits.saturating_mul(BYTES_PER_COMMIT);
        let by_head = self
            .head_artifacts
            .saturating_mul(BYTES_PER_HEAD_ARTIFACT)
            .max(self.object_bytes.saturating_mul(BYTES_PER_SOURCE_BYTE));
        by_commit.max(by_head)
    }
}

/// What the ladder decided about this conversion's peak once it had a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportProjection {
    /// The machine could not be measured, so nothing is claimed.
    Unmeasured { reason: String },
    /// The projection fits in what the machine still has.
    Fits {
        survey: ImportSurvey,
        projected_bytes: u64,
        available_bytes: u64,
    },
    /// The projection is larger than what the machine still has.
    Short {
        survey: ImportSurvey,
        projected_bytes: u64,
        available_bytes: u64,
    },
}

impl ImportProjection {
    /// The line an operator sees, or `None` when there is nothing to say.
    ///
    /// Silent unless the projection is short, because a memory line on a
    /// conversion with room to spare is the noise that trains an operator to
    /// skip the line that matters.
    ///
    /// It warns and does not refuse. Phase 1 already owns the refusal, decided
    /// against a ceiling with a documented calibration and an environment
    /// variable to override it. This runs four phases later on a conversion
    /// that has already been admitted and captured, and its own coefficients
    /// are calibrated on far fewer subjects, so turning it into a second
    /// refusal would spend a user's completed capture on the least-tested
    /// number in the module.
    pub fn advisory_line(&self) -> Option<String> {
        let Self::Short {
            survey,
            projected_bytes,
            available_bytes,
        } = self
        else {
            return None;
        };
        // Names the head tree rather than the history, because that is what
        // drove the number, and because the remedy differs. A deep history is
        // helped by a shallow clone. This is not: the measured subject WAS a
        // shallow clone, one commit deep, and it still needed sixteen
        // gigabytes. Telling that operator to clone shallower would send them
        // round a loop they are already standing in.
        Some(format!(
            "  this conversion is projected to hold about {}, and this {} has about {} left, \
             because {} files over {} of source is a wide tree. A shallower clone will not help: \
             the tree is the size, not the history. It will probably not finish; to be sure, give \
             it more than {} or convert a smaller subtree",
            human_bytes(*projected_bytes),
            ceiling_noun(),
            human_bytes(*available_bytes),
            survey.head_artifacts,
            human_bytes(survey.object_bytes),
            human_bytes(*projected_bytes),
        ))
    }
}

/// Project this conversion's peak against what it still has to spend.
///
/// Reads the machine and the environment, so the pure decision lives in
/// [`projection_for`] and this is the only part a test cannot run without one.
pub fn project_import(survey: ImportSurvey) -> ImportProjection {
    match headroom_bytes() {
        Ok(available_bytes) => projection_for(survey, available_bytes),
        Err(reason) => ImportProjection::Unmeasured { reason },
    }
}

/// Bytes this conversion still has, judged against the ceiling phase 1 used.
///
/// Not simply [`memory_pressure::MemoryReading::available_bytes`], because
/// [`INIT_MEMORY_CEILING_ENV`] exists and phase 1 already honours it. An
/// operator sets that variable for one of two reasons, a container whose real
/// cap Kin reads wrongly or a forecast they have judged wrong for their own
/// repository, and either way they stated the true ceiling once and phase 1
/// took them at their word. Reading the machine again four phases later would
/// warn that same operator with the number they overrode, and this projection
/// has no second variable to turn it off.
///
/// The machine is still asked what is charged against that ceiling, because by
/// phase 4 the conversion has already spent some of it. With no override set
/// that arithmetic is `limit_bytes - used_bytes`, which is exactly what
/// [`memory_pressure::MemoryReading::available_bytes`] returns, so an
/// unoverridden conversion is judged against the number it was judged against
/// before.
fn headroom_bytes() -> Result<u64, String> {
    let charged_bytes = memory_pressure::read()
        .reading()
        .map_or(0, |reading| reading.used_bytes);
    headroom_for(ceiling(), charged_bytes)
}

/// The same arithmetic over values, so the override's effect is testable
/// without a process-wide environment variable.
fn headroom_for(ceiling: Ceiling, charged_bytes: u64) -> Result<u64, String> {
    match ceiling {
        // Saturating, so a machine already charged past its own ceiling
        // projects against nothing left rather than wrapping to everything.
        Ceiling::Bytes(bytes) => Ok(bytes.saturating_sub(charged_bytes)),
        // Unreachable inside a conversion: phase 1 refuses an override it
        // cannot parse and never reaches this phase. Answered rather than
        // asserted, so a future caller that arrives here earlier is left
        // silent instead of panicking.
        Ceiling::Invalid(raw) => Err(format!(
            "{INIT_MEMORY_CEILING_ENV} is set to {raw:?}, which is not a byte count, so this \
             conversion's peak was not projected"
        )),
        Ceiling::Unreadable(reason) => Err(reason),
    }
}

/// The same decision over numbers, so the threshold is testable without a
/// machine of any particular size.
pub fn projection_for(survey: ImportSurvey, available_bytes: u64) -> ImportProjection {
    let projected_bytes = survey.projected_peak_bytes();
    if projected_bytes > available_bytes {
        ImportProjection::Short {
            survey,
            projected_bytes,
            available_bytes,
        }
    } else {
        ImportProjection::Fits {
            survey,
            projected_bytes,
            available_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Peak resident bytes measured converting a fresh one-commit snapshot of
    /// each, on kin 0.6.3, `--no-enrich`, with a scratch `KIN_HOME`.
    ///
    /// Name, head artifacts, captured object bytes, measured peak. These are
    /// the subjects both snapshot coefficients were read off, so a change to
    /// either that stops flooring them is a change that broke its own
    /// calibration.
    const MEASURED_SNAPSHOTS: [(&str, u64, u64, u64); 3] = [
        ("redis", 1_857, 21_264_703, 1_759_838_208),
        ("react", 7_210, 40_479_046, 1_836_630_016),
        ("vscode", 18_508, 531_828_795, 17_916_215_296),
    ];

    fn snapshot(head_artifacts: u64, object_bytes: u64) -> ImportSurvey {
        ImportSurvey {
            commits: 1,
            head_artifacts,
            object_bytes,
        }
    }

    /// The case this projection exists for.
    ///
    /// A one-commit snapshot of vscode, which is what `git clone --depth 1`
    /// leaves behind, measured at 16.69 GiB. On a 16 GB machine that must be
    /// spoken about before phase 5 spends the memory rather than after the
    /// kernel spends it for us.
    #[test]
    fn a_one_commit_snapshot_of_a_wide_tree_is_projected_over_a_small_machine() {
        let survey = snapshot(18_508, 531_828_795);
        let projection = projection_for(survey, 16 * 1000 * 1000 * 1000);
        assert!(
            matches!(projection, ImportProjection::Short { .. }),
            "expected a short projection, got {projection:?}"
        );
        assert!(projection.advisory_line().is_some());
    }

    /// Phase 1 sees a wide tree by its file count; phase 4 adds its bytes.
    ///
    /// The phase-1 forecast used to multiply a per-artifact term by the commit
    /// count, so a one-commit snapshot of a wide tree forecast one tree's
    /// worth of entries and nothing for parsing them, and the projection was
    /// the only thing that caught it. The per-head-artifact term now lives at
    /// phase 1 too, so the same snapshot the projection puts over sixteen
    /// gigabytes is forecast in the gigabytes at phase 1 rather than under
    /// one. What phase 1 still cannot see is the source's byte count, which
    /// is the term that carries vscode from four gigabytes to seventeen.
    #[test]
    fn the_phase_one_forecast_sees_the_tree_width_and_the_projection_adds_its_bytes() {
        let head_artifacts = 18_508;
        let object_bytes = 531_828_795;
        let forecast = HistorySurvey {
            commits: 1,
            tracked_artifacts: head_artifacts,
        }
        .forecast_peak_bytes();
        let projected = snapshot(head_artifacts, object_bytes).projected_peak_bytes();
        assert!(
            forecast > 4 * 1000 * 1000 * 1000,
            "the phase-1 forecast for a one-commit snapshot of 18,508 files was {forecast}, so \
             phase 1 went blind to tree width again"
        );
        assert!(
            projected > 16 * 1000 * 1000 * 1000 && projected > forecast,
            "the projection has to add what the forecast cannot see, got {projected} against \
             {forecast}"
        );
    }

    /// Silent when there is room, for the reason the module's own
    /// `TIGHT_FRACTION` gives: a memory line on a conversion that fits is the
    /// noise that trains an operator to skip the one that matters.
    #[test]
    fn a_projection_that_fits_says_nothing() {
        let projection = projection_for(snapshot(1_857, 21_264_703), 64 * 1024 * 1024 * 1024);
        assert!(matches!(projection, ImportProjection::Fits { .. }));
        assert_eq!(projection.advisory_line(), None);
    }

    /// The remedy has to be one the reader is not already standing in.
    ///
    /// The phase-1 refusal offers `git clone --depth`, which is right for a
    /// deep history and useless here: the measured subject WAS one commit deep
    /// and still needed sixteen gigabytes. A line that sent that operator to
    /// clone shallower would send them round a loop.
    #[test]
    fn the_advisory_names_the_tree_and_does_not_offer_a_shallower_clone() {
        let line = projection_for(snapshot(18_508, 531_828_795), 16 * 1000 * 1000 * 1000)
            .advisory_line()
            .expect("a short projection states itself");
        assert!(line.contains("18508 files"), "line was: {line}");
        assert!(line.contains("wide tree"), "line was: {line}");
        assert!(
            line.contains("shallower clone will not help"),
            "the one remedy that cannot work here has to be ruled out by name: {line}"
        );
        assert!(
            line.contains("smaller subtree"),
            "a warning with no remedy is most of the way back to silence: {line}"
        );
    }

    /// Every subject the coefficients were read off is still floored by them.
    ///
    /// This is the calibration's own guard. Raising either coefficient past a
    /// measured subject turns the projection from a floor into a guess, and a
    /// guess that overstates is how a warning starts firing on conversions
    /// that would have finished.
    #[test]
    fn the_projection_floors_every_measured_subject() {
        for (name, head_artifacts, object_bytes, measured_peak) in MEASURED_SNAPSHOTS {
            let projected = snapshot(head_artifacts, object_bytes).projected_peak_bytes();
            assert!(
                projected <= measured_peak,
                "{name} projected {projected} over a measured peak of {measured_peak}, so the \
                 projection is no longer a floor"
            );
        }
    }

    /// A repository is never projected lower at phase 4 than it was forecast
    /// at phase 1.
    ///
    /// The two run four phases apart on the same conversion, and a second
    /// number that undercut the first would read as the danger having passed.
    /// It has not: the projection adds a term, it does not replace one.
    #[test]
    fn a_repository_is_never_projected_below_its_phase_one_forecast() {
        for (commits, tracked) in [(18_514u64, 1_676u64), (6_493, 130), (200, 40), (1, 18_508)] {
            let forecast = HistorySurvey {
                commits,
                tracked_artifacts: tracked,
            }
            .forecast_peak_bytes();
            let projected = ImportSurvey {
                commits,
                head_artifacts: tracked,
                object_bytes: 0,
            }
            .projected_peak_bytes();
            assert!(
                projected >= forecast,
                "{commits} commits over {tracked} files projected {projected} against a phase-1 \
                 forecast of {forecast}"
            );
        }
    }

    /// A repository large enough to overflow a term saturates high rather
    /// than wrapping to a projection of nothing, which is the direction a
    /// forecast is allowed to be wrong in.
    ///
    /// Each case overflows exactly one term while the others stay small. A
    /// survey that is `u64::MAX` in every field would saturate on the
    /// per-commit term alone and pass with the others wrapping, which is a
    /// test that cannot fail for the code it was written for.
    #[test]
    fn a_projection_large_enough_to_overflow_saturates_high() {
        let by_artifact_count = ImportSurvey {
            commits: 1,
            head_artifacts: 100_000_000_000_000,
            object_bytes: 0,
        };
        assert_eq!(by_artifact_count.projected_peak_bytes(), u64::MAX);
        let by_source_bytes = ImportSurvey {
            commits: 1,
            head_artifacts: 0,
            object_bytes: 1_000_000_000_000_000_000,
        };
        assert_eq!(by_source_bytes.projected_peak_bytes(), u64::MAX);
        assert!(matches!(
            projection_for(by_source_bytes, u64::MAX - 1),
            ImportProjection::Short { .. }
        ));
    }

    /// An operator who told this module its real ceiling is not warned four
    /// phases later with the number they overrode.
    ///
    /// [`INIT_MEMORY_CEILING_ENV`] is this module's only lever and phase 1
    /// honours it. This projection has no lever of its own, so a projection
    /// that read the machine anyway would fire on precisely the operator who
    /// has already answered it, with no way to stop it.
    #[test]
    fn a_raised_ceiling_is_what_this_projection_is_judged_against() {
        let survey = snapshot(18_508, 531_828_795);
        let machine = headroom_for(Ceiling::Bytes(16 * 1000 * 1000 * 1000), 0)
            .expect("a readable ceiling has a headroom");
        assert!(
            projection_for(survey, machine).advisory_line().is_some(),
            "this subject has to be short against the machine before an override can matter"
        );
        let raised = headroom_for(
            Ceiling::Bytes(64 * 1024 * 1024 * 1024),
            8 * 1024 * 1024 * 1024,
        )
        .expect("an operator's ceiling has a headroom");
        assert_eq!(raised, 56 * 1024 * 1024 * 1024);
        assert_eq!(
            projection_for(survey, raised).advisory_line(),
            None,
            "an operator who raised the ceiling past this projection is still being warned by it"
        );
    }

    /// The headroom is the ceiling less what is already charged against it.
    ///
    /// By phase 4 the conversion has spent four phases of memory, so judging a
    /// projection against the whole ceiling would compare a peak against room
    /// that is already gone.
    #[test]
    fn the_headroom_is_the_ceiling_less_what_is_already_charged() {
        assert_eq!(
            headroom_for(Ceiling::Bytes(16_000_000_000), 15_000_000_000),
            Ok(1_000_000_000)
        );
        // A machine charged past its own ceiling has nothing left rather than
        // everything, which is what a wrapping subtraction would report.
        assert_eq!(headroom_for(Ceiling::Bytes(8), 9), Ok(0));
    }

    /// A ceiling this module cannot read projects nothing and says nothing.
    ///
    /// The same discipline as the phase-1 verdict: a check that could not run
    /// leaves the conversion exactly as it was rather than guessing at it.
    #[test]
    fn an_unreadable_ceiling_projects_nothing() {
        assert!(headroom_for(Ceiling::Unreadable("no ceiling here".to_string()), 0).is_err());
        assert!(headroom_for(Ceiling::Invalid("twelve".to_string()), 0).is_err());
        assert_eq!(
            ImportProjection::Unmeasured {
                reason: "no ceiling here".to_string(),
            }
            .advisory_line(),
            None
        );
    }

    fn survey(commits: u64, tracked_artifacts: u64) -> HistorySurvey {
        HistorySurvey {
            commits,
            tracked_artifacts,
        }
    }

    #[test]
    fn a_forecast_over_the_ceiling_refuses() {
        let verdict = verdict_for(survey(40_000, 1_676), 8 * 1024 * 1024 * 1024);
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
    /// operator meets the same dead end the silence left them in, and the
    /// mechanism it names has to be the one the conversion has.
    #[test]
    fn the_refusal_names_the_mechanism_both_remedies_and_the_shallow_dead_end() {
        let verdict = verdict_for(survey(40_000, 1_676), 8 * 1024 * 1024 * 1024);
        let text = verdict.refusal_lines().join("\n");
        assert!(text.contains("40000 commits"), "text was:\n{text}");
        assert!(text.contains("1676 tracked files"), "text was:\n{text}");
        assert!(text.contains("8.0 GB"), "text was:\n{text}");
        assert!(
            text.contains("entity and relation deltas"),
            "the refusal has to name what a conversion holds per commit: {text}"
        );
        assert!(
            !text.contains("one resolved tree per commit"),
            "the refusal names a structure the conversion no longer holds: {text}"
        );
        assert!(text.contains("give it more than"), "text was:\n{text}");
        assert!(
            text.contains("convert a repository with less history"),
            "text was:\n{text}"
        );
        assert!(text.contains("git clone --depth"), "text was:\n{text}");
        assert!(text.contains(INIT_MEMORY_CEILING_ENV), "text was:\n{text}");
        assert!(text.contains("no staging to reclaim"), "text was:\n{text}");
    }

    /// A repository large enough to overflow a term saturates high rather
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
    fn an_overflowing_survey_saturates_instead_of_wrapping() {
        let huge = survey(u64::MAX, u64::MAX);
        assert_eq!(
            huge.forecast_peak_bytes(),
            u64::MAX,
            "the forecast wrapped instead of saturating"
        );
        assert_eq!(
            huge.daemon_load_bytes(),
            u64::MAX,
            "the daemon load wrapped instead of saturating"
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
        let wide = survey(1_000, 5_000).forecast_peak_bytes();
        assert!(
            survey(1_000, 10_000).forecast_peak_bytes() > wide,
            "width did not move a forecast whose width term does win"
        );
    }

    /// The forecast never exceeds what a conversion really held, or it is not
    /// a floor and it will refuse work that would have finished.
    ///
    /// The rows are full `kin init` runs. The first three are the shipped
    /// 0.6.0 inside one Debian 12 container hard-capped at 8 GiB, with the peak
    /// taken by sampling the cgroup's `memory.current` beside the run; the
    /// requests row at the cap held 8,589,705,216 of an 8,589,934,592 cap and
    /// survived, so its reading is the ceiling rather than its demand, and a
    /// floor on the demand is all this assertion needs. The fourth is kin
    /// 0.7.3 on a 128 GB host with the resident set sampled from outside the
    /// process once a second, which is the row [`BYTES_PER_COMMIT`] was read
    /// off, and the last three are the frontier walk itself on the same host
    /// and method, which is what lets this test fail on the binary it ships
    /// in rather than only on a predecessor's. prometheus, 18,514 commits over
    /// 1,676 files, was killed at phase 4 under 0.6.0 on the tree structures
    /// this conversion no longer holds, so it says nothing about this forecast
    /// and is not a row. The per-commit demand across the frontier-walk rows
    /// spans 0.86 MB to 4.5 MB, which is why the coefficient is a floor on
    /// every one of them and a prediction of none.
    #[test]
    fn the_forecast_is_a_floor_on_every_conversion_it_was_measured_against() {
        const CEILING: u64 = 8 * 1024 * 1024 * 1024;
        // (name, commits, tracked files, bytes actually held)
        let measured = [
            ("axum 0.6.0", 1_983_u64, 503_u64, 4_067_635_200_u64),
            ("flask 0.6.0", 5_556, 236, 6_731_427_840),
            ("requests 0.6.0", 6_493, 130, 8_589_705_216),
            ("requests 0.7.3", 6_493, 130, 4_800_708_608),
            // The frontier walk's own bytes, resident set sampled from outside
            // the process once a second on a 128 GB host, without enrichment.
            // requests ran beside its v0.7.3 twin under the same pressure.
            ("requests frontier walk", 6_493, 130, 5_568_004_096),
            ("hiredis frontier walk", 1_141, 79, 1_526_988_800),
            ("kin frontier walk", 2_924, 1_033, 13_266_026_496),
        ];
        for (name, commits, artifacts, held_bytes) in measured {
            let survey = survey(commits, artifacts);
            let forecast = survey.forecast_peak_bytes();
            assert!(
                forecast <= held_bytes,
                "{name}: forecast {forecast} exceeds the {held_bytes} it really held, so the \
                 forecast is not a floor"
            );
            let verdict = verdict_for(survey, CEILING);
            assert!(
                !verdict.refuses(),
                "{name}: converted under 8 GiB and must not be refused there, got {verdict:?}"
            );
        }
    }

    /// The bands separate the measured conversions the way their daemons
    /// separated them.
    ///
    /// Separated from the floor test above because it grades a different
    /// thing: that test proves the forecast never over-claims, this one proves
    /// the thresholds over it are set somewhere useful. A band nothing ever
    /// lands in would pass every assertion above. At an 8 GiB ceiling axum's
    /// store loads under the daemon's half and says nothing; flask's and
    /// requests' load over it and say so, through the daemon band rather than
    /// the conversion band, because on this forecast neither conversion is
    /// itself close to the ceiling.
    #[test]
    fn the_bands_separate_the_measured_conversions() {
        const CEILING: u64 = 8 * 1024 * 1024 * 1024;
        assert!(
            matches!(
                verdict_for(survey(1_983, 503), CEILING),
                BudgetVerdict::Fits { .. }
            ),
            "axum should convert without comment"
        );
        for (name, commits, artifacts) in [("flask", 5_556_u64, 236_u64), ("requests", 6_493, 130)]
        {
            let verdict = verdict_for(survey(commits, artifacts), CEILING);
            assert!(
                matches!(verdict, BudgetVerdict::DaemonAllowance { .. }),
                "{name}'s store loads over the daemon's half of 8 GiB and should say so, got \
                 {verdict:?}"
            );
            assert!(
                verdict
                    .advisory_line()
                    .is_some_and(|line| line.contains("repository daemon")),
                "{name}'s advisory does not name the daemon"
            );
        }
    }

    /// The band the measurement opened: the conversion fits and the daemon
    /// does not.
    ///
    /// psf/requests at 6493 commits over 130 tracked files inside a 12 GiB
    /// container is the exact case that was silent and should not have been.
    /// The conversion completed all seventeen phases there and the repository
    /// daemon was then killed, four times across `kin init` and three
    /// `kin graph status` attempts, on the v0.6.2 candidate bytes.
    #[test]
    fn a_conversion_that_fits_the_machine_but_not_the_daemon_says_so() {
        const CEILING: u64 = 12 * 1024 * 1024 * 1024;
        let survey = survey(6_493, 130);
        let verdict = verdict_for(survey, CEILING);
        assert!(
            matches!(verdict, BudgetVerdict::DaemonAllowance { .. }),
            "requests at a 12 GiB ceiling should speak about the daemon, got {verdict:?}"
        );
        assert!(!verdict.refuses(), "this band warns, it does not refuse");

        // The figures that make the case are all in the sentence, because a
        // reader who is told only one of them cannot see why it applies.
        let line = verdict
            .advisory_line()
            .expect("this band prints its one line");
        for phrase in [
            "repository daemon",
            "is allowed",
            "6493 commits",
            "expected to take about",
        ] {
            assert!(line.contains(phrase), "line was: {line}");
        }
        // And it does not reuse the Tight sentence, whose claim is about the
        // conversion rather than about what runs after it.
        assert!(
            !line.contains("It will probably finish. If the kernel stops it"),
            "the daemon band borrowed the Tight wording: {line}"
        );
    }

    /// The lower edge of the daemon band is the allowance, to the byte.
    ///
    /// Written as a pair rather than as one assertion, because a band whose
    /// floor is never crossed in either direction is a rule nothing exercises.
    #[test]
    fn the_daemon_band_starts_exactly_at_the_allowance() {
        let survey = survey(6_493, 130);
        let load = survey.daemon_load_bytes();
        // A ceiling whose half is exactly the load leaves the daemon room,
        // because the comparison is strictly greater.
        let roomy = load * 2;
        assert_eq!(
            memory_pressure::FootprintBudget::derived_from(roomy),
            load,
            "this test's arithmetic assumes the allowance is half the ceiling here"
        );
        assert!(
            matches!(verdict_for(survey, roomy), BudgetVerdict::Fits { .. }),
            "a ceiling of exactly twice the load should be silent"
        );
        // One byte of allowance less puts the load over it.
        assert!(
            matches!(
                verdict_for(survey, roomy - 2),
                BudgetVerdict::DaemonAllowance { .. }
            ),
            "two bytes below twice the load should speak"
        );
    }

    /// A load no machine size can give the daemon room for is told that,
    /// rather than told to find a bigger machine.
    ///
    /// The derived allowance is capped at [`memory_pressure::DERIVED_BUDGET_CEILING_BYTES`]
    /// regardless of the host, so above that cap "give it more memory" is
    /// advice that cannot work, which is the failure mode this product already
    /// carries a ticket for on its OOM recovery text.
    #[test]
    fn a_load_past_the_allowance_cap_does_not_send_a_reader_to_buy_memory() {
        // Large enough that the load is past the cap, with a ceiling large
        // enough that the conversion itself has room.
        let survey = survey(20_000, 100);
        assert!(
            survey.daemon_load_bytes() > memory_pressure::DERIVED_BUDGET_CEILING_BYTES,
            "this test needs a load past the allowance cap"
        );
        let ceiling = survey.forecast_peak_bytes() * 4;
        let verdict = verdict_for(survey, ceiling);
        let line = verdict
            .advisory_line()
            .expect("this band prints its one line");
        assert!(
            line.contains("no machine size fixes this"),
            "line was: {line}"
        );
        assert!(
            !line.contains("give this"),
            "a capped allowance was still told to find more memory: {line}"
        );
    }

    /// The daemon band does not swallow the silence an ordinary conversion is
    /// owed.
    ///
    /// axum's store loads to about 55 percent of the daemon's half of an 8 GiB
    /// ceiling. That margin is pinned here as well as in the band test above:
    /// a change that widened the daemon rule would make an ordinary conversion
    /// narrate itself, which is the noise TIGHT_FRACTION's own comment exists
    /// to prevent.
    #[test]
    fn the_daemon_band_leaves_an_ordinary_conversion_silent() {
        const CEILING: u64 = 8 * 1024 * 1024 * 1024;
        let survey = survey(1_983, 503);
        let allowance = memory_pressure::FootprintBudget::derived_from(CEILING);
        assert!(
            survey.daemon_load_bytes() < allowance,
            "axum's load must sit under the allowance for this to be silence rather than luck"
        );
        let verdict = verdict_for(survey, CEILING);
        assert!(
            matches!(verdict, BudgetVerdict::Fits { .. }),
            "axum should stay silent, got {verdict:?}"
        );
        assert_eq!(verdict.advisory_line(), None);
    }

    /// A named allowance decides the band, so an operator who gave the daemon
    /// a different share is judged against the share the daemon will have.
    ///
    /// The pair matters more than either half. The same survey and the same
    /// ceiling land in two different verdicts depending only on the allowance,
    /// which is what makes this a real input rather than a value the function
    /// could have derived and ignored.
    #[test]
    fn the_named_allowance_and_not_the_ceiling_decides_the_daemon_band() {
        const CEILING: u64 = 8 * 1024 * 1024 * 1024;
        let survey = survey(1_983, 503);
        let load = survey.daemon_load_bytes();
        assert!(
            matches!(
                verdict_for_with_allowance(survey, CEILING, load + 1),
                BudgetVerdict::Fits { .. }
            ),
            "an allowance above the load leaves the daemon room"
        );
        assert!(
            matches!(
                verdict_for_with_allowance(survey, CEILING, load - 1),
                BudgetVerdict::DaemonAllowance { .. }
            ),
            "an allowance below the load does not"
        );
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
