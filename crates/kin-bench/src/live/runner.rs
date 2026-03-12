use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::BenchmarkArm;
use crate::error::{BenchError, Result};
use crate::metrics::{AssistantRunSource, AssistantTaskRun, BenchmarkSubstrate, DurationMs};

/// A validation check for benchmark task output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Validator {
    /// Output must contain all of these strings (case-insensitive).
    ContainsAll(Vec<String>),
    /// Output must contain at least N of these strings (case-insensitive).
    ContainsAtLeast { required: usize, terms: Vec<String> },
    /// Output must mention at least N file paths from this list.
    MentionsFiles { required: usize, paths: Vec<String> },
}

impl Validator {
    pub fn check(&self, output: &str) -> bool {
        let output_lower = output.to_lowercase();
        match self {
            Validator::ContainsAll(terms) => {
                terms.iter().all(|t| output_lower.contains(&t.to_lowercase()))
            }
            Validator::ContainsAtLeast { required, terms } => {
                let found = terms
                    .iter()
                    .filter(|t| output_lower.contains(&t.to_lowercase()))
                    .count();
                found >= *required
            }
            Validator::MentionsFiles { required, paths } => {
                let found = paths.iter().filter(|p| output.contains(p.as_str())).count();
                found >= *required
            }
        }
    }
}

/// A benchmark task definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveTask {
    pub name: String,
    pub prompt: String,
    #[serde(default)]
    pub validators: Vec<Validator>,
}

/// Result from running a single headless benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRunResult {
    pub assistant_name: String,
    pub model_name: Option<String>,
    pub wall_clock_ms: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub estimated_cost_usd: f64,
    pub output_text: String,
    pub raw_stdout: String,
    pub raw_stderr: String,
    #[serde(default)]
    pub timed_events: Vec<TimedLineEvent>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedLineEvent {
    pub stream: String,
    pub offset_ms: f64,
    pub line: String,
}

impl LiveRunResult {
    /// Validate the output against task validators.
    /// Returns true if all validators pass (or if no validators are defined).
    pub fn validate(&self, validators: &[Validator]) -> bool {
        if validators.is_empty() {
            return self.success;
        }
        self.success && validators.iter().all(|v| v.check(&self.output_text))
    }

    /// Convert to an `AssistantTaskRun` for storage in the benchmark database.
    pub fn into_task_run(self, task_name: &str, arm: BenchmarkArm) -> AssistantTaskRun {
        let substrate = match arm {
            BenchmarkArm::Git => BenchmarkSubstrate::Git,
            BenchmarkArm::KinCompat | BenchmarkArm::KinNative => BenchmarkSubstrate::Kin,
        };

        AssistantTaskRun {
            task_name: task_name.to_string(),
            assistant_name: self.assistant_name,
            model_name: self.model_name,
            substrate,
            duration_ms: DurationMs(self.wall_clock_ms),
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            total_tokens: self.total_tokens,
            estimated_cost_usd: self.estimated_cost_usd,
            first_pass_success: self.success,
            validation_passed: self.success,
            run_source: AssistantRunSource::LiveHarness,
            notes: self.error,
            recorded_at: Utc::now(),
        }
    }
}

/// Default set of live benchmark tasks.
///
/// These tasks are designed to test **cross-file semantic understanding** —
/// the kind of work where a semantic index (kin) provides a real advantage
/// over raw filesystem exploration (grep/find/cat). Each task requires
/// tracing relationships across module boundaries.
pub fn default_live_tasks() -> Vec<LiveTask> {
    vec![
        LiveTask {
            name: "trace-data-flow".to_string(),
            prompt: "Trace the primary data flow through this codebase from the main entry \
                     point to the core processing logic. For each step, name the function, \
                     its file, and what it passes to the next function. Show the full chain."
                .to_string(),
            validators: vec![],
        },
        LiveTask {
            name: "impact-analysis".to_string(),
            prompt: "Pick the most-depended-on type or interface in this codebase. List every \
                     function and module that directly depends on it. Then explain what would \
                     break if you added a required field/parameter to it."
                .to_string(),
            validators: vec![],
        },
        LiveTask {
            name: "cross-module-callers".to_string(),
            prompt: "Find a function that is called from at least 3 different files. Name the \
                     function, list every call site (file + line), and explain whether the \
                     callers use it consistently or if some callers use it differently."
                .to_string(),
            validators: vec![],
        },
    ]
}

/// Which assistant family a binary belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssistantType {
    Claude,
    Codex,
    Gemini,
}

/// A spawned but not-yet-completed benchmark task.
/// Exposes the child PID immediately so callers can register it
/// with a `ResourceMonitor` before waiting for completion.
pub struct SpawnedTask {
    child: std::process::Child,
    start: Instant,
    assistant_type: AssistantType,
    binary_name: String,
}

impl std::fmt::Debug for SpawnedTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnedTask")
            .field("pid", &self.child.id())
            .field("assistant_type", &self.assistant_type)
            .field("binary_name", &self.binary_name)
            .finish()
    }
}

impl SpawnedTask {
    /// Return the OS process ID of the spawned child.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for the child to finish and parse its output into a `LiveRunResult`.
    pub fn wait(self) -> Result<LiveRunResult> {
        let mut child = self.child;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BenchError::Other("child stdout was not piped".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BenchError::Other("child stderr was not piped".to_string()))?;

        let stdout_start = self.start;
        let stderr_start = self.start;
        let stdout_handle = std::thread::spawn(move || collect_stream("stdout", stdout, stdout_start));
        let stderr_handle = std::thread::spawn(move || collect_stream("stderr", stderr, stderr_start));

        let status = child
            .wait()
            .map_err(|e| BenchError::io(&self.binary_name, e))?;
        let wall_clock_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        let exit_success = status.success();

        let (raw_stdout, mut stdout_events) = stdout_handle
            .join()
            .map_err(|_| BenchError::Other("stdout collector thread panicked".to_string()))?;
        let (raw_stderr, mut stderr_events) = stderr_handle
            .join()
            .map_err(|_| BenchError::Other("stderr collector thread panicked".to_string()))?;
        let mut timed_events = Vec::with_capacity(stdout_events.len() + stderr_events.len());
        timed_events.append(&mut stdout_events);
        timed_events.append(&mut stderr_events);
        timed_events.sort_by(|a, b| {
            a.offset_ms
                .partial_cmp(&b.offset_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut result = match self.assistant_type {
            AssistantType::Claude => parse_claude_output(&raw_stdout, wall_clock_ms)?,
            AssistantType::Codex => parse_codex_output(&raw_stdout, wall_clock_ms, exit_success)?,
            AssistantType::Gemini => parse_gemini_output(&raw_stdout, wall_clock_ms, exit_success)?,
        };
        result.raw_stdout = raw_stdout;
        result.raw_stderr = raw_stderr;
        result.timed_events = timed_events;

        Ok(result)
    }
}

fn collect_stream<R: Read>(stream: &str, reader: R, start: Instant) -> (String, Vec<TimedLineEvent>) {
    let mut raw = String::new();
    let mut events = Vec::new();
    let mut buf_reader = BufReader::new(reader);
    let mut line = Vec::new();

    loop {
        line.clear();
        match buf_reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
                let text = String::from_utf8_lossy(&line).to_string();
                raw.push_str(&text);
                let trimmed = text.trim_end_matches(&['\r', '\n'][..]).to_string();
                if !trimmed.is_empty() {
                    events.push(TimedLineEvent {
                        stream: stream.to_string(),
                        offset_ms: start.elapsed().as_secs_f64() * 1000.0,
                        line: trimmed,
                    });
                }
            }
            Err(_) => break,
        }
    }

    (raw, events)
}

/// Detect the assistant type from a binary path.
fn detect_assistant_type(cli_binary: &str) -> Result<AssistantType> {
    let binary_name = Path::new(cli_binary)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    if binary_name.contains("claude") {
        Ok(AssistantType::Claude)
    } else if binary_name.contains("codex") {
        Ok(AssistantType::Codex)
    } else if binary_name.contains("gemini") {
        Ok(AssistantType::Gemini)
    } else {
        Err(BenchError::Other(format!(
            "unsupported CLI binary: {cli_binary}"
        )))
    }
}

fn assistant_arg_for_binary(cli_binary: &str) -> Result<&'static str> {
    let binary_name = Path::new(cli_binary)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    if binary_name.contains("claude") {
        Ok("claude")
    } else if binary_name.contains("codex") {
        Ok("codex")
    } else if binary_name.contains("gemini") {
        Ok("gemini")
    } else {
        Err(BenchError::Other(format!(
            "unsupported CLI binary: {cli_binary}"
        )))
    }
}

/// Build the argument list for a given assistant type and task prompt.
fn build_args(assistant_type: AssistantType, prompt: &str, _cwd: &Path) -> Vec<String> {
    match assistant_type {
        AssistantType::Claude => {
            let args = vec![
                "-p".to_string(),
                prompt.to_string(),
                "--output-format".to_string(),
                "stream-json".to_string(),
                "--include-partial-messages".to_string(),
                "--verbose".to_string(),
                "--setting-sources".to_string(),
                "project,local".to_string(),
                "--strict-mcp-config".to_string(),
                "--permission-mode".to_string(),
                "bypassPermissions".to_string(),
            ];
            args
        }
        AssistantType::Codex => vec![
            "exec".to_string(),
            "--json".to_string(),
            "--ephemeral".to_string(),
            "--dangerously-bypass-approvals-and-sandbox".to_string(),
            prompt.to_string(),
        ],
        AssistantType::Gemini => vec![
            "-p".to_string(),
            prompt.to_string(),
            "--yolo".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
        ],
    }
}

fn build_env_overrides(
    assistant_type: AssistantType,
    env_overrides: &[(&str, &str)],
) -> Vec<(String, String)> {
    env_overrides
        .iter()
        .filter(|(key, _)| {
            if assistant_type == AssistantType::Claude {
                !matches!(*key, "HOME" | "XDG_CONFIG_HOME" | "XDG_DATA_HOME")
            } else {
                true
            }
        })
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

/// Build the task prompt for a given arm.
///
/// Strategy: NO prompt injection. The kin arms have AGENTS.md on disk as a
/// passive reference. The agent gets the exact same task prompt across all arms.
/// This avoids the "double work" problem where injected guidance causes agents
/// to run kin commands ON TOP OF their normal filesystem exploration.
pub fn build_prompt_with_guidance(_arm_name: &str, task_prompt: &str, _arm_dir: &Path) -> String {
    task_prompt.to_string()
}

/// Spawn a benchmark task without waiting for it to complete.
///
/// Returns a [`SpawnedTask`] whose PID can be registered with a
/// `ResourceMonitor` before calling [`SpawnedTask::wait`].
pub fn spawn_task(
    cli_binary: &str,
    task: &LiveTask,
    cwd: &Path,
    env_overrides: &[(&str, &str)],
) -> Result<SpawnedTask> {
    let assistant_type = detect_assistant_type(cli_binary)?;
    let args = build_args(assistant_type, &task.prompt, cwd);
    let env_overrides = build_env_overrides(assistant_type, env_overrides);

    let mut cmd = Command::new(cli_binary);
    cmd.args(&args)
        .current_dir(cwd)
        .envs(env_overrides)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Unset CLAUDECODE so nested Claude Code instances can launch from benchmarks
    cmd.env_remove("CLAUDECODE");

    let child = cmd.spawn()
        .map_err(|e| BenchError::io(cli_binary, e))?;

    Ok(SpawnedTask {
        child,
        start: Instant::now(),
        assistant_type,
        binary_name: cli_binary.to_string(),
    })
}

fn build_kin_with_args(
    assistant_arg: &str,
    task_prompt: &str,
    passive_guidance: bool,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Vec<String> {
    let mut args = vec!["with".to_string(), assistant_arg.to_string()];
    if passive_guidance {
        args.push("--passive-guidance".to_string());
    }
    if restrict_discovery {
        args.push("--restrict-discovery".to_string());
    }
    if restrict_filesystem {
        args.push("--restrict-filesystem".to_string());
    }
    args.push("--".to_string());
    args.push(task_prompt.to_string());
    args
}

/// Spawn a benchmark task through the real `kin with` launcher path.
///
/// This keeps parsing tied to the target assistant while exercising the
/// actual Kin wrapper contract for compat/native arms.
pub fn spawn_task_via_kin_with(
    kin_binary: &Path,
    cli_binary: &str,
    task: &LiveTask,
    cwd: &Path,
    env_overrides: &[(&str, &str)],
    passive_guidance: bool,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<SpawnedTask> {
    let assistant_type = detect_assistant_type(cli_binary)?;
    let assistant_arg = assistant_arg_for_binary(cli_binary)?;
    let args = build_kin_with_args(
        assistant_arg,
        &task.prompt,
        passive_guidance,
        restrict_discovery,
        restrict_filesystem,
    );
    let mut env_overrides = build_env_overrides(assistant_type, env_overrides);
    env_overrides.push(("KIN_BENCHMARK".to_string(), "1".to_string()));

    let mut cmd = Command::new(kin_binary);
    cmd.args(&args)
        .current_dir(cwd)
        .envs(env_overrides)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    cmd.env_remove("CLAUDECODE");

    let child = cmd
        .spawn()
        .map_err(|e| BenchError::io(&kin_binary.display().to_string(), e))?;

    Ok(SpawnedTask {
        child,
        start: Instant::now(),
        assistant_type,
        binary_name: cli_binary.to_string(),
    })
}

/// Run a benchmark task using the specified CLI.
pub fn run_task(
    cli_binary: &str,
    task: &LiveTask,
    cwd: &Path,
    env_overrides: &[(&str, &str)],
) -> Result<LiveRunResult> {
    spawn_task(cli_binary, task, cwd, env_overrides)?.wait()
}

/// Run a benchmark task, returning both the result and the child PID.
pub fn run_task_with_pid(
    cli_binary: &str,
    task: &LiveTask,
    cwd: &Path,
    env_overrides: &[(&str, &str)],
) -> Result<(LiveRunResult, u32)> {
    let spawned = spawn_task(cli_binary, task, cwd, env_overrides)?;
    let pid = spawned.pid();
    let result = spawned.wait()?;
    Ok((result, pid))
}

/// Parse Claude Code JSON output.
fn parse_claude_output(stdout: &str, wall_clock_ms: f64) -> Result<LiveRunResult> {
    let v = if let Ok(direct) = serde_json::from_str::<Value>(stdout) {
        direct
    } else {
        let mut result_event: Option<Value> = None;
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(candidate) = serde_json::from_str::<Value>(line) {
                if candidate.get("type").and_then(|t| t.as_str()) == Some("result") {
                    result_event = Some(candidate);
                }
            }
        }
        result_event.ok_or_else(|| {
            BenchError::Other("failed to parse claude output: expected JSON object or stream-json result event".to_string())
        })?
    };

    let (model, total_input_tokens, output_tokens, model_cost_usd) =
        summarize_claude_model_usage(&v);

    let top_level_input_tokens = v
        .pointer("/usage/input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let top_level_cache_creation_input_tokens = v
        .pointer("/usage/cache_creation_input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let top_level_cache_read_input_tokens = v
        .pointer("/usage/cache_read_input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let top_level_output_tokens = v
        .pointer("/usage/output_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let fallback_total_input_tokens = top_level_input_tokens
        + top_level_cache_creation_input_tokens
        + top_level_cache_read_input_tokens;
    let total_input_tokens = if total_input_tokens > 0 {
        total_input_tokens
    } else {
        fallback_total_input_tokens
    };
    let output_tokens = if output_tokens > 0 {
        output_tokens
    } else {
        top_level_output_tokens
    };

    let cost_usd = v
        .get("total_cost_usd")
        .or_else(|| v.get("cost_usd"))
        .and_then(|v| v.as_f64())
        .or(model_cost_usd)
        .unwrap_or(0.0);

    let duration_ms = v
        .get("duration_ms")
        .and_then(|v| v.as_f64())
        .unwrap_or(wall_clock_ms);

    let result_text = v
        .get("result")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();

    let is_error = v
        .get("is_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(LiveRunResult {
        assistant_name: "Claude Code".to_string(),
        model_name: model,
        wall_clock_ms: duration_ms,
        input_tokens: total_input_tokens,
        output_tokens,
        total_tokens: total_input_tokens + output_tokens,
        estimated_cost_usd: cost_usd,
        output_text: result_text,
        raw_stdout: String::new(),
        raw_stderr: String::new(),
        timed_events: Vec::new(),
        success: !is_error,
        error: if is_error {
            Some("claude reported is_error=true".to_string())
        } else {
            None
        },
    })
}

fn summarize_claude_model_usage(v: &Value) -> (Option<String>, u64, u64, Option<f64>) {
    let Some(model_usage) = v.get("modelUsage").and_then(|m| m.as_object()) else {
        return (
            v.get("model")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string()),
            0,
            0,
            None,
        );
    };

    let mut names: Vec<String> = model_usage.keys().cloned().collect();
    names.sort();

    let model_name = if names.is_empty() {
        v.get("model")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string())
    } else if names.len() == 1 {
        Some(names[0].clone())
    } else {
        Some(format!("{} (+{} more)", names[0], names.len() - 1))
    };

    let mut total_input_tokens = 0u64;
    let mut total_output_tokens = 0u64;
    let mut total_cost_usd = 0.0f64;
    let mut saw_cost = false;

    for model in model_usage.values() {
        total_input_tokens += model
            .get("inputTokens")
            .or_else(|| model.get("input_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        total_input_tokens += model
            .get("cacheReadInputTokens")
            .or_else(|| model.get("cache_read_input_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        total_input_tokens += model
            .get("cacheCreationInputTokens")
            .or_else(|| model.get("cache_creation_input_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        total_output_tokens += model
            .get("outputTokens")
            .or_else(|| model.get("output_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if let Some(cost) = model
            .get("costUSD")
            .or_else(|| model.get("cost_usd"))
            .and_then(|v| v.as_f64())
        {
            total_cost_usd += cost;
            saw_cost = true;
        }
    }

    (
        model_name,
        total_input_tokens,
        total_output_tokens,
        if saw_cost { Some(total_cost_usd) } else { None },
    )
}

/// Parse Codex JSONL output for token counts and result.
fn parse_codex_output(stdout: &str, wall_clock_ms: f64, exit_success: bool) -> Result<LiveRunResult> {
    let mut input_tokens: u64 = 0;
    let mut output_tokens: u64 = 0;
    let mut result_text = String::new();
    let mut model_name: Option<String> = None;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            // Look for token_count events
            let event_type = v.get("type").and_then(|t| t.as_str()).unwrap_or("");

            if event_type == "token_count" || v.get("input_tokens").is_some() {
                input_tokens += v
                    .get("input_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                output_tokens += v
                    .get("output_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
            }

            if event_type == "turn.completed" {
                let usage = v.get("usage").unwrap_or(&Value::Null);
                let uncached_input = usage
                    .get("input_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                let cached_input = usage
                    .get("cached_input_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                let completed_output = usage
                    .get("output_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                if uncached_input > 0 || cached_input > 0 || completed_output > 0 {
                    input_tokens = uncached_input + cached_input;
                    output_tokens = completed_output;
                }
            }

            if event_type == "message" || v.get("content").is_some() {
                if let Some(content) = v.get("content").and_then(|c| c.as_str()) {
                    if !result_text.is_empty() {
                        result_text.push('\n');
                    }
                    result_text.push_str(content);
                }
            }

            if model_name.is_none() {
                model_name = v.get("model").and_then(|m| m.as_str()).map(|s| s.to_string());
            }
        }
    }

    // If no structured output, use raw stdout
    if result_text.is_empty() {
        result_text = stdout.to_string();
    }

    Ok(LiveRunResult {
        assistant_name: "Codex".to_string(),
        model_name,
        wall_clock_ms,
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
        estimated_cost_usd: 0.0, // Codex doesn't report cost directly
        output_text: result_text,
        raw_stdout: String::new(),
        raw_stderr: String::new(),
        timed_events: Vec::new(),
        success: exit_success,
        error: if exit_success {
            None
        } else {
            Some("codex exited with non-zero status".to_string())
        },
    })
}

/// Parse Gemini CLI JSON output for token counts from stats.models.
fn parse_gemini_output(stdout: &str, wall_clock_ms: f64, exit_success: bool) -> Result<LiveRunResult> {
    let v: Value = serde_json::from_str(stdout).map_err(|e| {
        BenchError::Other(format!("failed to parse gemini output as JSON: {e}"))
    })?;

    let mut input_tokens: u64 = 0;
    let mut output_tokens: u64 = 0;
    let mut model_name: Option<String> = None;
    let mut total_latency_ms: f64 = 0.0;

    // Parse stats.models array
    if let Some(models) = v.pointer("/stats/models").and_then(|m| m.as_array()) {
        for model in models {
            input_tokens += model
                .get("input_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            output_tokens += model
                .get("output_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            total_latency_ms += model
                .get("latency_ms")
                .and_then(|l| l.as_f64())
                .unwrap_or(0.0);

            if model_name.is_none() {
                model_name = model
                    .get("model_name")
                    .or_else(|| model.get("model"))
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string());
            }
        }
    }

    let result_text = v
        .get("result")
        .or_else(|| v.get("response"))
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();

    // Use model-reported latency if available, otherwise wall clock
    let duration = if total_latency_ms > 0.0 {
        total_latency_ms
    } else {
        wall_clock_ms
    };

    Ok(LiveRunResult {
        assistant_name: "Gemini CLI".to_string(),
        model_name,
        wall_clock_ms: duration,
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
        estimated_cost_usd: 0.0, // Gemini doesn't report cost directly
        output_text: result_text,
        raw_stdout: String::new(),
        raw_stderr: String::new(),
        timed_events: Vec::new(),
        success: exit_success,
        error: if exit_success {
            None
        } else {
            Some("gemini exited with non-zero status".to_string())
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tasks_has_expected_count() {
        let tasks = default_live_tasks();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0].name, "trace-data-flow");
        assert_eq!(tasks[2].name, "cross-module-callers");
    }

    #[test]
    fn live_task_serialization_roundtrip() {
        let task = LiveTask {
            name: "test-task".to_string(),
            prompt: "Do something".to_string(),
            validators: vec![],
        };
        let json = serde_json::to_string(&task).unwrap();
        let parsed: LiveTask = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test-task");
        assert_eq!(parsed.prompt, "Do something");
    }

    #[test]
    fn parse_claude_output_success() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "usage": {
                "input_tokens": 1200,
                "output_tokens": 800
            },
            "total_cost_usd": 0.15,
            "duration_ms": 5400.0,
            "result": "Here are the functions I found...",
            "is_error": false
        }"#;

        let result = parse_claude_output(json, 6000.0).unwrap();
        assert_eq!(result.assistant_name, "Claude Code");
        assert_eq!(result.model_name, Some("claude-sonnet-4-20250514".to_string()));
        assert_eq!(result.input_tokens, 1200);
        assert_eq!(result.output_tokens, 800);
        assert_eq!(result.total_tokens, 2000);
        assert!((result.estimated_cost_usd - 0.15).abs() < f64::EPSILON);
        assert!((result.wall_clock_ms - 5400.0).abs() < f64::EPSILON);
        assert!(result.success);
        assert!(result.error.is_none());
        assert!(result.output_text.contains("functions I found"));
    }

    #[test]
    fn parse_claude_output_error() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "usage": {"input_tokens": 100, "output_tokens": 0},
            "result": "Error occurred",
            "is_error": true
        }"#;

        let result = parse_claude_output(json, 1000.0).unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn parse_claude_output_missing_fields_uses_defaults() {
        let json = r#"{
            "result": "some output"
        }"#;

        let result = parse_claude_output(json, 3000.0).unwrap();
        assert_eq!(result.model_name, None);
        assert_eq!(result.input_tokens, 0);
        assert_eq!(result.output_tokens, 0);
        assert!((result.estimated_cost_usd - 0.0).abs() < f64::EPSILON);
        // Falls back to wall_clock_ms when duration_ms is missing
        assert!((result.wall_clock_ms - 3000.0).abs() < f64::EPSILON);
        assert!(result.success);
    }

    #[test]
    fn parse_claude_output_counts_cache_tokens() {
        let json = r#"{
            "usage": {
                "input_tokens": 14,
                "cache_creation_input_tokens": 9299,
                "cache_read_input_tokens": 118312,
                "output_tokens": 1386
            },
            "result": "done",
            "is_error": false
        }"#;

        let result = parse_claude_output(json, 1000.0).unwrap();
        assert_eq!(result.input_tokens, 127625);
        assert_eq!(result.output_tokens, 1386);
        assert_eq!(result.total_tokens, 129011);
    }

    #[test]
    fn parse_claude_output_falls_back_to_model_usage_key() {
        let json = r#"{
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5
            },
            "modelUsage": {
                "claude-opus-4-6": {
                    "inputTokens": 10,
                    "outputTokens": 5
                }
            },
            "result": "ok"
        }"#;

        let result = parse_claude_output(json, 1000.0).unwrap();
        assert_eq!(result.model_name, Some("claude-opus-4-6".to_string()));
    }

    #[test]
    fn parse_claude_output_prefers_full_model_usage_totals() {
        let json = r#"{
            "usage": {
                "input_tokens": 4,
                "cache_creation_input_tokens": 8027,
                "cache_read_input_tokens": 24389,
                "output_tokens": 744
            },
            "modelUsage": {
                "claude-opus-4-6": {
                    "inputTokens": 4,
                    "outputTokens": 744,
                    "cacheReadInputTokens": 24389,
                    "cacheCreationInputTokens": 8027,
                    "costUSD": 0.08098325
                },
                "claude-haiku-4-5-20251001": {
                    "inputTokens": 33,
                    "outputTokens": 1688,
                    "cacheReadInputTokens": 99763,
                    "cacheCreationInputTokens": 4878,
                    "costUSD": 0.0245468
                }
            },
            "result": "done",
            "is_error": false
        }"#;

        let result = parse_claude_output(json, 1000.0).unwrap();
        assert_eq!(
            result.model_name,
            Some("claude-haiku-4-5-20251001 (+1 more)".to_string())
        );
        assert_eq!(result.input_tokens, 137094);
        assert_eq!(result.output_tokens, 2432);
        assert_eq!(result.total_tokens, 139526);
        assert!((result.estimated_cost_usd - 0.10553005).abs() < 1e-9);
    }

    #[test]
    fn summarize_claude_model_usage_supports_snake_case_fields() {
        let v: Value = serde_json::from_str(
            r#"{
                "modelUsage": {
                    "claude-opus-4-6": {
                        "input_tokens": 10,
                        "output_tokens": 5,
                        "cache_read_input_tokens": 100,
                        "cache_creation_input_tokens": 20,
                        "cost_usd": 0.12
                    }
                }
            }"#,
        )
        .unwrap();

        let (model, input, output, cost) = summarize_claude_model_usage(&v);
        assert_eq!(model, Some("claude-opus-4-6".to_string()));
        assert_eq!(input, 130);
        assert_eq!(output, 5);
        assert!((cost.unwrap() - 0.12).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_codex_output_jsonl() {
        let jsonl = r#"{"type": "token_count", "input_tokens": 500, "output_tokens": 300, "model": "o3-mini"}
{"type": "message", "content": "Found these functions..."}
{"type": "token_count", "input_tokens": 200, "output_tokens": 100}
"#;

        let result = parse_codex_output(jsonl, 4000.0, true).unwrap();
        assert_eq!(result.assistant_name, "Codex");
        assert_eq!(result.model_name, Some("o3-mini".to_string()));
        assert_eq!(result.input_tokens, 700);
        assert_eq!(result.output_tokens, 400);
        assert_eq!(result.total_tokens, 1100);
        assert!(result.success);
        assert!(result.output_text.contains("Found these functions"));
    }

    #[test]
    fn parse_codex_output_turn_completed_usage() {
        let jsonl = r#"{"type":"thread.started","thread_id":"123"}
{"type":"item.completed","item":{"type":"agent_message","text":"hello"}}
{"type":"turn.completed","usage":{"input_tokens":1000,"cached_input_tokens":2000,"output_tokens":250},"model":"gpt-5.4"}"#;

        let result = parse_codex_output(jsonl, 4000.0, true).unwrap();
        assert_eq!(result.input_tokens, 3000);
        assert_eq!(result.output_tokens, 250);
        assert_eq!(result.total_tokens, 3250);
    }

    #[test]
    fn parse_codex_output_plain_text_fallback() {
        let plain = "Just some plain text output\nwith multiple lines\n";

        let result = parse_codex_output(plain, 2000.0, true).unwrap();
        assert_eq!(result.input_tokens, 0);
        assert_eq!(result.output_tokens, 0);
        assert!(result.output_text.contains("Just some plain text"));
        assert!(result.success);
    }

    #[test]
    fn parse_codex_output_failure() {
        let result = parse_codex_output("error output", 1000.0, false).unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn parse_gemini_output_with_stats() {
        let json = r#"{
            "result": "Architecture analysis complete.",
            "stats": {
                "models": [
                    {
                        "model_name": "gemini-2.5-pro",
                        "input_tokens": 2000,
                        "output_tokens": 1500,
                        "latency_ms": 8000.0
                    }
                ]
            }
        }"#;

        let result = parse_gemini_output(json, 9000.0, true).unwrap();
        assert_eq!(result.assistant_name, "Gemini CLI");
        assert_eq!(result.model_name, Some("gemini-2.5-pro".to_string()));
        assert_eq!(result.input_tokens, 2000);
        assert_eq!(result.output_tokens, 1500);
        assert_eq!(result.total_tokens, 3500);
        assert!((result.wall_clock_ms - 8000.0).abs() < f64::EPSILON);
        assert!(result.success);
        assert!(result.output_text.contains("Architecture analysis"));
    }

    #[test]
    fn parse_gemini_output_multiple_models() {
        let json = r#"{
            "result": "Done.",
            "stats": {
                "models": [
                    {"model_name": "gemini-2.5-pro", "input_tokens": 1000, "output_tokens": 500, "latency_ms": 3000.0},
                    {"model": "gemini-2.5-flash", "input_tokens": 500, "output_tokens": 200, "latency_ms": 1000.0}
                ]
            }
        }"#;

        let result = parse_gemini_output(json, 5000.0, true).unwrap();
        assert_eq!(result.input_tokens, 1500);
        assert_eq!(result.output_tokens, 700);
        // Model name from first entry
        assert_eq!(result.model_name, Some("gemini-2.5-pro".to_string()));
        // Total latency from both models
        assert!((result.wall_clock_ms - 4000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_gemini_output_no_stats_uses_wall_clock() {
        let json = r#"{"result": "Output text"}"#;

        let result = parse_gemini_output(json, 7000.0, true).unwrap();
        assert!((result.wall_clock_ms - 7000.0).abs() < f64::EPSILON);
        assert_eq!(result.input_tokens, 0);
    }

    #[test]
    fn parse_gemini_output_failure() {
        let json = r#"{"result": "failed"}"#;

        let result = parse_gemini_output(json, 1000.0, false).unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn into_task_run_git_arm() {
        let result = LiveRunResult {
            assistant_name: "Claude Code".to_string(),
            model_name: Some("opus".to_string()),
            wall_clock_ms: 5000.0,
            input_tokens: 1000,
            output_tokens: 500,
            total_tokens: 1500,
            estimated_cost_usd: 0.10,
            output_text: "output".to_string(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            timed_events: Vec::new(),
            success: true,
            error: None,
        };

        let run = result.into_task_run("search-functions", BenchmarkArm::Git);
        assert_eq!(run.task_name, "search-functions");
        assert_eq!(run.substrate, BenchmarkSubstrate::Git);
        assert_eq!(run.run_source, AssistantRunSource::LiveHarness);
        assert!(run.first_pass_success);
    }

    #[test]
    fn into_task_run_kin_arm() {
        let result = LiveRunResult {
            assistant_name: "Codex".to_string(),
            model_name: None,
            wall_clock_ms: 3000.0,
            input_tokens: 800,
            output_tokens: 400,
            total_tokens: 1200,
            estimated_cost_usd: 0.0,
            output_text: "result".to_string(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            timed_events: Vec::new(),
            success: false,
            error: Some("failed".to_string()),
        };

        let run = result.into_task_run("explain-architecture", BenchmarkArm::KinNative);
        assert_eq!(run.substrate, BenchmarkSubstrate::Kin);
        assert!(!run.first_pass_success);
        assert!(run.notes.is_some());
    }

    #[test]
    fn into_task_run_kin_compat_maps_to_kin_substrate() {
        let result = LiveRunResult {
            assistant_name: "Gemini CLI".to_string(),
            model_name: None,
            wall_clock_ms: 1000.0,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            estimated_cost_usd: 0.0,
            output_text: String::new(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            timed_events: Vec::new(),
            success: true,
            error: None,
        };

        let run = result.into_task_run("test", BenchmarkArm::KinCompat);
        assert_eq!(run.substrate, BenchmarkSubstrate::Kin);
    }

    #[test]
    fn run_task_rejects_unknown_binary() {
        let task = LiveTask {
            name: "test".to_string(),
            prompt: "hello".to_string(),
            validators: vec![],
        };
        let result = run_task("unknown-binary", &task, Path::new("/tmp"), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn run_task_with_empty_env_overrides() {
        let task = LiveTask {
            name: "test".to_string(),
            prompt: "hello".to_string(),
            validators: vec![],
        };
        // Verify that passing empty env_overrides still works for the dispatch logic
        // (will fail on unknown binary, confirming the param is threaded through)
        let result = run_task("unknown-binary", &task, Path::new("/tmp"), &[]);
        assert!(result.is_err());

        let result_with_pid = run_task_with_pid("unknown-binary", &task, Path::new("/tmp"), &[]);
        assert!(result_with_pid.is_err());
    }

    #[test]
    fn live_run_result_serialization_roundtrip() {
        let result = LiveRunResult {
            assistant_name: "Claude Code".to_string(),
            model_name: Some("opus".to_string()),
            wall_clock_ms: 5000.0,
            input_tokens: 1000,
            output_tokens: 500,
            total_tokens: 1500,
            estimated_cost_usd: 0.10,
            output_text: "some output".to_string(),
            raw_stdout: "raw stdout content".to_string(),
            raw_stderr: "raw stderr content".to_string(),
            timed_events: Vec::new(),
            success: true,
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: LiveRunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.assistant_name, "Claude Code");
        assert_eq!(parsed.total_tokens, 1500);
        assert_eq!(parsed.raw_stdout, "raw stdout content");
        assert_eq!(parsed.raw_stderr, "raw stderr content");
        assert!(parsed.success);
    }

    #[test]
    fn live_run_result_raw_fields_default_empty_from_parsers() {
        // Verify that parse functions initialize raw_stdout/raw_stderr as empty
        // (callers fill them in after parsing)
        let json = r#"{"result": "test"}"#;
        let result = parse_claude_output(json, 1000.0).unwrap();
        assert!(result.raw_stdout.is_empty());
        assert!(result.raw_stderr.is_empty());

        let result = parse_codex_output("test", 1000.0, true).unwrap();
        assert!(result.raw_stdout.is_empty());
        assert!(result.raw_stderr.is_empty());

        let result = parse_gemini_output(json, 1000.0, true).unwrap();
        assert!(result.raw_stdout.is_empty());
        assert!(result.raw_stderr.is_empty());
    }

    #[test]
    fn spawn_task_rejects_unknown_binary() {
        let task = LiveTask {
            name: "test".to_string(),
            prompt: "hello".to_string(),
            validators: vec![],
        };
        let result = spawn_task("unknown-binary", &task, Path::new("/tmp"), &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsupported CLI binary"));
    }

    #[test]
    fn assistant_arg_for_binary_maps_known_clis() {
        assert_eq!(assistant_arg_for_binary("claude").unwrap(), "claude");
        assert_eq!(assistant_arg_for_binary("codex").unwrap(), "codex");
        assert_eq!(assistant_arg_for_binary("gemini").unwrap(), "gemini");
    }

    #[test]
    fn build_kin_with_args_can_be_passive_and_restrictive() {
        let args = build_kin_with_args("codex", "trace flow", true, true, false);
        assert_eq!(
            args,
            vec![
                "with".to_string(),
                "codex".to_string(),
                "--passive-guidance".to_string(),
                "--restrict-discovery".to_string(),
                "--".to_string(),
                "trace flow".to_string(),
            ]
        );
    }

    #[test]
    fn build_kin_with_args_can_restrict_full_filesystem() {
        let args = build_kin_with_args("gemini", "find auth", true, false, true);
        assert_eq!(
            args,
            vec![
                "with".to_string(),
                "gemini".to_string(),
                "--passive-guidance".to_string(),
                "--restrict-filesystem".to_string(),
                "--".to_string(),
                "find auth".to_string(),
            ]
        );
    }

    #[test]
    fn build_args_claude_uses_strict_project_settings() {
        let dir = tempfile::tempdir().unwrap();

        let args = build_args(AssistantType::Claude, "Say hi", dir.path());
        assert!(args.contains(&"--setting-sources".to_string()));
        assert!(args.contains(&"project,local".to_string()));
        assert!(args.contains(&"--strict-mcp-config".to_string()));
        assert!(args.contains(&"--permission-mode".to_string()));
        assert!(args.contains(&"bypassPermissions".to_string()));
        assert!(args.contains(&"--verbose".to_string()));
        assert!(args.contains(&"stream-json".to_string()));
    }

    #[test]
    fn build_args_codex_requests_json_output() {
        let args = build_args(AssistantType::Codex, "Say hi", Path::new("."));
        assert!(args.contains(&"--json".to_string()));
    }

    #[test]
    fn build_env_overrides_claude_keeps_auth_but_not_isolated_home() {
        let env = build_env_overrides(
            AssistantType::Claude,
            &[
                ("HOME", "/tmp/isolated"),
                ("XDG_CONFIG_HOME", "/tmp/isolated/.config"),
                ("OPENAI_API_KEY", "secret"),
            ],
        );

        assert!(!env.iter().any(|(key, _)| key == "HOME"));
        assert!(!env.iter().any(|(key, _)| key == "XDG_CONFIG_HOME"));
        assert!(env.iter().any(|(key, value)| key == "OPENAI_API_KEY" && value == "secret"));
    }

    #[test]
    fn validator_contains_all_passes() {
        let v = Validator::ContainsAll(vec!["foo".to_string(), "bar".to_string()]);
        assert!(v.check("this has foo and bar in it"));
        assert!(!v.check("this has foo but not the other"));
    }

    #[test]
    fn validator_contains_at_least_passes() {
        let v = Validator::ContainsAtLeast {
            required: 2,
            terms: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };
        assert!(v.check("has a and b"));
        assert!(!v.check("has only a"));
    }

    #[test]
    fn validator_case_insensitive() {
        let v = Validator::ContainsAll(vec!["SaveDocument".to_string()]);
        assert!(v.check("found savedocument in the code"));
    }

    #[test]
    fn validator_mentions_files() {
        let v = Validator::MentionsFiles {
            required: 2,
            paths: vec![
                "src/main.rs".to_string(),
                "src/lib.rs".to_string(),
                "src/utils.rs".to_string(),
            ],
        };
        assert!(v.check("found src/main.rs and src/lib.rs"));
        assert!(!v.check("found src/main.rs only"));
    }

    #[test]
    fn validate_empty_validators_uses_success() {
        let result = LiveRunResult {
            assistant_name: "test".to_string(),
            model_name: None,
            wall_clock_ms: 100.0,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            estimated_cost_usd: 0.0,
            output_text: "anything".to_string(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            timed_events: Vec::new(),
            success: true,
            error: None,
        };
        assert!(result.validate(&[]));

        let failed = LiveRunResult {
            success: false,
            ..result.clone()
        };
        assert!(!failed.validate(&[]));
    }

    #[test]
    fn validate_fails_when_not_success() {
        let result = LiveRunResult {
            assistant_name: "test".to_string(),
            model_name: None,
            wall_clock_ms: 100.0,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            estimated_cost_usd: 0.0,
            output_text: "foo bar".to_string(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            timed_events: Vec::new(),
            success: false,
            error: Some("process failed".to_string()),
        };
        let validators = vec![Validator::ContainsAll(vec!["foo".to_string()])];
        assert!(!result.validate(&validators));
    }

    #[test]
    fn validate_passes_with_matching_output() {
        let result = LiveRunResult {
            assistant_name: "test".to_string(),
            model_name: None,
            wall_clock_ms: 100.0,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            estimated_cost_usd: 0.0,
            output_text: "found saveDocument and loadDocuments".to_string(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            timed_events: Vec::new(),
            success: true,
            error: None,
        };
        let validators = vec![Validator::ContainsAtLeast {
            required: 2,
            terms: vec![
                "saveDocument".to_string(),
                "loadDocuments".to_string(),
                "deleteDocument".to_string(),
            ],
        }];
        assert!(result.validate(&validators));
    }
}
