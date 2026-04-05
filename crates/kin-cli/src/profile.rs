// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, Networks, ProcessRefreshKind, ProcessesToUpdate,
    RefreshKind, System,
};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

const DEFAULT_RESOURCE_SAMPLE_MS: u64 = 250;

#[derive(Clone)]
pub struct ProfileSession {
    inner: Arc<Mutex<ProfileState>>,
    output_path: PathBuf,
    sampler: Arc<SamplerControl>,
}

struct SamplerControl {
    stop: AtomicBool,
    handle: Mutex<Option<JoinHandle<()>>>,
    sample_interval_ms: u64,
}

impl std::fmt::Debug for SamplerControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamplerControl")
            .field("sample_interval_ms", &self.sample_interval_ms)
            .field("stop", &self.stop.load(Ordering::Relaxed))
            .finish()
    }
}

impl std::fmt::Debug for ProfileSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileSession")
            .field("output_path", &self.output_path)
            .field("sampler", &self.sampler)
            .finish()
    }
}

#[derive(Debug)]
struct ProfileState {
    command: String,
    cwd: String,
    pid: u32,
    started_at: SystemTime,
    started_mono: Instant,
    next_span_id: u64,
    spans: BTreeMap<u64, SpanRecord>,
    resource_host: Option<ProfileResourceHost>,
    resource_samples: Vec<ResourceSampleRecord>,
}

#[derive(Debug, Clone)]
struct SpanRecord {
    id: u64,
    parent_id: Option<u64>,
    name: String,
    target: String,
    level: String,
    started_ms: f64,
    ended_ms: Option<f64>,
    fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
struct ResourceSampleRecord {
    sample_ms: f64,
    process_cpu_percent: Option<f64>,
    system_cpu_percent: Option<f64>,
    per_core_cpu_percent: Vec<f64>,
    process_memory_bytes: Option<u64>,
    process_virtual_memory_bytes: Option<u64>,
    thread_count: Option<u64>,
    system_total_memory_bytes: u64,
    system_used_memory_bytes: u64,
    system_available_memory_bytes: u64,
    system_total_swap_bytes: u64,
    system_used_swap_bytes: u64,
    system_network_rx_bytes: u64,
    system_network_tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    pub format: &'static str,
    pub command: String,
    pub cwd: String,
    pub pid: u32,
    pub started_at: String,
    pub total_ms: f64,
    pub span_count: usize,
    pub spans: Vec<ProfileSpan>,
    pub summary: ProfileSummary,
    pub resources: ProfileResources,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileSpan {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub path: String,
    pub name: String,
    pub target: String,
    pub level: String,
    pub started_ms: f64,
    pub ended_ms: f64,
    pub duration_ms: f64,
    pub self_ms: f64,
    pub fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileSummary {
    pub hot_paths: Vec<ProfileHotPath>,
    pub slowest_spans: Vec<ProfileSlowSpan>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileHotPath {
    pub path: String,
    pub count: usize,
    pub total_ms: f64,
    pub self_ms: f64,
    pub avg_ms: f64,
    pub avg_self_ms: f64,
    pub max_ms: f64,
    pub max_self_ms: f64,
    pub slowest_span_id: u64,
    pub slowest_self_span_id: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileSlowSpan {
    pub id: u64,
    pub path: String,
    pub duration_ms: f64,
    pub self_ms: f64,
    pub started_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileResources {
    pub host: Option<ProfileResourceHost>,
    pub sample_interval_ms: u64,
    pub samples: Vec<ProfileResourceSample>,
    pub summary: ProfileResourceSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileResourceHost {
    pub os: String,
    pub arch: String,
    pub logical_cores: usize,
    pub cpu_name: Option<String>,
    pub cpu_brand: Option<String>,
    pub gpu_devices: Vec<ProfileGpuDevice>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileGpuDevice {
    pub name: String,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub core_count: Option<u64>,
    pub backend: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileResourceSample {
    pub sample_ms: f64,
    pub active_path: Option<String>,
    pub process_cpu_percent: Option<f64>,
    pub system_cpu_percent: Option<f64>,
    pub per_core_cpu_percent: Vec<f64>,
    pub process_memory_bytes: Option<u64>,
    pub process_virtual_memory_bytes: Option<u64>,
    pub thread_count: Option<u64>,
    pub system_total_memory_bytes: u64,
    pub system_used_memory_bytes: u64,
    pub system_available_memory_bytes: u64,
    pub system_total_swap_bytes: u64,
    pub system_used_swap_bytes: u64,
    pub system_network_rx_bytes: u64,
    pub system_network_tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileResourceSummary {
    pub sample_count: usize,
    pub peak_process_cpu_percent: f64,
    pub peak_system_cpu_percent: f64,
    pub peak_process_memory_bytes: u64,
    pub peak_thread_count: Option<u64>,
    pub total_system_network_rx_bytes: u64,
    pub total_system_network_tx_bytes: u64,
    pub hot_paths: Vec<ProfileResourceHotPath>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileResourceHotPath {
    pub path: String,
    pub sample_count: usize,
    pub approx_cpu_ms: f64,
    pub avg_process_cpu_percent: f64,
    pub peak_process_cpu_percent: f64,
    pub avg_process_memory_bytes: u64,
    pub peak_process_memory_bytes: u64,
    pub peak_thread_count: Option<u64>,
    pub total_system_network_rx_bytes: u64,
    pub total_system_network_tx_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ProfilingLayer {
    session: ProfileSession,
}

#[derive(Debug, Clone, Copy)]
struct ProfileSpanId(u64);

#[derive(Debug, Clone)]
struct ResourceHotPathAccumulator {
    path: String,
    sample_count: usize,
    approx_cpu_ms: f64,
    total_process_cpu_percent: f64,
    peak_process_cpu_percent: f64,
    total_process_memory_bytes: u128,
    process_memory_samples: usize,
    peak_process_memory_bytes: u64,
    peak_thread_count: Option<u64>,
    total_system_network_rx_bytes: u64,
    total_system_network_tx_bytes: u64,
}

impl ProfileSession {
    pub fn new(command: impl Into<String>, cwd: impl Into<String>, output_path: PathBuf) -> Self {
        let sample_interval_ms = configured_sample_interval_ms();
        let session = Self {
            inner: Arc::new(Mutex::new(ProfileState {
                command: command.into(),
                cwd: cwd.into(),
                pid: std::process::id(),
                started_at: SystemTime::now(),
                started_mono: Instant::now(),
                next_span_id: 1,
                spans: BTreeMap::new(),
                resource_host: None,
                resource_samples: Vec::new(),
            })),
            output_path,
            sampler: Arc::new(SamplerControl {
                stop: AtomicBool::new(false),
                handle: Mutex::new(None),
                sample_interval_ms,
            }),
        };
        session.start_resource_sampler();
        session
    }

    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    pub fn report(&self) -> ProfileReport {
        let state = self.inner.lock().expect("profile state poisoned");
        build_report(&state, self.sampler.sample_interval_ms)
    }

    pub fn write_report(&self) -> anyhow::Result<ProfileReport> {
        self.stop_sampler();
        let report = self.report();
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.output_path, serde_json::to_vec_pretty(&report)?)?;
        Ok(report)
    }

    pub fn render_summary(&self, limit: usize) -> String {
        let report = self.report();
        let mut lines = Vec::new();
        lines.push(format!(
            "Kin profile: {} total_ms={:.2} spans={} samples={}",
            report.command,
            report.total_ms,
            report.span_count,
            report.resources.samples.len()
        ));
        if report.resources.summary.sample_count > 0 {
            lines.push(format!(
                "  peak cpu {:.1}% | peak rss {} | peak threads {} | net rx {} | net tx {}",
                report.resources.summary.peak_process_cpu_percent,
                format_bytes(report.resources.summary.peak_process_memory_bytes),
                report
                    .resources
                    .summary
                    .peak_thread_count
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                format_bytes(report.resources.summary.total_system_network_rx_bytes),
                format_bytes(report.resources.summary.total_system_network_tx_bytes),
            ));
        }
        for hot in report.summary.hot_paths.iter().take(limit) {
            lines.push(format!(
                "  {:.2} ms self | {:.2} ms total | avg {:.2} ms | count {:>3} | {}",
                hot.self_ms, hot.total_ms, hot.avg_self_ms, hot.count, hot.path
            ));
        }
        if !report.resources.summary.hot_paths.is_empty() {
            lines.push("  Resource hotspots:".to_string());
            for hot in report.resources.summary.hot_paths.iter().take(limit.min(6)) {
                lines.push(format!(
                    "    cpu {:.2} ms | peak {:.1}% | peak rss {} | {}",
                    hot.approx_cpu_ms,
                    hot.peak_process_cpu_percent,
                    format_bytes(hot.peak_process_memory_bytes),
                    hot.path
                ));
            }
        }
        lines.join("\n")
    }

    fn register_span(
        &self,
        name: &str,
        target: &str,
        level: &str,
        parent_id: Option<u64>,
        fields: BTreeMap<String, serde_json::Value>,
    ) -> u64 {
        let mut state = self.inner.lock().expect("profile state poisoned");
        let span_id = state.next_span_id;
        state.next_span_id += 1;
        let started_ms = state.started_mono.elapsed().as_secs_f64() * 1000.0;
        state.spans.insert(
            span_id,
            SpanRecord {
                id: span_id,
                parent_id,
                name: name.to_string(),
                target: target.to_string(),
                level: level.to_string(),
                started_ms,
                ended_ms: None,
                fields,
            },
        );
        span_id
    }

    fn record_fields(&self, span_id: u64, fields: BTreeMap<String, serde_json::Value>) {
        let mut state = self.inner.lock().expect("profile state poisoned");
        if let Some(record) = state.spans.get_mut(&span_id) {
            for (key, value) in fields {
                record.fields.insert(key, value);
            }
        }
    }

    fn finish_span(&self, span_id: u64) {
        let mut state = self.inner.lock().expect("profile state poisoned");
        let ended_ms = state.started_mono.elapsed().as_secs_f64() * 1000.0;
        if let Some(record) = state.spans.get_mut(&span_id) {
            if record.ended_ms.is_none() {
                record.ended_ms = Some(ended_ms);
            }
        }
    }

    fn record_resource_host(&self, host: ProfileResourceHost) {
        let mut state = self.inner.lock().expect("profile state poisoned");
        state.resource_host = Some(host);
    }

    fn record_resource_sample(&self, sample: ResourceSampleRecord) {
        let mut state = self.inner.lock().expect("profile state poisoned");
        state.resource_samples.push(sample);
    }

    fn start_resource_sampler(&self) {
        if self.sampler.sample_interval_ms == 0 {
            return;
        }

        let mut handle_slot = self.sampler.handle.lock().expect("sampler handle poisoned");
        if handle_slot.is_some() {
            return;
        }

        let session = self.clone();
        let sampler = Arc::clone(&self.sampler);
        let requested_interval = Duration::from_millis(self.sampler.sample_interval_ms);
        let minimum_interval = sysinfo::MINIMUM_CPU_UPDATE_INTERVAL;
        let interval = requested_interval.max(minimum_interval);
        *handle_slot = Some(thread::spawn(move || {
            run_resource_sampler(session, sampler, interval);
        }));
    }

    fn stop_sampler(&self) {
        self.sampler.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self
            .sampler
            .handle
            .lock()
            .expect("sampler handle poisoned")
            .take()
        {
            let _ = handle.join();
        }
    }
}

impl Drop for ProfileSession {
    fn drop(&mut self) {
        if Arc::strong_count(&self.sampler) == 1 {
            self.stop_sampler();
        }
    }
}

impl ProfilingLayer {
    pub fn new(session: ProfileSession) -> Self {
        Self { session }
    }
}

impl<S> Layer<S> for ProfilingLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }

    fn enabled(&self, _metadata: &tracing::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        true
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let parent_id = span_parent_profile_id(attrs, &ctx);
        let mut visitor = JsonFieldVisitor::default();
        attrs.record(&mut visitor);
        let metadata = attrs.metadata();
        let span_id = self.session.register_span(
            metadata.name(),
            metadata.target(),
            metadata.level().as_str(),
            parent_id,
            visitor.fields,
        );
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(ProfileSpanId(span_id));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span_id) = span_profile_id(id, &ctx) else {
            return;
        };
        let mut visitor = JsonFieldVisitor::default();
        values.record(&mut visitor);
        self.session.record_fields(span_id, visitor.fields);
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if let Some(span_id) = span_profile_id(&id, &ctx) {
            self.session.finish_span(span_id);
        }
    }
}

fn span_parent_profile_id<S>(attrs: &Attributes<'_>, ctx: &Context<'_, S>) -> Option<u64>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    attrs
        .parent()
        .and_then(|parent| span_profile_id(parent, ctx))
        .or_else(|| {
            if attrs.is_contextual() {
                ctx.current_span()
                    .id()
                    .and_then(|parent| span_profile_id(&parent, ctx))
            } else {
                None
            }
        })
}

fn span_profile_id<S>(id: &Id, ctx: &Context<'_, S>) -> Option<u64>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    ctx.span(id)
        .and_then(|span| span.extensions().get::<ProfileSpanId>().copied())
        .map(|wrapped| wrapped.0)
}

fn build_report(state: &ProfileState, sample_interval_ms: u64) -> ProfileReport {
    let now_ms = state.started_mono.elapsed().as_secs_f64() * 1000.0;
    let span_records: HashMap<u64, SpanRecord> = state
        .spans
        .iter()
        .map(|(id, record)| {
            let mut cloned = record.clone();
            if cloned.ended_ms.is_none() {
                cloned.ended_ms = Some(now_ms);
            }
            (*id, cloned)
        })
        .collect();

    let mut path_cache = HashMap::new();
    let mut child_duration_totals: HashMap<u64, f64> = HashMap::new();
    for record in span_records.values() {
        if let Some(parent_id) = record.parent_id {
            let ended_ms = record.ended_ms.unwrap_or(now_ms);
            let duration_ms = (ended_ms - record.started_ms).max(0.0);
            *child_duration_totals.entry(parent_id).or_insert(0.0) += duration_ms;
        }
    }
    let mut spans: Vec<ProfileSpan> = span_records
        .values()
        .map(|record| {
            let ended_ms = record.ended_ms.unwrap_or(now_ms);
            let duration_ms = (ended_ms - record.started_ms).max(0.0);
            let self_ms = (duration_ms
                - child_duration_totals
                    .get(&record.id)
                    .copied()
                    .unwrap_or(0.0))
            .max(0.0);
            let path = span_path(record.id, &span_records, &mut path_cache);
            ProfileSpan {
                id: record.id,
                parent_id: record.parent_id,
                path,
                name: record.name.clone(),
                target: record.target.clone(),
                level: record.level.clone(),
                started_ms: round_ms(record.started_ms),
                ended_ms: round_ms(ended_ms),
                duration_ms: round_ms(duration_ms),
                self_ms: round_ms(self_ms),
                fields: record.fields.clone(),
            }
        })
        .collect();
    spans.sort_by(|a, b| {
        a.started_ms
            .partial_cmp(&b.started_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let summary = summarize_spans(&spans);
    let resources = build_resource_report(state, &span_records, now_ms, sample_interval_ms);

    ProfileReport {
        format: "kin.profile.v2",
        command: state.command.clone(),
        cwd: state.cwd.clone(),
        pid: state.pid,
        started_at: chrono::DateTime::<chrono::Utc>::from(state.started_at).to_rfc3339(),
        total_ms: round_ms(now_ms),
        span_count: spans.len(),
        spans,
        summary,
        resources,
    }
}

fn summarize_spans(spans: &[ProfileSpan]) -> ProfileSummary {
    let mut by_path: HashMap<&str, ProfileHotPath> = HashMap::new();
    for span in spans {
        let entry = by_path.entry(&span.path).or_insert(ProfileHotPath {
            path: span.path.clone(),
            count: 0,
            total_ms: 0.0,
            self_ms: 0.0,
            avg_ms: 0.0,
            avg_self_ms: 0.0,
            max_ms: 0.0,
            max_self_ms: 0.0,
            slowest_span_id: span.id,
            slowest_self_span_id: span.id,
        });
        entry.count += 1;
        entry.total_ms += span.duration_ms;
        entry.self_ms += span.self_ms;
        if span.duration_ms > entry.max_ms {
            entry.max_ms = span.duration_ms;
            entry.slowest_span_id = span.id;
        }
        if span.self_ms > entry.max_self_ms {
            entry.max_self_ms = span.self_ms;
            entry.slowest_self_span_id = span.id;
        }
    }

    let mut hot_paths: Vec<ProfileHotPath> = by_path
        .into_values()
        .map(|mut path| {
            path.total_ms = round_ms(path.total_ms);
            path.self_ms = round_ms(path.self_ms);
            path.avg_ms = round_ms(path.total_ms / path.count as f64);
            path.avg_self_ms = round_ms(path.self_ms / path.count as f64);
            path.max_ms = round_ms(path.max_ms);
            path.max_self_ms = round_ms(path.max_self_ms);
            path
        })
        .collect();
    hot_paths.sort_by(|a, b| {
        b.self_ms
            .partial_cmp(&a.self_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.total_ms
                    .partial_cmp(&a.total_ms)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    let mut slowest_spans: Vec<ProfileSlowSpan> = spans
        .iter()
        .map(|span| ProfileSlowSpan {
            id: span.id,
            path: span.path.clone(),
            duration_ms: span.duration_ms,
            self_ms: span.self_ms,
            started_ms: span.started_ms,
        })
        .collect();
    slowest_spans.sort_by(|a, b| {
        b.self_ms
            .partial_cmp(&a.self_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.duration_ms
                    .partial_cmp(&a.duration_ms)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    ProfileSummary {
        hot_paths,
        slowest_spans,
    }
}

fn build_resource_report(
    state: &ProfileState,
    spans: &HashMap<u64, SpanRecord>,
    now_ms: f64,
    sample_interval_ms: u64,
) -> ProfileResources {
    let mut path_cache = HashMap::new();
    let mut depth_cache = HashMap::new();
    let mut samples = Vec::with_capacity(state.resource_samples.len());

    for sample in &state.resource_samples {
        let active_path = active_span_path(
            sample.sample_ms,
            spans,
            now_ms,
            &mut path_cache,
            &mut depth_cache,
        );
        samples.push(ProfileResourceSample {
            sample_ms: round_ms(sample.sample_ms),
            active_path,
            process_cpu_percent: sample.process_cpu_percent.map(round_ms),
            system_cpu_percent: sample.system_cpu_percent.map(round_ms),
            per_core_cpu_percent: sample
                .per_core_cpu_percent
                .iter()
                .copied()
                .map(round_ms)
                .collect(),
            process_memory_bytes: sample.process_memory_bytes,
            process_virtual_memory_bytes: sample.process_virtual_memory_bytes,
            thread_count: sample.thread_count,
            system_total_memory_bytes: sample.system_total_memory_bytes,
            system_used_memory_bytes: sample.system_used_memory_bytes,
            system_available_memory_bytes: sample.system_available_memory_bytes,
            system_total_swap_bytes: sample.system_total_swap_bytes,
            system_used_swap_bytes: sample.system_used_swap_bytes,
            system_network_rx_bytes: sample.system_network_rx_bytes,
            system_network_tx_bytes: sample.system_network_tx_bytes,
        });
    }

    let summary = summarize_resources(&samples, sample_interval_ms);

    ProfileResources {
        host: state.resource_host.clone(),
        sample_interval_ms,
        samples,
        summary,
    }
}

fn summarize_resources(
    samples: &[ProfileResourceSample],
    sample_interval_ms: u64,
) -> ProfileResourceSummary {
    let mut peak_process_cpu_percent = 0.0_f64;
    let mut peak_system_cpu_percent = 0.0_f64;
    let mut peak_process_memory_bytes = 0_u64;
    let mut peak_thread_count = None;
    let mut total_system_network_rx_bytes = 0_u64;
    let mut total_system_network_tx_bytes = 0_u64;
    let mut by_path: HashMap<&str, ResourceHotPathAccumulator> = HashMap::new();

    for sample in samples {
        peak_process_cpu_percent =
            peak_process_cpu_percent.max(sample.process_cpu_percent.unwrap_or(0.0));
        peak_system_cpu_percent =
            peak_system_cpu_percent.max(sample.system_cpu_percent.unwrap_or(0.0));
        peak_process_memory_bytes =
            peak_process_memory_bytes.max(sample.process_memory_bytes.unwrap_or(0));
        peak_thread_count = max_option_u64(peak_thread_count, sample.thread_count);
        total_system_network_rx_bytes =
            total_system_network_rx_bytes.saturating_add(sample.system_network_rx_bytes);
        total_system_network_tx_bytes =
            total_system_network_tx_bytes.saturating_add(sample.system_network_tx_bytes);

        let Some(path) = sample.active_path.as_deref() else {
            continue;
        };

        let entry = by_path.entry(path).or_insert(ResourceHotPathAccumulator {
            path: path.to_string(),
            sample_count: 0,
            approx_cpu_ms: 0.0,
            total_process_cpu_percent: 0.0,
            peak_process_cpu_percent: 0.0,
            total_process_memory_bytes: 0,
            process_memory_samples: 0,
            peak_process_memory_bytes: 0,
            peak_thread_count: None,
            total_system_network_rx_bytes: 0,
            total_system_network_tx_bytes: 0,
        });
        entry.sample_count += 1;
        let process_cpu = sample.process_cpu_percent.unwrap_or(0.0);
        entry.approx_cpu_ms += process_cpu * sample_interval_ms as f64 / 100.0;
        entry.total_process_cpu_percent += process_cpu;
        entry.peak_process_cpu_percent = entry.peak_process_cpu_percent.max(process_cpu);
        if let Some(memory) = sample.process_memory_bytes {
            entry.total_process_memory_bytes += u128::from(memory);
            entry.process_memory_samples += 1;
            entry.peak_process_memory_bytes = entry.peak_process_memory_bytes.max(memory);
        }
        entry.peak_thread_count = max_option_u64(entry.peak_thread_count, sample.thread_count);
        entry.total_system_network_rx_bytes = entry
            .total_system_network_rx_bytes
            .saturating_add(sample.system_network_rx_bytes);
        entry.total_system_network_tx_bytes = entry
            .total_system_network_tx_bytes
            .saturating_add(sample.system_network_tx_bytes);
    }

    let mut hot_paths: Vec<ProfileResourceHotPath> = by_path
        .into_values()
        .map(|entry| ProfileResourceHotPath {
            path: entry.path,
            sample_count: entry.sample_count,
            approx_cpu_ms: round_ms(entry.approx_cpu_ms),
            avg_process_cpu_percent: round_ms(
                entry.total_process_cpu_percent / entry.sample_count as f64,
            ),
            peak_process_cpu_percent: round_ms(entry.peak_process_cpu_percent),
            avg_process_memory_bytes: if entry.process_memory_samples > 0 {
                (entry.total_process_memory_bytes / entry.process_memory_samples as u128) as u64
            } else {
                0
            },
            peak_process_memory_bytes: entry.peak_process_memory_bytes,
            peak_thread_count: entry.peak_thread_count,
            total_system_network_rx_bytes: entry.total_system_network_rx_bytes,
            total_system_network_tx_bytes: entry.total_system_network_tx_bytes,
        })
        .collect();

    hot_paths.sort_by(|a, b| {
        b.approx_cpu_ms
            .partial_cmp(&a.approx_cpu_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.peak_process_memory_bytes
                    .cmp(&a.peak_process_memory_bytes)
            })
    });

    ProfileResourceSummary {
        sample_count: samples.len(),
        peak_process_cpu_percent: round_ms(peak_process_cpu_percent),
        peak_system_cpu_percent: round_ms(peak_system_cpu_percent),
        peak_process_memory_bytes,
        peak_thread_count,
        total_system_network_rx_bytes,
        total_system_network_tx_bytes,
        hot_paths,
    }
}

fn active_span_path(
    sample_ms: f64,
    spans: &HashMap<u64, SpanRecord>,
    now_ms: f64,
    path_cache: &mut HashMap<u64, String>,
    depth_cache: &mut HashMap<u64, usize>,
) -> Option<String> {
    let mut best_span_id = None;
    let mut best_depth = 0_usize;
    let mut best_started_ms = f64::MIN;

    for record in spans.values() {
        let ended_ms = record.ended_ms.unwrap_or(now_ms);
        if sample_ms < record.started_ms || sample_ms > ended_ms {
            continue;
        }
        let depth = span_depth(record.id, spans, depth_cache);
        if best_span_id.is_none()
            || depth > best_depth
            || (depth == best_depth && record.started_ms > best_started_ms)
        {
            best_span_id = Some(record.id);
            best_depth = depth;
            best_started_ms = record.started_ms;
        }
    }

    best_span_id.map(|span_id| span_path(span_id, spans, path_cache))
}

fn span_depth(
    span_id: u64,
    spans: &HashMap<u64, SpanRecord>,
    cache: &mut HashMap<u64, usize>,
) -> usize {
    if let Some(depth) = cache.get(&span_id) {
        return *depth;
    }

    let depth = spans
        .get(&span_id)
        .and_then(|record| {
            record
                .parent_id
                .map(|parent_id| span_depth(parent_id, spans, cache) + 1)
        })
        .unwrap_or(1);
    cache.insert(span_id, depth);
    depth
}

fn span_path(
    span_id: u64,
    spans: &HashMap<u64, SpanRecord>,
    cache: &mut HashMap<u64, String>,
) -> String {
    if let Some(path) = cache.get(&span_id) {
        return path.clone();
    }

    let record = spans
        .get(&span_id)
        .expect("profile path requested for missing span");
    let path = match record.parent_id {
        Some(parent_id) => format!("{} > {}", span_path(parent_id, spans, cache), record.name),
        None => record.name.clone(),
    };
    cache.insert(span_id, path.clone());
    path
}

fn round_ms(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0_usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn configured_sample_interval_ms() -> u64 {
    if env_flag("KIN_PROFILE_DISABLE_RESOURCES") {
        return 0;
    }

    std::env::var("KIN_PROFILE_SAMPLE_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RESOURCE_SAMPLE_MS)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

fn max_option_u64(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn run_resource_sampler(session: ProfileSession, sampler: Arc<SamplerControl>, interval: Duration) {
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let process_refresh = ProcessRefreshKind::nothing().with_memory().with_cpu();
    let mut system = System::new_with_specifics(
        RefreshKind::nothing()
            .with_memory(MemoryRefreshKind::everything())
            .with_cpu(CpuRefreshKind::everything())
            .with_processes(process_refresh),
    );
    let mut networks = Networks::new_with_refreshed_list();

    session.record_resource_host(ProfileResourceHost {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        logical_cores: system.cpus().len(),
        cpu_name: system.cpus().first().map(|cpu| cpu.name().to_string()),
        cpu_brand: system.cpus().first().map(|cpu| cpu.brand().to_string()),
        gpu_devices: discover_gpu_devices(),
    });

    while !sampler.stop.load(Ordering::Relaxed) {
        thread::sleep(interval);
        if sampler.stop.load(Ordering::Relaxed) {
            break;
        }

        system.refresh_memory();
        system.refresh_cpu_usage();
        system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), false, process_refresh);
        networks.refresh(true);

        let process = system.process(pid);
        let (process_cpu_percent, process_memory_bytes, process_virtual_memory_bytes) =
            if let Some(process) = process {
                (
                    Some(process.cpu_usage() as f64),
                    Some(process.memory()),
                    Some(process.virtual_memory()),
                )
            } else {
                (None, None, None)
            };

        let thread_count = process_thread_count(process, pid.as_u32());
        let sample_ms = {
            let state = session.inner.lock().expect("profile state poisoned");
            state.started_mono.elapsed().as_secs_f64() * 1000.0
        };

        session.record_resource_sample(ResourceSampleRecord {
            sample_ms,
            process_cpu_percent,
            system_cpu_percent: Some(system.global_cpu_usage() as f64),
            per_core_cpu_percent: system
                .cpus()
                .iter()
                .map(|cpu| cpu.cpu_usage() as f64)
                .collect(),
            process_memory_bytes,
            process_virtual_memory_bytes,
            thread_count,
            system_total_memory_bytes: system.total_memory(),
            system_used_memory_bytes: system.used_memory(),
            system_available_memory_bytes: system.available_memory(),
            system_total_swap_bytes: system.total_swap(),
            system_used_swap_bytes: system.used_swap(),
            system_network_rx_bytes: networks.values().map(|network| network.received()).sum(),
            system_network_tx_bytes: networks.values().map(|network| network.transmitted()).sum(),
        });
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_thread_count(process: Option<&sysinfo::Process>, _pid: u32) -> Option<u64> {
    process.and_then(|process| process.tasks().map(|tasks| tasks.len() as u64))
}

#[cfg(target_os = "macos")]
fn process_thread_count(_process: Option<&sysinfo::Process>, pid: u32) -> Option<u64> {
    let output = Command::new("ps")
        .args(["-M", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .count();
    (lines > 0).then_some(lines as u64)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn process_thread_count(_process: Option<&sysinfo::Process>, _pid: u32) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn discover_gpu_devices() -> Vec<ProfileGpuDevice> {
    discover_macos_gpu_devices()
}

#[cfg(not(target_os = "macos"))]
fn discover_gpu_devices() -> Vec<ProfileGpuDevice> {
    Vec::new()
}

#[cfg(target_os = "macos")]
fn discover_macos_gpu_devices() -> Vec<ProfileGpuDevice> {
    let output = Command::new("/usr/sbin/system_profiler")
        .args(["SPDisplaysDataType", "-json"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return Vec::new();
    };
    let Some(entries) = payload
        .get("SPDisplaysDataType")
        .and_then(|value| value.as_array())
    else {
        return Vec::new();
    };

    entries
        .iter()
        .map(|entry| ProfileGpuDevice {
            name: entry
                .get("sppci_model")
                .and_then(|value| value.as_str())
                .or_else(|| entry.get("_name").and_then(|value| value.as_str()))
                .unwrap_or("Unknown GPU")
                .to_string(),
            model: entry
                .get("sppci_model")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            vendor: entry
                .get("spdisplays_vendor")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            core_count: entry
                .get("sppci_cores")
                .and_then(|value| value.as_str())
                .and_then(parse_first_u64),
            backend: entry
                .get("spdisplays_mtlgpufamilysupport")
                .and_then(|value| value.as_str())
                .map(|_| "metal".to_string()),
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn parse_first_u64(value: &str) -> Option<u64> {
    let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u64>().ok()
    }
}

#[derive(Default)]
struct JsonFieldVisitor {
    fields: BTreeMap<String, serde_json::Value>,
}

impl Visit for JsonFieldVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if let Some(number) = serde_json::Number::from_f64(value) {
            self.fields
                .insert(field.name().to_string(), serde_json::Value::Number(number));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::String(format!("{value:?}")),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    #[test]
    fn profiling_layer_records_spans() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let session = ProfileSession::new("test", "/tmp", temp.path().to_path_buf());
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("info"))
            .with(ProfilingLayer::new(session.clone()));

        tracing::subscriber::with_default(subscriber, || {
            let _outer = tracing::info_span!("outer").entered();
            let _inner = tracing::info_span!("inner", answer = 42).entered();
        });

        let report = session.report();
        assert!(report.span_count >= 2, "report={report:?}");
        assert!(
            report
                .summary
                .hot_paths
                .iter()
                .any(|path| path.path.contains("outer")),
            "report={report:?}"
        );
    }

    #[test]
    fn resource_samples_are_attributed_to_deepest_span() {
        let mut spans = BTreeMap::new();
        spans.insert(
            1,
            SpanRecord {
                id: 1,
                parent_id: None,
                name: "outer".into(),
                target: "test".into(),
                level: "INFO".into(),
                started_ms: 0.0,
                ended_ms: Some(20.0),
                fields: BTreeMap::new(),
            },
        );
        spans.insert(
            2,
            SpanRecord {
                id: 2,
                parent_id: Some(1),
                name: "inner".into(),
                target: "test".into(),
                level: "INFO".into(),
                started_ms: 5.0,
                ended_ms: Some(15.0),
                fields: BTreeMap::new(),
            },
        );

        let state = ProfileState {
            command: "test".into(),
            cwd: "/tmp".into(),
            pid: 1,
            started_at: SystemTime::UNIX_EPOCH,
            started_mono: Instant::now(),
            next_span_id: 3,
            spans,
            resource_host: None,
            resource_samples: vec![ResourceSampleRecord {
                sample_ms: 10.0,
                process_cpu_percent: Some(200.0),
                system_cpu_percent: Some(90.0),
                per_core_cpu_percent: vec![80.0, 70.0],
                process_memory_bytes: Some(1024),
                process_virtual_memory_bytes: Some(2048),
                thread_count: Some(4),
                system_total_memory_bytes: 4096,
                system_used_memory_bytes: 2048,
                system_available_memory_bytes: 2048,
                system_total_swap_bytes: 1024,
                system_used_swap_bytes: 0,
                system_network_rx_bytes: 128,
                system_network_tx_bytes: 64,
            }],
        };

        let report = build_report(&state, 250);
        assert_eq!(
            report.resources.samples[0].active_path.as_deref(),
            Some("outer > inner")
        );
        assert_eq!(report.resources.summary.hot_paths[0].path, "outer > inner");
        assert!(report.resources.summary.hot_paths[0].approx_cpu_ms > 0.0);
    }
}
