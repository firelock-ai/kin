// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

#[derive(Debug, Clone)]
pub struct ProfileSession {
    inner: Arc<Mutex<ProfileState>>,
    output_path: PathBuf,
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
    pub avg_ms: f64,
    pub max_ms: f64,
    pub slowest_span_id: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileSlowSpan {
    pub id: u64,
    pub path: String,
    pub duration_ms: f64,
    pub started_ms: f64,
}

#[derive(Debug, Clone)]
pub struct ProfilingLayer {
    session: ProfileSession,
}

#[derive(Debug, Clone, Copy)]
struct ProfileSpanId(u64);

impl ProfileSession {
    pub fn new(command: impl Into<String>, cwd: impl Into<String>, output_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ProfileState {
                command: command.into(),
                cwd: cwd.into(),
                pid: std::process::id(),
                started_at: SystemTime::now(),
                started_mono: Instant::now(),
                next_span_id: 1,
                spans: BTreeMap::new(),
            })),
            output_path,
        }
    }

    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    pub fn report(&self) -> ProfileReport {
        let state = self.inner.lock().expect("profile state poisoned");
        build_report(&state)
    }

    pub fn write_report(&self) -> anyhow::Result<ProfileReport> {
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
            "Kin profile: {} total_ms={:.2} spans={}",
            report.command, report.total_ms, report.span_count
        ));
        for hot in report.summary.hot_paths.iter().take(limit) {
            lines.push(format!(
                "  {:.2} ms total | avg {:.2} ms | count {:>3} | {}",
                hot.total_ms, hot.avg_ms, hot.count, hot.path
            ));
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

fn build_report(state: &ProfileState) -> ProfileReport {
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
    let mut spans: Vec<ProfileSpan> = span_records
        .values()
        .map(|record| {
            let ended_ms = record.ended_ms.unwrap_or(now_ms);
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
                duration_ms: round_ms((ended_ms - record.started_ms).max(0.0)),
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

    ProfileReport {
        format: "kin.profile.v1",
        command: state.command.clone(),
        cwd: state.cwd.clone(),
        pid: state.pid,
        started_at: chrono::DateTime::<chrono::Utc>::from(state.started_at).to_rfc3339(),
        total_ms: round_ms(now_ms),
        span_count: spans.len(),
        spans,
        summary,
    }
}

fn summarize_spans(spans: &[ProfileSpan]) -> ProfileSummary {
    let mut by_path: HashMap<&str, ProfileHotPath> = HashMap::new();
    for span in spans {
        let entry = by_path.entry(&span.path).or_insert(ProfileHotPath {
            path: span.path.clone(),
            count: 0,
            total_ms: 0.0,
            avg_ms: 0.0,
            max_ms: 0.0,
            slowest_span_id: span.id,
        });
        entry.count += 1;
        entry.total_ms += span.duration_ms;
        if span.duration_ms > entry.max_ms {
            entry.max_ms = span.duration_ms;
            entry.slowest_span_id = span.id;
        }
    }

    let mut hot_paths: Vec<ProfileHotPath> = by_path
        .into_values()
        .map(|mut path| {
            path.total_ms = round_ms(path.total_ms);
            path.avg_ms = round_ms(path.total_ms / path.count as f64);
            path.max_ms = round_ms(path.max_ms);
            path
        })
        .collect();
    hot_paths.sort_by(|a, b| {
        b.total_ms
            .partial_cmp(&a.total_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut slowest_spans: Vec<ProfileSlowSpan> = spans
        .iter()
        .map(|span| ProfileSlowSpan {
            id: span.id,
            path: span.path.clone(),
            duration_ms: span.duration_ms,
            started_ms: span.started_ms,
        })
        .collect();
    slowest_spans.sort_by(|a, b| {
        b.duration_ms
            .partial_cmp(&a.duration_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    ProfileSummary {
        hot_paths,
        slowest_spans,
    }
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
}
