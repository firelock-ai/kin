// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin path <from> <to>`: the shortest routes between two entities.
//!
//! The walk itself lives in `kin_mcp::handlers::path` and runs in the daemon
//! behind `POST /commands/path`, so this command, the daemon route and the
//! `trace_path` MCP tool answer from one implementation. What this module owns
//! is the rendering and the exit code: a route found is 0, an end that did not
//! resolve is an error, and no route inside the bound is
//! [`NO_ROUTE_EXIT_CODE`] with the gap on stderr, so a script that captures
//! stdout never captures something that reads like a route.

use anyhow::{Context, Result};
use kin_mcp::handlers::path::{render_compact, PathDirection, PathRequest, PathResponse};

/// The graph holds no route inside the bound. Kept apart from 1, which is an
/// error, so a caller can tell "the question was answered, negatively" from
/// "the question was not answered".
pub const NO_ROUTE_EXIT_CODE: i32 = 3;

/// CLI entry: build the request, ask the daemon, render, and hand back the
/// exit code.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    from: String,
    to: String,
    from_file: Option<String>,
    to_file: Option<String>,
    max_depth: Option<usize>,
    limit: Option<usize>,
    direction: Option<String>,
    include_type_edges: bool,
    json: bool,
    compact: bool,
) -> Result<i32> {
    let direction = match direction {
        Some(value) => {
            Some(PathDirection::parse(&value).map_err(|message| anyhow::anyhow!(message))?)
        }
        None => None,
    };
    let request = PathRequest {
        from,
        to,
        from_file,
        to_file,
        max_depth,
        limit,
        direction,
        include_type_edges: include_type_edges.then_some(true),
    };
    let layout = crate::commands::require_repository_layout()?;
    let payload = run_daemon_path(&layout, &request).await?;
    let response: PathResponse =
        serde_json::from_value(payload.clone()).context("parse daemon path response")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else if response.found {
        if compact {
            print!("{}", render_compact(&response));
        } else {
            print!("{}", render_report(&response, &payload));
        }
    } else {
        eprint!("{}", render_report(&response, &payload));
    }
    Ok(if response.found {
        0
    } else {
        NO_ROUTE_EXIT_CODE
    })
}

async fn run_daemon_path(
    layout: &kin_core::KinLayout,
    request: &PathRequest,
) -> Result<serde_json::Value> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("path", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .path(request)
        .await
        .context("daemon path command failed")
}

/// The readable form: the compact route lines, then what the walk covered, how
/// each end resolved, and the envelope's verdict when the daemon attached one.
pub fn render_report(response: &PathResponse, payload: &serde_json::Value) -> String {
    let mut out = String::new();
    if response.found {
        out.push_str(&render_compact(response));
    } else if let Some(gap) = &response.gap {
        out.push_str(&format!(
            "no route: {}\n  {}\n",
            gap.detail, gap.remediation
        ));
    } else {
        out.push_str("no route\n");
    }
    for walk in &response.explored {
        out.push_str(&format!(
            "explored: {} walk, {} entities, {} edges, depth {}, {} in {} ms\n",
            walk.sense,
            walk.nodes,
            walk.edges,
            walk.depth_reached,
            walk.stopped_by,
            walk.elapsed_ms
        ));
    }
    for (which, end) in [("from", &response.from), ("to", &response.to)] {
        let location = match (&end.file, end.start_line) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            (Some(file), None) => file.clone(),
            (None, _) => "(no file)".to_string(),
        };
        out.push_str(&format!(
            "{which}: {} [{}] {} ({}",
            end.name,
            end.kind.to_lowercase(),
            location,
            end.addressed_by.replace('_', " ")
        ));
        if end.same_name_candidates > 1 {
            let others: Vec<String> = end
                .other_candidates
                .iter()
                .map(|candidate| {
                    format!(
                        "{}:{}",
                        candidate.file.as_deref().unwrap_or("(no file)"),
                        candidate
                            .start_line
                            .map(|line| line.to_string())
                            .unwrap_or_else(|| "?".to_string())
                    )
                })
                .collect();
            out.push_str(&format!(
                "; one of {} named {}, others at {}; pin with {}@<file>",
                end.same_name_candidates,
                end.name,
                others.join(", "),
                end.name
            ));
        }
        out.push_str(")\n");
    }
    for degradation in &response.degradations {
        out.push_str(&format!(
            "note: {} ({}): {}\n",
            degradation.component, degradation.reason, degradation.detail
        ));
    }
    let verdict = &payload[kin_mcp::ENVELOPE_KEY][kin_mcp::VERDICT_KEY];
    if let Some(state) = verdict["state"].as_str() {
        match verdict["limiting_factor"].as_str() {
            Some(factor) => out.push_str(&format!("verdict: {state} ({factor})\n")),
            None => out.push_str(&format!("verdict: {state}\n")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_mcp::handlers::path::{
        PathCandidate, PathEndpoint, PathExplored, PathGap, PathHop, PathRoute,
    };

    fn end(name: &str, file: &str, line: u32) -> PathEndpoint {
        PathEndpoint {
            entity_id: "00000000-0000-0000-0000-000000000001".to_string(),
            name: name.to_string(),
            kind: "Function".to_string(),
            file: Some(file.to_string()),
            start_line: Some(line),
            end_line: Some(line + 3),
            external: false,
            addressed_by: "name".to_string(),
            same_name_candidates: 1,
            other_candidates: Vec::new(),
            members_expanded: 0,
        }
    }

    fn hop(name: &str, file: &str, line: u32, relation: Option<&str>) -> PathHop {
        PathHop {
            entity_id: "00000000-0000-0000-0000-000000000002".to_string(),
            name: name.to_string(),
            kind: "Function".to_string(),
            file: Some(file.to_string()),
            start_line: Some(line),
            end_line: Some(line + 3),
            external: false,
            relation: relation.map(str::to_string),
            edge: relation.map(|_| "outgoing".to_string()),
            resolution: relation.map(|_| "type_resolved".to_string()),
            site_lines: relation.map(|_| vec![line + 1]).unwrap_or_default(),
            site_lines_absent_reason: None,
        }
    }

    fn response(found: bool) -> PathResponse {
        PathResponse {
            from: end("edit", "src/editor.rs", 4),
            to: end("write", "src/model.rs", 9),
            direction_requested: "either".to_string(),
            direction: found.then(|| "forward".to_string()),
            max_depth: 6,
            limit: 3,
            walked_kinds: vec!["Calls".to_string()],
            include_type_edges: false,
            found,
            routes: if found {
                vec![PathRoute {
                    direction: "forward".to_string(),
                    hops: 2,
                    walked_hops: 2,
                    steps: vec![
                        hop("edit", "src/editor.rs", 4, Some("Calls")),
                        hop("push", "src/model.rs", 1, Some("Calls")),
                        hop("write", "src/model.rs", 9, None),
                    ],
                }]
            } else {
                Vec::new()
            },
            routes_total: usize::from(found),
            routes_truncated: false,
            explored: vec![PathExplored {
                sense: "forward".to_string(),
                nodes: 3,
                edges: 2,
                depth_reached: 2,
                stopped_by: if found {
                    "route_found"
                } else {
                    "frontier_exhausted"
                }
                .to_string(),
                elapsed_ms: 1,
            }],
            gap: (!found).then(|| PathGap {
                reason: "frontier_exhausted".to_string(),
                detail: "no route between 'edit' and 'write' within 6 hops".to_string(),
                remediation: "check both ends".to_string(),
            }),
            degradations: Vec::new(),
            edge_coverage: serde_json::Value::Null,
        }
    }

    /// The report leads with the route, one line per hop, and closes with the
    /// verdict the daemon attached.
    #[test]
    fn the_report_leads_with_the_route_and_ends_with_the_verdict() {
        let payload = serde_json::json!({
            "_kin": { "verdict": { "state": "certified", "limiting_factor": null } }
        });
        let report = render_report(&response(true), &payload);
        let lines: Vec<&str> = report.lines().collect();
        assert!(
            lines[0].starts_with("route 1 of 1 (forward, 2 hops): edit -> write"),
            "{report}"
        );
        assert_eq!(lines[1].trim(), "edit [function] src/editor.rs:4");
        assert!(
            lines[2]
                .trim()
                .starts_with("-Calls@5-> push [function] src/model.rs:1"),
            "{report}"
        );
        assert!(
            lines[3]
                .trim()
                .starts_with("-Calls@2-> write [function] src/model.rs:9"),
            "{report}"
        );
        assert!(
            report.contains("explored: forward walk, 3 entities, 2 edges"),
            "{report}"
        );
        assert!(report.ends_with("verdict: certified\n"), "{report}");
    }

    /// No route renders the gap, never a route-shaped line, and names a twin
    /// the caller could pin.
    #[test]
    fn a_no_route_report_names_the_gap_and_the_twin() {
        let mut response = response(false);
        response.from.same_name_candidates = 2;
        response.from.other_candidates = vec![PathCandidate {
            entity_id: "00000000-0000-0000-0000-000000000003".to_string(),
            name: "edit".to_string(),
            kind: "Function".to_string(),
            file: Some("src/other.rs".to_string()),
            start_line: Some(70),
        }];
        let payload = serde_json::json!({
            "_kin": { "verdict": { "state": "inconclusive", "limiting_factor": "from_ambiguous" } }
        });
        let report = render_report(&response, &payload);
        assert!(
            report.starts_with("no route: no route between 'edit' and 'write'"),
            "{report}"
        );
        assert!(!report.contains("route 1"), "{report}");
        assert!(
            report.contains("one of 2 named edit, others at src/other.rs:70; pin with edit@<file>"),
            "{report}"
        );
        assert!(
            report.ends_with("verdict: inconclusive (from_ambiguous)\n"),
            "{report}"
        );
    }
}
