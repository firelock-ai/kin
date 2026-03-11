use axum::response::Html;

/// Main dashboard page.
pub fn dashboard_page() -> Html<String> {
    Html(render_page("Kin Dashboard", DASHBOARD_CONTENT))
}

/// Graph visualization page.
pub fn graph_page() -> Html<String> {
    Html(render_page("Kin Graph", GRAPH_CONTENT))
}

/// Review interface page.
pub fn review_page() -> Html<String> {
    Html(render_page("Kin Review", REVIEW_CONTENT))
}

/// Benchmarks page.
pub fn benchmarks_page() -> Html<String> {
    Html(render_page("Kin Benchmarks", BENCHMARKS_CONTENT))
}

/// Live traffic view page.
pub fn traffic_page() -> Html<String> {
    Html(render_page("Kin Traffic", TRAFFIC_CONTENT))
}

/// Work items view page.
pub fn work_page() -> Html<String> {
    Html(render_page("Kin Work", WORK_CONTENT))
}

/// Verification / coverage view page.
pub fn verification_page() -> Html<String> {
    Html(render_page("Kin Verification", VERIFICATION_CONTENT))
}

/// Provenance / audit view page.
pub fn provenance_page() -> Html<String> {
    Html(render_page("Kin Provenance", PROVENANCE_CONTENT))
}

fn render_page(title: &str, content: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; }}
        nav {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; gap: 24px; align-items: center; }}
        nav a {{ color: #58a6ff; text-decoration: none; font-size: 14px; }}
        nav a:hover {{ text-decoration: underline; }}
        nav .brand {{ font-weight: 700; font-size: 16px; color: #f0f6fc; margin-right: 16px; }}
        .container {{ max-width: 1200px; margin: 24px auto; padding: 0 24px; }}
        h1 {{ font-size: 24px; margin-bottom: 16px; color: #f0f6fc; }}
        h2 {{ font-size: 18px; margin: 24px 0 12px; color: #f0f6fc; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 16px; }}
        .card h3 {{ font-size: 14px; color: #8b949e; margin-bottom: 8px; }}
        .card .value {{ font-size: 32px; font-weight: 700; color: #58a6ff; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }}
        .status {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
        .status.ok {{ background: #1a3a2a; color: #3fb950; }}
        .status.warn {{ background: #3d2e00; color: #d29922; }}
        .status.error {{ background: #3d1a1a; color: #f85149; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 14px; }}
        th {{ color: #8b949e; font-weight: 600; }}
        #loading {{ color: #8b949e; font-style: italic; }}
        .graph-placeholder {{ width: 100%; height: 400px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; display: flex; align-items: center; justify-content: center; color: #8b949e; }}
    </style>
</head>
<body>
    <nav>
        <span class="brand">Kin</span>
        <a href="/">Dashboard</a>
        <a href="/graph">Graph</a>
        <a href="/review">Review</a>
        <a href="/work">Work</a>
        <a href="/verification">Verification</a>
        <a href="/benchmarks">Benchmarks</a>
        <a href="/traffic">Traffic</a>
        <a href="/provenance">Provenance</a>
    </nav>
    <div class="container">
        {content}
    </div>
</body>
</html>"#
    )
}

const DASHBOARD_CONTENT: &str = r#"
<h1>Dashboard</h1>
<div id="status-section">
    <p id="loading">Connecting to daemon...</p>
</div>
<div class="grid" id="metrics-grid"></div>

<h2>Working Copy Status</h2>
<div class="card" id="wc-status">
    <p id="loading">Loading...</p>
</div>

<script>
async function loadDashboard() {
    try {
        const health = await fetch('/api/health').then(r => r.json());
        document.getElementById('status-section').innerHTML =
            '<p>Daemon: <span class="status ok">' + health.status + '</span> v' + health.version + '</p>';
    } catch(e) {
        document.getElementById('status-section').innerHTML =
            '<p>Daemon: <span class="status error">offline</span></p>';
    }

    try {
        const status = await fetch('/api/status').then(r => r.json());
        document.getElementById('wc-status').innerHTML =
            '<table><tr><th>Base Change</th><td>' + status.base_change + '</td></tr>' +
            '<tr><th>Entity Adds</th><td>' + status.entity_adds + '</td></tr>' +
            '<tr><th>Entity Mods</th><td>' + status.entity_mods + '</td></tr>' +
            '<tr><th>Entity Removes</th><td>' + status.entity_removes + '</td></tr>' +
            '<tr><th>Relation Adds</th><td>' + status.relation_adds + '</td></tr>' +
            '<tr><th>Relation Removes</th><td>' + status.relation_removes + '</td></tr></table>';
    } catch(e) {
        document.getElementById('wc-status').innerHTML = '<p class="status error">Could not load status</p>';
    }
}
loadDashboard();
</script>
"#;

const GRAPH_CONTENT: &str = r#"
<h1>Graph Visualization</h1>
<p>Entity and relation graph for the current repository.</p>

<div class="card">
    <h3>Entity Graph</h3>
    <div class="graph-placeholder" id="graph-container">
        Graph visualization will render here. Connect to daemon for live data.
    </div>
</div>

<h2>Entity List</h2>
<div class="card" id="entity-list">
    <p id="loading">Loading entities...</p>
</div>

<script>
async function loadGraph() {
    try {
        const resp = await fetch('/api/status').then(r => r.json());
        document.getElementById('entity-list').innerHTML =
            '<p>Working copy has ' +
            (resp.entity_adds + resp.entity_mods) + ' active entity changes.</p>';
    } catch(e) {
        document.getElementById('entity-list').innerHTML =
            '<p class="status error">Could not connect to daemon</p>';
    }
}
loadGraph();
</script>
"#;

const REVIEW_CONTENT: &str = r#"
<h1>Semantic Review</h1>
<p>Review changed entities and their downstream impact.</p>

<div class="card">
    <h3>Current Changes</h3>
    <div id="review-content">
        <p id="loading">Loading review data...</p>
    </div>
</div>

<h2>Risk Assessment</h2>
<div class="card" id="risk-section">
    <p id="loading">Analyzing risk...</p>
</div>

<script>
async function loadReview() {
    try {
        const status = await fetch('/api/status').then(r => r.json());
        const total = status.entity_adds + status.entity_mods + status.entity_removes;
        document.getElementById('review-content').innerHTML =
            '<div class="grid">' +
            '<div class="card"><h3>Added</h3><div class="value">' + status.entity_adds + '</div></div>' +
            '<div class="card"><h3>Modified</h3><div class="value">' + status.entity_mods + '</div></div>' +
            '<div class="card"><h3>Removed</h3><div class="value">' + status.entity_removes + '</div></div>' +
            '</div>';

        let riskLevel = 'LOW';
        let riskClass = 'ok';
        if (status.entity_removes > 0) { riskLevel = 'MEDIUM'; riskClass = 'warn'; }
        if (total > 10) { riskLevel = 'HIGH'; riskClass = 'error'; }

        document.getElementById('risk-section').innerHTML =
            '<p>Overall risk: <span class="status ' + riskClass + '">' + riskLevel + '</span></p>' +
            '<p>' + total + ' entity changes in working copy.</p>';
    } catch(e) {
        document.getElementById('review-content').innerHTML =
            '<p class="status error">Could not load review data</p>';
        document.getElementById('risk-section').innerHTML = '';
    }
}
loadReview();
</script>
"#;

const BENCHMARKS_CONTENT: &str = r#"
<h1>Benchmarks</h1>
<p>Performance metrics and economic analysis.</p>

<h2>Developer Velocity</h2>
<div class="grid" id="velocity-metrics">
    <div class="card"><h3>Context Warmup</h3><div class="value" id="warmup">--</div></div>
    <div class="card"><h3>Review Turnaround</h3><div class="value" id="review-time">--</div></div>
    <div class="card"><h3>Impact Analysis</h3><div class="value" id="impact-time">--</div></div>
</div>

<h2>Reliability</h2>
<div class="grid" id="reliability-metrics">
    <div class="card"><h3>Dependency Coverage</h3><div class="value" id="dep-coverage">--</div></div>
    <div class="card"><h3>Test Coverage</h3><div class="value" id="test-coverage">--</div></div>
    <div class="card"><h3>Dead Code</h3><div class="value" id="dead-code">--</div></div>
</div>

<h2>Economic</h2>
<div class="grid" id="economic-metrics">
    <div class="card"><h3>Token Savings</h3><div class="value" id="token-savings">--</div></div>
    <div class="card"><h3>CI/CD Savings</h3><div class="value" id="cicd-savings">--</div></div>
    <div class="card"><h3>Tokens/Entity</h3><div class="value" id="token-ratio">--</div></div>
</div>

<h2>Assistant Comparison (Git vs Kin)</h2>
<div class="card" id="assistant-comparison">
    <p>Loading comparison data...</p>
</div>

<script>
async function loadBenchmarks() {
    try {
        const data = await fetch('/api/benchmarks').then(r => r.json());
        if (!data || !data.velocity) {
            dimPlaceholders();
            return;
        }

        // Velocity
        if (data.velocity.context_warmup_latencies && data.velocity.context_warmup_latencies.length > 0) {
            const avg = data.velocity.context_warmup_latencies.reduce((s, l) => s + l.latency_ms, 0) / data.velocity.context_warmup_latencies.length;
            setText('warmup', avg.toFixed(1) + 'ms');
        }
        if (data.velocity.review_turnarounds && data.velocity.review_turnarounds.length > 0) {
            const avg = data.velocity.review_turnarounds.reduce((s, r) => s + r.turnaround_ms, 0) / data.velocity.review_turnarounds.length;
            setText('review-time', avg.toFixed(1) + 'ms');
        }
        if (data.velocity.impact_analysis_times && data.velocity.impact_analysis_times.length > 0) {
            const avg = data.velocity.impact_analysis_times.reduce((s, i) => s + i.analysis_ms, 0) / data.velocity.impact_analysis_times.length;
            setText('impact-time', avg.toFixed(1) + 'ms');
        }

        // Reliability
        if (data.reliability) {
            if (data.reliability.dependency_coverage) {
                setText('dep-coverage', data.reliability.dependency_coverage.coverage_pct.toFixed(1) + '%');
            }
            if (data.reliability.test_coverage) {
                setText('test-coverage', data.reliability.test_coverage.coverage_pct.toFixed(1) + '%');
            }
            if (data.reliability.dead_code) {
                setText('dead-code', String(data.reliability.dead_code.detected_dead));
            }
        }

        // Economic
        if (data.economic) {
            if (data.economic.token_savings) {
                setText('token-savings', data.economic.token_savings.savings_pct.toFixed(1) + '%');
            }
            if (data.economic.cicd_savings) {
                setText('cicd-savings', data.economic.cicd_savings.savings_pct.toFixed(1) + '%');
            }
            if (data.economic.token_to_logic) {
                setText('token-ratio', data.economic.token_to_logic.ratio.toFixed(1));
            }
        }

        loadDashboardComparison();
        dimPlaceholders();
    } catch(e) {
        loadDashboardComparison();
        dimPlaceholders();
    }
}

async function loadDashboardComparison() {
    const el = document.getElementById('assistant-comparison');
    try {
        const dashboard = await fetch('/api/dashboard').then(r => r.json());
        if (dashboard && dashboard.assistant_task_comparisons && dashboard.assistant_task_comparisons.length > 0) {
            let html = '<table><tr><th>Task</th><th>Assistant</th><th>Git Duration</th><th>Kin Duration</th><th>Duration Saved%</th><th>Tokens Saved%</th></tr>';
            for (const c of dashboard.assistant_task_comparisons) {
                const durSaved = c.duration_saved_pct_by_kin != null ? c.duration_saved_pct_by_kin.toFixed(1) + '%' : '-';
                const tokSaved = c.tokens_saved_pct_by_kin != null ? c.tokens_saved_pct_by_kin.toFixed(1) + '%' : '-';
                html += '<tr><td>' + (c.task_name || '-') + '</td><td>' + (c.assistant_name || '-') + '</td><td>' + (c.git_avg_duration_ms || '-') + '</td><td>' + (c.kin_avg_duration_ms || '-') + '</td><td>' + durSaved + '</td><td>' + tokSaved + '</td></tr>';
            }
            html += '</table>';
            el.innerHTML = html;
        } else {
            el.innerHTML = '<p style="color: #8b949e;">No assistant comparison data yet. Use <code>kin bench capture</code> to record runs.</p>';
        }
    } catch(e) {
        el.innerHTML = '<p style="color: #8b949e;">No assistant comparison data yet. Use <code>kin bench capture</code> to record runs.</p>';
    }
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) { el.textContent = text; el.style.color = '#58a6ff'; }
}

function dimPlaceholders() {
    document.querySelectorAll('.value').forEach(el => {
        if (el.textContent === '--') { el.style.color = '#484f58'; }
    });
}

document.addEventListener('DOMContentLoaded', loadBenchmarks);
</script>
"#;

const TRAFFIC_CONTENT: &str = r#"
<h1>Live Traffic</h1>
<p>Active agent sessions and their intents. Shows who is working on what.</p>

<h2>Active Sessions</h2>
<div class="card" id="sessions-section">
    <p id="loading">Connecting to daemon...</p>
</div>

<h2>Lock Map</h2>
<p>Entities and files currently locked by active intents.</p>
<div class="card" id="lock-map">
    <p id="loading">Loading lock map...</p>
</div>

<h2>Intent Feed</h2>
<div class="card" id="intent-feed">
    <p id="loading">Loading intents...</p>
</div>

<script>
async function loadTraffic() {
    try {
        const sessions = await fetch('/api/sessions').then(r => r.json());
        const el = document.getElementById('sessions-section');
        if (Array.isArray(sessions) && sessions.length > 0) {
            const tbl = document.createElement('table');
            const hdr = tbl.insertRow();
            ['Vendor','Client','Transport','PID','CWD','Last Heartbeat'].forEach(h => {
                const th = document.createElement('th');
                th.textContent = h;
                hdr.appendChild(th);
            });
            for (const s of sessions) {
                const row = tbl.insertRow();
                [s.vendor, s.client_name, s.transport, s.pid, s.cwd, s.last_heartbeat].forEach(v => {
                    const td = row.insertCell();
                    td.textContent = v || '-';
                });
            }
            el.replaceChildren(tbl);
        } else {
            el.textContent = 'No active sessions. Agents will appear here when they connect.';
        }
    } catch(e) {
        document.getElementById('sessions-section').textContent = 'Could not connect to daemon';
    }

    try {
        const traffic = await fetch('/api/traffic').then(r => r.json());
        const lockEl = document.getElementById('lock-map');
        const feedEl = document.getElementById('intent-feed');
        if (traffic && traffic.intents && traffic.intents.length > 0) {
            const lockTbl = document.createElement('table');
            const lockHdr = lockTbl.insertRow();
            ['Target','Lock','Vendor','Task'].forEach(h => {
                const th = document.createElement('th');
                th.textContent = h;
                lockHdr.appendChild(th);
            });
            for (const intent of traffic.intents) {
                const lockLabel = intent.lock_type === 'Hard' ? 'HARD' : 'SOFT';
                for (const scope of (intent.scopes || [])) {
                    const row = lockTbl.insertRow();
                    [formatScope(scope), lockLabel, intent.vendor, intent.task_description].forEach(v => {
                        const td = row.insertCell();
                        td.textContent = v || '-';
                    });
                }
            }
            lockEl.replaceChildren(lockTbl);

            const feedTbl = document.createElement('table');
            const feedHdr = feedTbl.insertRow();
            ['Intent','Session','Vendor','Lock','Description','Registered'].forEach(h => {
                const th = document.createElement('th');
                th.textContent = h;
                feedHdr.appendChild(th);
            });
            for (const intent of traffic.intents) {
                const row = feedTbl.insertRow();
                [shortId(intent.intent_id), shortId(intent.session_id), intent.vendor, intent.lock_type, intent.task_description, intent.registered_at].forEach(v => {
                    const td = row.insertCell();
                    td.textContent = v || '-';
                });
            }
            feedEl.replaceChildren(feedTbl);
        } else {
            lockEl.textContent = 'No active locks.';
            feedEl.textContent = 'No active intents.';
        }
    } catch(e) {
        document.getElementById('lock-map').textContent = 'Could not load traffic data';
        document.getElementById('intent-feed').textContent = '';
    }
}

function shortId(id) {
    if (!id) return '-';
    return id.length > 8 ? id.substring(0, 8) + '...' : id;
}

function formatScope(scope) {
    if (typeof scope === 'object') {
        if (scope.Entity) return 'Entity: ' + shortId(scope.Entity);
        if (scope.Contract) return 'Contract: ' + shortId(scope.Contract);
        if (scope.Artifact) return 'File: ' + scope.Artifact;
    }
    return String(scope);
}

loadTraffic();
setInterval(loadTraffic, 5000);
</script>
"#;

const WORK_CONTENT: &str = r#"
<h1>Work Items</h1>
<p>Features, tasks, issues, and debt tracked in the semantic graph.</p>

<h2>Overview</h2>
<div class="grid" id="work-summary">
    <div class="card"><h3>Total Items</h3><div class="value" id="total-work">--</div></div>
    <div class="card"><h3>Open</h3><div class="value" id="open-work">--</div></div>
    <div class="card"><h3>In Progress</h3><div class="value" id="progress-work">--</div></div>
    <div class="card"><h3>Done</h3><div class="value" id="done-work">--</div></div>
</div>

<h2>Active Work Items</h2>
<div class="card" id="work-list">
    <table>
        <tr>
            <th>Kind</th>
            <th>Title</th>
            <th>Status</th>
            <th>Priority</th>
            <th>Scopes</th>
        </tr>
    </table>
    <p style="color: #8b949e; margin-top: 8px;">Connect to daemon for live data. Use <code>kin work list</code> or <code>kin work create</code> to manage work items.</p>
</div>

<h2>Acceptance Criteria</h2>
<div class="card" id="criteria-section">
    <p style="color: #8b949e;">Select a work item above to view its acceptance criteria and linked proof.</p>
</div>
"#;

const VERIFICATION_CONTENT: &str = r#"
<h1>Verification</h1>
<p>Test coverage and proof status for entities in the semantic graph.</p>

<h2>Coverage Summary</h2>
<div class="grid" id="coverage-summary">
    <div class="card"><h3>Total Entities</h3><div class="value" id="total-entities">--</div></div>
    <div class="card"><h3>Covered</h3><div class="value" id="covered-entities" style="color: #3fb950;">--</div></div>
    <div class="card"><h3>Missing Proof</h3><div class="value" id="missing-entities" style="color: #f85149;">--</div></div>
    <div class="card"><h3>Coverage Ratio</h3><div class="value" id="coverage-ratio">--</div></div>
</div>

<h2>Test Status by Entity</h2>
<div class="card" id="test-status">
    <table>
        <tr>
            <th>Status</th>
            <th>Entity</th>
            <th>Kind</th>
            <th>Tests</th>
            <th>Runner</th>
        </tr>
    </table>
    <p style="color: #8b949e; margin-top: 8px;">Connect to daemon for live data. Use <code>kin verify</code> to check coverage from the CLI.</p>
</div>

<h2>Missing Proof</h2>
<div class="card" id="missing-proof">
    <p style="color: #8b949e;">Entities without linked tests will appear here. Use <code>kin verify --missing</code> to list them.</p>
</div>
"#;

const PROVENANCE_CONTENT: &str = r#"
<h1>Provenance</h1>
<p>Actors, delegations, approvals, and audit trail for the repository.</p>

<h2>Actors</h2>
<div class="card" id="actors-section">
    <table>
        <tr>
            <th>Actor</th>
            <th>Kind</th>
            <th>Display Name</th>
            <th>Delegations</th>
        </tr>
    </table>
    <p style="color: #8b949e; margin-top: 8px;">Connect to daemon for live data. Use <code>kin audit</code> to query events from the CLI.</p>
</div>

<h2>Recent Approvals</h2>
<div class="card" id="approvals-section">
    <table>
        <tr>
            <th>Change</th>
            <th>Approver</th>
            <th>Decision</th>
            <th>Reason</th>
            <th>Timestamp</th>
        </tr>
    </table>
    <p style="color: #8b949e; margin-top: 8px;">Use <code>kin approvals show &lt;change-id&gt;</code> to view approvals for a specific change.</p>
</div>

<h2>Audit Trail</h2>
<div class="card" id="audit-section">
    <table>
        <tr>
            <th>Event</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Timestamp</th>
        </tr>
    </table>
    <p style="color: #8b949e; margin-top: 8px;">Use <code>kin audit --limit N</code> to query the audit log.</p>
</div>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_page_renders() {
        let html = dashboard_page();
        assert!(html.0.contains("Dashboard"));
        assert!(html.0.contains("<nav>"));
    }

    #[test]
    fn graph_page_renders() {
        let html = graph_page();
        assert!(html.0.contains("Graph Visualization"));
    }

    #[test]
    fn review_page_renders() {
        let html = review_page();
        assert!(html.0.contains("Semantic Review"));
    }

    #[test]
    fn benchmarks_page_renders() {
        let html = benchmarks_page();
        assert!(html.0.contains("Benchmarks"));
        assert!(html.0.contains("Developer Velocity"));
    }

    #[test]
    fn traffic_page_renders() {
        let html = traffic_page();
        assert!(html.0.contains("Live Traffic"));
        assert!(html.0.contains("Active Sessions"));
        assert!(html.0.contains("Lock Map"));
    }

    #[test]
    fn work_page_renders() {
        let html = work_page();
        assert!(html.0.contains("Work Items"));
        assert!(html.0.contains("Acceptance Criteria"));
    }

    #[test]
    fn verification_page_renders() {
        let html = verification_page();
        assert!(html.0.contains("Verification"));
        assert!(html.0.contains("Coverage Summary"));
        assert!(html.0.contains("Missing Proof"));
    }

    #[test]
    fn provenance_page_renders() {
        let html = provenance_page();
        assert!(html.0.contains("Provenance"));
        assert!(html.0.contains("Actors"));
        assert!(html.0.contains("Audit Trail"));
    }

    #[test]
    fn all_pages_have_nav() {
        for page in [
            dashboard_page(),
            graph_page(),
            review_page(),
            benchmarks_page(),
            traffic_page(),
            work_page(),
            verification_page(),
            provenance_page(),
        ] {
            assert!(page.0.contains("/graph"));
            assert!(page.0.contains("/review"));
            assert!(page.0.contains("/benchmarks"));
            assert!(page.0.contains("/traffic"));
            assert!(page.0.contains("/work"));
            assert!(page.0.contains("/verification"));
            assert!(page.0.contains("/provenance"));
        }
    }
}
