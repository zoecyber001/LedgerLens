"""Interactive Standalone HTML Dashboard Generator for LedgerLens v2.0."""

import json
from pathlib import Path

from ledgerlens.models import AuditReport, RiskTier


def generate_html_report(report: AuditReport, output_dir: Path) -> Path:
    """Generate an interactive, standalone HTML compliance dashboard.

    Args:
        report: The complete AuditReport model.
        output_dir: Output directory path.

    Returns:
        Path to the generated HTML file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "audit_dashboard.html"

    findings_json = json.dumps([f.to_dict() for f in report.findings])
    summary_json = json.dumps(report.to_dict()["summary"])
    metadata_json = json.dumps(report.to_dict()["metadata"])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LedgerLens Audit Return — {report.target.fingerprint}</title>
    <style>
        :root {{
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --bg-hover: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: var(--font);
            background-color: var(--bg-main);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}

        .title-group h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            letter-spacing: -0.025em;
        }}

        .title-group p {{
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }}

        .badge-score {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            text-align: right;
        }}

        .badge-score .score {{
            font-size: 1.5rem;
            font-weight: 800;
            color: var(--accent);
        }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .metric-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            padding: 1.25rem;
            border-radius: 0.5rem;
        }}

        .metric-card span {{
            display: block;
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .metric-card div {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-top: 0.25rem;
        }}

        .controls {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }}

        .search-box {{
            flex: 1;
            min-width: 250px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.625rem 1rem;
            border-radius: 0.375rem;
            font-family: inherit;
            font-size: 0.875rem;
        }}

        .search-box:focus {{
            outline: None;
            border-color: var(--accent);
        }}

        .filter-tabs {{
            display: flex;
            gap: 0.5rem;
        }}

        .tab-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.625rem 1rem;
            border-radius: 0.375rem;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.15s ease;
        }}

        .tab-btn:hover, .tab-btn.active {{
            color: var(--text-main);
            border-color: var(--accent);
            background: var(--bg-hover);
        }}

        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-left: 4px solid var(--border);
            border-radius: 0.5rem;
            padding: 1.25rem;
        }}

        .finding-card.CRITICAL {{ border-left-color: var(--critical); }}
        .finding-card.HIGH {{ border-left-color: var(--high); }}
        .finding-card.MEDIUM {{ border-left-color: var(--medium); }}
        .finding-card.LOW {{ border-left-color: var(--low); }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.75rem;
        }}

        .finding-title {{
            font-size: 1rem;
            font-weight: 600;
        }}

        .risk-badge {{
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 0.25rem;
            text-transform: uppercase;
        }}

        .risk-badge.CRITICAL {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); }}
        .risk-badge.HIGH {{ background: rgba(249, 115, 22, 0.2); color: var(--high); }}
        .risk-badge.MEDIUM {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); }}
        .risk-badge.LOW {{ background: rgba(34, 197, 94, 0.2); color: var(--low); }}

        .finding-meta {{
            font-size: 0.8125rem;
            color: var(--text-muted);
            margin-bottom: 0.75rem;
        }}

        .finding-desc {{
            font-size: 0.875rem;
            margin-bottom: 1rem;
        }}

        .remediation-box {{
            background: var(--bg-main);
            border: 1px solid var(--border);
            padding: 0.75rem 1rem;
            border-radius: 0.375rem;
            font-size: 0.8125rem;
        }}

        .remediation-box strong {{
            color: var(--accent);
        }}

        footer {{
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8125rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="title-group">
                <h1>LedgerLens Financial Audit Return</h1>
                <p>Target: {report.target.root_path} &bull; Fingerprint: {report.target.fingerprint}</p>
            </div>
            <div class="badge-score">
                <span style="font-size:0.75rem; color:var(--text-muted);">COMPLIANCE SCORE</span>
                <div class="score">{report.compliance_score}%</div>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <span>Files Scanned</span>
                <div>{report.total_files_scanned}</div>
            </div>
            <div class="metric-card">
                <span>Tables Audited</span>
                <div>{report.total_tables_audited}</div>
            </div>
            <div class="metric-card">
                <span>Ledger Tables</span>
                <div>{report.total_ledger_tables_found}</div>
            </div>
            <div class="metric-card">
                <span>Redacted Tokens</span>
                <div>{report.total_secrets_redacted}</div>
            </div>
            <div class="metric-card">
                <span>Overall Risk</span>
                <div style="color: var(--{report.overall_risk_tier.value.lower()});">{report.overall_risk_tier.value}</div>
            </div>
        </div>

        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Search findings, tables, rules...">
            <div class="filter-tabs">
                <button class="tab-btn active" onclick="filterTier('ALL')">All ({len(report.findings)})</button>
                <button class="tab-btn" onclick="filterTier('CRITICAL')">Critical ({report.risk_summary['CRITICAL']})</button>
                <button class="tab-btn" onclick="filterTier('HIGH')">High ({report.risk_summary['HIGH']})</button>
                <button class="tab-btn" onclick="filterTier('MEDIUM')">Medium ({report.risk_summary['MEDIUM']})</button>
            </div>
        </div>

        <div id="findingsList" class="findings-list"></div>

        <footer>
            Generated by LedgerLens v2.0 &bull; Financial Ledger & DB Integrity Audit Engine
        </footer>
    </div>

    <script>
        const findings = {findings_json};
        let currentTier = 'ALL';

        function renderFindings() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const list = document.getElementById('findingsList');
            list.innerHTML = '';

            const filtered = findings.filter(f => {{
                const matchTier = currentTier === 'ALL' || f.risk_tier === currentTier;
                const matchQuery = !query || 
                    f.title.toLowerCase().includes(query) || 
                    f.rule_id.toLowerCase().includes(query) || 
                    (f.table_name && f.table_name.toLowerCase().includes(query)) ||
                    f.description.toLowerCase().includes(query);
                return matchTier && matchQuery;
            }});

            if (filtered.length === 0) {{
                list.innerHTML = '<div style="text-align:center; padding:3rem; color:var(--text-muted);">No compliance findings match the selected filter.</div>';
                return;
            }}

            filtered.forEach(f => {{
                const card = document.createElement('div');
                card.className = `finding-card ${{f.risk_tier}}`;
                card.innerHTML = `
                    <div class="finding-header">
                        <div class="finding-title">[${{f.rule_id}}] ${{f.title}}</div>
                        <span class="risk-badge ${{f.risk_tier}}">${{f.risk_tier}}</span>
                    </div>
                    <div class="finding-meta">
                        Framework: ${{f.framework}} &bull; File: ${{f.file_path}} ${{f.table_name ? '&bull; Table: ' + f.table_name : ''}}
                    </div>
                    <div class="finding-desc">${{f.description}}</div>
                    <div class="remediation-box">
                        <strong>Remediation:</strong> ${{f.remediation}}<br>
                        <span style="color:var(--text-muted); font-size:0.75rem;">Reference: ${{f.reference}}</span>
                    </div>
                `;
                list.appendChild(card);
            }});
        }}

        function filterTier(tier) {{
            currentTier = tier;
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            renderFindings();
        }}

        document.getElementById('searchInput').addEventListener('input', renderFindings);
        renderFindings();
    </script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
