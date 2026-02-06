/**
 * HTML report generator.
 *
 * Produces a self-contained HTML file with inline CSS.
 * No external dependencies — single file, works offline.
 */

import { Severity, type Finding, type ScanResult } from "./types.js";
import { getScoreGrade } from "./scoring.js";

const SEVERITY_COLORS: Record<Severity, string> = {
  [Severity.Critical]: "#ff2d87",
  [Severity.High]: "#ffe135",
  [Severity.Medium]: "#00e5ff",
  [Severity.Low]: "#888",
};

const SEVERITY_ORDER = [
  Severity.Critical,
  Severity.High,
  Severity.Medium,
  Severity.Low,
];

const GRADE_COLORS: Record<string, string> = {
  green: "#00e5ff",
  yellow: "#ffe135",
  red: "#ff2d87",
  magenta: "#b44dff",
};

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function groupBySeverity(findings: Finding[]): Map<Severity, Finding[]> {
  const groups = new Map<Severity, Finding[]>();
  for (const sev of SEVERITY_ORDER) {
    groups.set(sev, []);
  }
  for (const f of findings) {
    groups.get(f.severity)!.push(f);
  }
  return groups;
}

function renderFindingCard(finding: Finding): string {
  const sevColor = SEVERITY_COLORS[finding.severity];
  const fileLoc = finding.file
    ? finding.line
      ? `${escapeHtml(finding.file)}:${finding.line}`
      : escapeHtml(finding.file)
    : null;

  return `
    <div class="finding-card">
      <div class="finding-header">
        <span class="severity-badge" style="background:${sevColor}">${escapeHtml(finding.severity)}</span>
        ${finding.autoFixable ? '<span class="autofix-badge">AUTO-FIXABLE</span>' : ""}
      </div>
      <h3 class="finding-title">${escapeHtml(finding.title)}</h3>
      <p class="finding-desc">${escapeHtml(finding.description)}</p>
      <div class="finding-meta">
        <div class="meta-row"><span class="meta-label">Risk</span><span class="meta-value">${escapeHtml(finding.risk)}</span></div>
        <div class="meta-row"><span class="meta-label">Fix</span><span class="meta-value">${escapeHtml(finding.remediation)}</span></div>
        ${fileLoc ? `<div class="meta-row"><span class="meta-label">File</span><span class="meta-value file-path">${fileLoc}</span></div>` : ""}
      </div>
    </div>`;
}

export function generateHtmlReport(result: ScanResult): string {
  const { grade, label, color } = getScoreGrade(result.score);
  const gradeColor = GRADE_COLORS[color];

  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of result.findings) {
    const key = f.severity.toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
  }

  const grouped = groupBySeverity(result.findings);

  let findingsHtml = "";
  for (const [severity, findings] of grouped) {
    if (findings.length === 0) continue;
    const sevColor = SEVERITY_COLORS[severity];
    findingsHtml += `
      <div class="severity-group">
        <h2 class="severity-heading" style="color:${sevColor}">
          ${escapeHtml(severity)} <span class="count">(${findings.length})</span>
        </h2>
        ${findings.map(renderFindingCard).join("\n")}
      </div>`;
  }

  if (result.findings.length === 0) {
    findingsHtml = `
      <div class="no-findings">
        <div class="check-icon">&#10003;</div>
        <p>No security findings! Your setup looks solid.</p>
      </div>`;
  }

  let suggestionsHtml = "";
  if (result.suggestions.length > 0) {
    const suggestionCards = result.suggestions
      .map(
        (s) => `
        <div class="suggestion-card">
          <h4>${escapeHtml(s.title)}</h4>
          <p>${escapeHtml(s.remediation)}</p>
        </div>`
      )
      .join("\n");

    suggestionsHtml = `
      <details class="suggestions-section">
        <summary class="suggestions-toggle">
          Suggestions (${result.suggestions.length} — lower confidence, review manually)
        </summary>
        <div class="suggestions-list">
          ${suggestionCards}
        </div>
      </details>`;
  }

  const autoFixCount = result.findings.filter((f) => f.autoFixable).length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Clawhatch Security Report — ${escapeHtml(grade)} (${result.score}/100)</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: #0a0a0f;
      color: #e0e0e0;
      line-height: 1.6;
      min-height: 100vh;
    }

    .container {
      max-width: 860px;
      margin: 0 auto;
      padding: 32px 20px;
    }

    /* Header */
    .header {
      text-align: center;
      margin-bottom: 40px;
    }

    .header h1 {
      font-size: 24px;
      font-weight: 700;
      color: #00e5ff;
      margin-bottom: 24px;
      letter-spacing: 0.5px;
    }

    .score-circle {
      width: 140px;
      height: 140px;
      border-radius: 50%;
      border: 4px solid ${gradeColor};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      margin: 0 auto 16px;
      box-shadow: 0 0 30px ${gradeColor}33;
    }

    .score-number {
      font-size: 42px;
      font-weight: 800;
      color: ${gradeColor};
      line-height: 1;
    }

    .score-max {
      font-size: 14px;
      color: #888;
    }

    .grade-label {
      font-size: 20px;
      font-weight: 700;
      color: ${gradeColor};
      margin-bottom: 4px;
    }

    .grade-sublabel {
      font-size: 14px;
      color: #888;
    }

    /* Metadata */
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 32px;
    }

    .meta-card {
      background: #12121a;
      border-radius: 8px;
      padding: 14px 18px;
      border: 1px solid #1e1e2e;
    }

    .meta-card .mc-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: #666;
      margin-bottom: 4px;
    }

    .meta-card .mc-value {
      font-size: 15px;
      color: #e0e0e0;
      font-weight: 500;
    }

    /* Summary bar */
    .summary-bar {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      justify-content: center;
      margin-bottom: 36px;
      padding: 18px;
      background: #12121a;
      border-radius: 10px;
      border: 1px solid #1e1e2e;
    }

    .summary-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .summary-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    .summary-count {
      font-size: 20px;
      font-weight: 700;
    }

    .summary-label {
      font-size: 12px;
      color: #888;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    /* Findings */
    .findings-section {
      margin-bottom: 32px;
    }

    .severity-group {
      margin-bottom: 24px;
    }

    .severity-heading {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid #1e1e2e;
    }

    .severity-heading .count {
      font-weight: 400;
      opacity: 0.7;
    }

    .finding-card {
      background: #12121a;
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 12px;
      border: 1px solid #1e1e2e;
      transition: border-color 0.2s;
    }

    .finding-card:hover {
      border-color: #333;
    }

    .finding-header {
      display: flex;
      gap: 8px;
      align-items: center;
      margin-bottom: 10px;
    }

    .severity-badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 700;
      color: #0a0a0f;
      letter-spacing: 0.5px;
    }

    .autofix-badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      background: #1a3a2a;
      color: #4ade80;
      letter-spacing: 0.5px;
    }

    .finding-title {
      font-size: 16px;
      font-weight: 600;
      color: #fff;
      margin-bottom: 6px;
    }

    .finding-desc {
      font-size: 13px;
      color: #999;
      margin-bottom: 14px;
    }

    .finding-meta {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .meta-row {
      display: flex;
      gap: 12px;
      font-size: 13px;
    }

    .meta-label {
      color: #666;
      min-width: 36px;
      font-weight: 600;
    }

    .meta-value {
      color: #ccc;
    }

    .file-path {
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
      font-size: 12px;
      color: #b44dff;
    }

    .no-findings {
      text-align: center;
      padding: 48px 20px;
      background: #12121a;
      border-radius: 10px;
      border: 1px solid #1e1e2e;
    }

    .no-findings .check-icon {
      font-size: 48px;
      color: #00e5ff;
      margin-bottom: 12px;
    }

    .no-findings p {
      font-size: 16px;
      color: #999;
    }

    /* Suggestions */
    .suggestions-section {
      margin-bottom: 32px;
    }

    .suggestions-toggle {
      cursor: pointer;
      font-size: 14px;
      font-weight: 600;
      color: #888;
      padding: 14px 18px;
      background: #12121a;
      border-radius: 10px;
      border: 1px solid #1e1e2e;
      list-style: none;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .suggestions-toggle::-webkit-details-marker { display: none; }

    .suggestions-toggle::before {
      content: '\\25B6';
      font-size: 10px;
      transition: transform 0.2s;
    }

    details[open] .suggestions-toggle::before {
      transform: rotate(90deg);
    }

    .suggestions-list {
      padding: 12px 0 0;
    }

    .suggestion-card {
      background: #12121a;
      border-radius: 8px;
      padding: 14px 18px;
      margin-bottom: 8px;
      border: 1px solid #1e1e2e;
    }

    .suggestion-card h4 {
      font-size: 14px;
      font-weight: 600;
      color: #ccc;
      margin-bottom: 4px;
    }

    .suggestion-card p {
      font-size: 13px;
      color: #888;
    }

    /* Footer */
    .footer {
      text-align: center;
      padding-top: 24px;
      border-top: 1px solid #1e1e2e;
      margin-top: 16px;
    }

    .footer p {
      font-size: 12px;
      color: #555;
    }

    .footer .autofix-note {
      color: #4ade80;
      font-size: 13px;
      margin-bottom: 8px;
    }

    /* Print styles */
    @media print {
      body {
        background: #fff;
        color: #222;
      }
      .container { max-width: 100%; padding: 16px; }
      .score-circle {
        border-color: #333;
        box-shadow: none;
      }
      .score-number, .grade-label { color: #222; }
      .meta-card, .finding-card, .summary-bar, .suggestion-card, .suggestions-toggle {
        background: #f5f5f5;
        border-color: #ddd;
        color: #222;
      }
      .finding-card:hover { border-color: #ddd; }
      .meta-card .mc-label, .meta-label, .summary-label { color: #666; }
      .meta-card .mc-value, .finding-title, .meta-value, .suggestion-card h4 { color: #222; }
      .finding-desc, .suggestion-card p, .grade-sublabel, .score-max { color: #555; }
      .severity-badge { color: #fff !important; }
      .no-findings { background: #f5f5f5; border-color: #ddd; }
      .no-findings .check-icon { color: #333; }
      .no-findings p { color: #555; }
      .footer { border-top-color: #ddd; }
      .footer p { color: #888; }
      .severity-heading { border-bottom-color: #ddd; }
      details[open] .suggestions-list { display: block; }
    }

    /* Responsive */
    @media (max-width: 600px) {
      .container { padding: 16px 12px; }
      .header h1 { font-size: 18px; }
      .score-circle { width: 110px; height: 110px; }
      .score-number { font-size: 32px; }
      .meta-grid { grid-template-columns: 1fr 1fr; }
      .summary-bar { gap: 10px; padding: 12px; }
      .finding-card { padding: 14px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1>Clawhatch Security Scan</h1>
      <div class="score-circle">
        <span class="score-number">${result.score}</span>
        <span class="score-max">/ 100</span>
      </div>
      <div class="grade-label">${escapeHtml(grade)}</div>
      <div class="grade-sublabel">${escapeHtml(label)}</div>
    </header>

    <div class="meta-grid">
      <div class="meta-card">
        <div class="mc-label">Timestamp</div>
        <div class="mc-value">${escapeHtml(result.timestamp)}</div>
      </div>
      <div class="meta-card">
        <div class="mc-label">Platform</div>
        <div class="mc-value">${escapeHtml(String(result.platform))}</div>
      </div>
      <div class="meta-card">
        <div class="mc-label">OpenClaw</div>
        <div class="mc-value">${result.openclawVersion ? escapeHtml(result.openclawVersion) : "Not detected"}</div>
      </div>
      <div class="meta-card">
        <div class="mc-label">Duration</div>
        <div class="mc-value">${result.duration}ms</div>
      </div>
      <div class="meta-card">
        <div class="mc-label">Files Scanned</div>
        <div class="mc-value">${result.filesScanned}</div>
      </div>
      <div class="meta-card">
        <div class="mc-label">Checks</div>
        <div class="mc-value">${result.checksRun} run / ${result.checksPassed} passed</div>
      </div>
    </div>

    <div class="summary-bar">
      <div class="summary-item">
        <span class="summary-dot" style="background:${SEVERITY_COLORS[Severity.Critical]}"></span>
        <span class="summary-count" style="color:${SEVERITY_COLORS[Severity.Critical]}">${counts.critical}</span>
        <span class="summary-label">Critical</span>
      </div>
      <div class="summary-item">
        <span class="summary-dot" style="background:${SEVERITY_COLORS[Severity.High]}"></span>
        <span class="summary-count" style="color:${SEVERITY_COLORS[Severity.High]}">${counts.high}</span>
        <span class="summary-label">High</span>
      </div>
      <div class="summary-item">
        <span class="summary-dot" style="background:${SEVERITY_COLORS[Severity.Medium]}"></span>
        <span class="summary-count" style="color:${SEVERITY_COLORS[Severity.Medium]}">${counts.medium}</span>
        <span class="summary-label">Medium</span>
      </div>
      <div class="summary-item">
        <span class="summary-dot" style="background:${SEVERITY_COLORS[Severity.Low]}"></span>
        <span class="summary-count" style="color:${SEVERITY_COLORS[Severity.Low]}">${counts.low}</span>
        <span class="summary-label">Low</span>
      </div>
    </div>

    <section class="findings-section">
      ${findingsHtml}
    </section>

    ${suggestionsHtml}

    <footer class="footer">
      ${autoFixCount > 0 ? `<p class="autofix-note">${autoFixCount} issue(s) can be auto-fixed. Run with --fix</p>` : ""}
      <p>Generated by Clawhatch Security Scanner v0.1.0</p>
    </footer>
  </div>
</body>
</html>`;
}
