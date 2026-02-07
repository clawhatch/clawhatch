/**
 * Tests for output formats (JSON and HTML).
 *
 * Validates the structure of --json and --format html outputs.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { generateHtmlReport } from "../reporter-html.js";
import { Severity, type ScanResult, type Finding } from "../types.js";

// Helper to create test findings
function createFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "TEST-001",
    severity: Severity.Medium,
    confidence: "high",
    category: "Test Category",
    title: "Test Finding",
    description: "Test description",
    risk: "Test risk",
    remediation: "Test remediation",
    autoFixable: false,
    ...overrides,
  };
}

// Helper to create test scan result
function createScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    timestamp: new Date().toISOString(),
    openclawVersion: "1.0.0",
    score: 85,
    findings: [],
    suggestions: [],
    filesScanned: 10,
    checksRun: 100,
    checksPassed: 95,
    duration: 150,
    platform: "linux",
    ...overrides,
  };
}

describe("JSON output format", () => {
  it("ScanResult is valid JSON-serializable", () => {
    const result = createScanResult({
      findings: [
        createFinding({ severity: Severity.Critical, id: "CRITICAL-001" }),
        createFinding({ severity: Severity.High, id: "HIGH-001" }),
      ],
      suggestions: [
        createFinding({ id: "SUGGEST-001", confidence: "low" }),
      ],
    });

    // Should serialize without errors
    const json = JSON.stringify(result);
    assert.ok(json.length > 0, "Should produce non-empty JSON");

    // Should parse back correctly
    const parsed = JSON.parse(json) as ScanResult;
    assert.strictEqual(parsed.score, 85);
    assert.strictEqual(parsed.findings.length, 2);
    assert.strictEqual(parsed.suggestions.length, 1);
  });

  it("JSON includes all required fields", () => {
    const result = createScanResult({
      findings: [createFinding()],
    });

    const json = JSON.stringify(result);
    const parsed = JSON.parse(json) as ScanResult;

    // Required ScanResult fields
    assert.ok("timestamp" in parsed, "Should have timestamp");
    assert.ok("score" in parsed, "Should have score");
    assert.ok("findings" in parsed, "Should have findings");
    assert.ok("suggestions" in parsed, "Should have suggestions");
    assert.ok("filesScanned" in parsed, "Should have filesScanned");
    assert.ok("checksRun" in parsed, "Should have checksRun");
    assert.ok("checksPassed" in parsed, "Should have checksPassed");
    assert.ok("duration" in parsed, "Should have duration");
    assert.ok("platform" in parsed, "Should have platform");
  });

  it("JSON findings have all required fields", () => {
    const result = createScanResult({
      findings: [createFinding({ file: "/path/to/file.json", line: 42 })],
    });

    const json = JSON.stringify(result);
    const parsed = JSON.parse(json) as ScanResult;
    const finding = parsed.findings[0];

    // Required Finding fields
    assert.ok("id" in finding, "Finding should have id");
    assert.ok("severity" in finding, "Finding should have severity");
    assert.ok("confidence" in finding, "Finding should have confidence");
    assert.ok("category" in finding, "Finding should have category");
    assert.ok("title" in finding, "Finding should have title");
    assert.ok("description" in finding, "Finding should have description");
    assert.ok("risk" in finding, "Finding should have risk");
    assert.ok("remediation" in finding, "Finding should have remediation");
    assert.ok("autoFixable" in finding, "Finding should have autoFixable");

    // Optional fields when present
    assert.ok("file" in finding, "Finding should have file when provided");
    assert.ok("line" in finding, "Finding should have line when provided");
  });

  it("JSON handles special characters in strings", () => {
    const result = createScanResult({
      findings: [
        createFinding({
          title: 'Finding with "quotes" and <brackets>',
          description: "Description with\nnewlines\tand\ttabs",
          file: "C:\\Users\\Test\\path with spaces\\file.json",
        }),
      ],
    });

    // Should serialize without errors
    const json = JSON.stringify(result);
    assert.ok(json.includes('\\"quotes\\"'), "Should escape quotes");
    assert.ok(json.includes("\\n"), "Should escape newlines");

    // Should parse back correctly
    const parsed = JSON.parse(json) as ScanResult;
    assert.ok(parsed.findings[0].title.includes('"quotes"'), "Should preserve quotes");
  });

  it("JSON handles empty findings arrays", () => {
    const result = createScanResult({
      findings: [],
      suggestions: [],
    });

    const json = JSON.stringify(result);
    const parsed = JSON.parse(json) as ScanResult;

    assert.strictEqual(parsed.findings.length, 0);
    assert.strictEqual(parsed.suggestions.length, 0);
  });
});

describe("HTML output format", () => {
  it("generates valid HTML document", () => {
    const result = createScanResult({
      findings: [createFinding()],
    });

    const html = generateHtmlReport(result);

    assert.ok(html.startsWith("<!DOCTYPE html>"), "Should start with DOCTYPE");
    assert.ok(html.includes("<html"), "Should have html tag");
    assert.ok(html.includes("</html>"), "Should close html tag");
    assert.ok(html.includes("<head>"), "Should have head section");
    assert.ok(html.includes("<body>"), "Should have body section");
  });

  it("includes score and grade", () => {
    const result = createScanResult({ score: 95 });

    const html = generateHtmlReport(result);

    assert.ok(html.includes("95"), "Should include score");
    assert.ok(html.includes("A+"), "Should include grade for 95");
  });

  it("includes all severity levels", () => {
    const result = createScanResult({
      findings: [
        createFinding({ severity: Severity.Critical, id: "CRIT-001" }),
        createFinding({ severity: Severity.High, id: "HIGH-001" }),
        createFinding({ severity: Severity.Medium, id: "MED-001" }),
        createFinding({ severity: Severity.Low, id: "LOW-001" }),
      ],
    });

    const html = generateHtmlReport(result);

    assert.ok(html.includes("CRITICAL"), "Should include CRITICAL severity");
    assert.ok(html.includes("HIGH"), "Should include HIGH severity");
    assert.ok(html.includes("MEDIUM"), "Should include MEDIUM severity");
    assert.ok(html.includes("LOW"), "Should include LOW severity");
  });

  it("escapes HTML in finding content", () => {
    const result = createScanResult({
      findings: [
        createFinding({
          title: "<script>alert('xss')</script>",
          description: "Description with <html> tags & special chars",
        }),
      ],
    });

    const html = generateHtmlReport(result);

    // Should escape HTML entities
    assert.ok(!html.includes("<script>alert"), "Should escape script tags");
    assert.ok(html.includes("&lt;script&gt;"), "Should convert < to &lt;");
    assert.ok(html.includes("&amp;"), "Should convert & to &amp;");
  });

  it("includes metadata section", () => {
    const result = createScanResult({
      openclawVersion: "1.2.3",
      platform: "linux",
      duration: 500,
      filesScanned: 25,
    });

    const html = generateHtmlReport(result);

    assert.ok(html.includes("1.2.3"), "Should include OpenClaw version");
    assert.ok(html.includes("linux"), "Should include platform");
    assert.ok(html.includes("500"), "Should include duration");
    assert.ok(html.includes("25"), "Should include files scanned count");
  });

  it("includes suggestions section when present", () => {
    const result = createScanResult({
      suggestions: [
        createFinding({ id: "SUGGEST-001", confidence: "low", title: "Suggestion title" }),
      ],
    });

    const html = generateHtmlReport(result);

    assert.ok(html.includes("Suggestion"), "Should include suggestions");
    assert.ok(html.includes("Suggestion title"), "Should include suggestion content");
  });

  it("shows success message when no findings", () => {
    const result = createScanResult({
      findings: [],
      score: 100,
    });

    const html = generateHtmlReport(result);

    assert.ok(
      html.includes("No security findings") || html.includes("looks solid"),
      "Should show success message"
    );
  });

  it("marks auto-fixable findings", () => {
    const result = createScanResult({
      findings: [createFinding({ autoFixable: true })],
    });

    const html = generateHtmlReport(result);

    assert.ok(
      html.includes("AUTO-FIXABLE") || html.includes("auto-fix") || html.includes("--fix"),
      "Should mark auto-fixable findings"
    );
  });

  it("includes file path when present", () => {
    const result = createScanResult({
      findings: [createFinding({ file: "/path/to/config.json", line: 10 })],
    });

    const html = generateHtmlReport(result);

    assert.ok(html.includes("config.json"), "Should include filename");
    // Line number may or may not be shown depending on implementation
  });

  it("generates self-contained HTML (inline CSS)", () => {
    const result = createScanResult({
      findings: [createFinding()],
    });

    const html = generateHtmlReport(result);

    assert.ok(html.includes("<style>"), "Should have inline styles");
    assert.ok(!html.includes('href=".css"'), "Should not reference external CSS");
    assert.ok(!html.includes('src=".js"'), "Should not reference external JS");
  });

  it("includes version in footer", () => {
    const result = createScanResult();

    const html = generateHtmlReport(result);

    assert.ok(html.includes("v0.1.0") || html.includes("Clawhatch"), "Should include version in footer");
  });
});
