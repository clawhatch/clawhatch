import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { sanitizeFindings } from "../sanitize.js";
import { Severity, type Finding } from "../types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "TEST",
    severity: Severity.Medium,
    confidence: "high",
    category: "Test",
    title: "Test finding",
    description: "Test description",
    risk: "Test risk",
    remediation: "Test remediation",
    autoFixable: false,
    ...overrides,
  };
}

describe("sanitizeFindings", () => {
  it("redacts OpenAI key patterns", () => {
    const findings = [
      makeFinding({
        description: "Found key sk-abc123xyzABCDEF01234567890",
      }),
    ];
    const result = sanitizeFindings(findings);
    assert.ok(!result[0].description.includes("sk-abc123"));
    assert.ok(result[0].description.includes("[REDACTED]"));
  });

  it("redacts Anthropic key patterns", () => {
    const findings = [
      makeFinding({
        description: "Found key sk-ant-api03-abcdefghijklmnopqrst",
      }),
    ];
    const result = sanitizeFindings(findings);
    assert.ok(!result[0].description.includes("sk-ant-"));
    assert.ok(result[0].description.includes("[REDACTED]"));
  });

  it("redacts AWS key patterns", () => {
    const findings = [
      makeFinding({
        description: "Found key AKIAIOSFODNN7EXAMPLE",
      }),
    ];
    const result = sanitizeFindings(findings);
    assert.ok(!result[0].description.includes("AKIA"));
    assert.ok(result[0].description.includes("[REDACTED]"));
  });

  it("redacts private key headers", () => {
    const findings = [
      makeFinding({
        title: "Contains -----BEGIN RSA PRIVATE KEY----- in file",
      }),
    ];
    const result = sanitizeFindings(findings);
    assert.ok(!result[0].title.includes("BEGIN RSA PRIVATE KEY"));
    assert.ok(result[0].title.includes("[REDACTED]"));
  });

  it("passes through clean strings unchanged", () => {
    const findings = [
      makeFinding({
        title: "Normal finding title",
        description: "Nothing secret here",
        risk: "Some risk description",
        remediation: "Fix this thing",
      }),
    ];
    const result = sanitizeFindings(findings);
    assert.equal(result[0].title, "Normal finding title");
    assert.equal(result[0].description, "Nothing secret here");
    assert.equal(result[0].risk, "Some risk description");
    assert.equal(result[0].remediation, "Fix this thing");
  });

  it("handles empty findings array", () => {
    const result = sanitizeFindings([]);
    assert.deepEqual(result, []);
  });

  it("redacts secrets in all string fields", () => {
    const key = "sk-abc123xyzABCDEF01234567890";
    const findings = [
      makeFinding({
        title: `Key: ${key}`,
        description: `Found ${key}`,
        risk: `Exposed ${key}`,
        remediation: `Rotate ${key}`,
      }),
    ];
    const result = sanitizeFindings(findings);
    assert.ok(!result[0].title.includes("sk-abc123"));
    assert.ok(!result[0].description.includes("sk-abc123"));
    assert.ok(!result[0].risk.includes("sk-abc123"));
    assert.ok(!result[0].remediation.includes("sk-abc123"));
  });

  it("redacts GitHub token patterns", () => {
    const findings = [
      makeFinding({
        description: "Token ghp_ABCDEFghijklmnopqrstuvwxyz012345",
      }),
    ];
    const result = sanitizeFindings(findings);
    assert.ok(!result[0].description.includes("ghp_"));
    assert.ok(result[0].description.includes("[REDACTED]"));
  });
});
