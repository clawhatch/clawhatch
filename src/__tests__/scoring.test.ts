import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { calculateScore, getScoreGrade } from "../scoring.js";
import { Severity, type Finding } from "../types.js";

function makeFinding(severity: Severity): Finding {
  return {
    id: "TEST",
    severity,
    confidence: "high",
    category: "Test",
    title: "Test",
    description: "Test",
    risk: "Test",
    remediation: "Test",
    autoFixable: false,
  };
}

describe("calculateScore", () => {
  it("returns 100 for empty findings", () => {
    assert.equal(calculateScore([]), 100);
  });

  it("caps at 40 with 1 CRITICAL finding", () => {
    const findings = [makeFinding(Severity.Critical)];
    assert.equal(calculateScore(findings), 40);
  });

  it("returns 92 with 1 HIGH finding", () => {
    const findings = [makeFinding(Severity.High)];
    assert.equal(calculateScore(findings), 92);
  });

  it("returns 97 with 1 MEDIUM finding", () => {
    const findings = [makeFinding(Severity.Medium)];
    assert.equal(calculateScore(findings), 97);
  });

  it("returns 99 with 1 LOW finding", () => {
    const findings = [makeFinding(Severity.Low)];
    assert.equal(calculateScore(findings), 99);
  });

  it("penalizes correctly with mixed findings", () => {
    const findings = [
      makeFinding(Severity.High),
      makeFinding(Severity.Medium),
      makeFinding(Severity.Low),
    ];
    // 100 - 8 - 3 - 1 = 88, no CRITICAL so no cap
    assert.equal(calculateScore(findings), 88);
  });

  it("caps mixed findings at 40 when CRITICAL is present", () => {
    const findings = [
      makeFinding(Severity.Critical),
      makeFinding(Severity.High),
      makeFinding(Severity.Low),
    ];
    // 100 - 15 - 8 - 1 = 76, but CRITICAL caps at 40
    assert.equal(calculateScore(findings), 40);
  });

  it("floors at 0 with many findings", () => {
    const findings = Array.from({ length: 20 }, () =>
      makeFinding(Severity.High)
    );
    // 100 - 20*8 = -60 -> clamped to 0
    assert.equal(calculateScore(findings), 0);
  });
});

describe("getScoreGrade", () => {
  it("returns A+ for 95", () => {
    assert.equal(getScoreGrade(95).grade, "A+");
  });

  it("returns A for 85", () => {
    assert.equal(getScoreGrade(85).grade, "A");
  });

  it("returns B for 75", () => {
    assert.equal(getScoreGrade(75).grade, "B");
  });

  it("returns C for 55", () => {
    assert.equal(getScoreGrade(55).grade, "C");
  });

  it("returns D for 35", () => {
    assert.equal(getScoreGrade(35).grade, "D");
  });

  it("returns F for 15", () => {
    assert.equal(getScoreGrade(15).grade, "F");
  });

  it("returns correct labels and colors", () => {
    const result = getScoreGrade(95);
    assert.equal(result.label, "Excellent");
    assert.equal(result.color, "green");

    const poor = getScoreGrade(35);
    assert.equal(poor.label, "Poor");
    assert.equal(poor.color, "red");

    const critical = getScoreGrade(15);
    assert.equal(critical.label, "Critical");
    assert.equal(critical.color, "magenta");
  });
});
