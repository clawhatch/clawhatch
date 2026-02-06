/**
 * Score calculation engine.
 *
 * Formula:
 *   base = 100
 *   penalties: CRITICAL=-15, HIGH=-8, MEDIUM=-3, LOW=-1
 *   score = max(0, base - sum(penalties))
 *   Cap: any CRITICAL finding hard-caps score at 40
 */

import { Severity, type Finding } from "./types.js";

const PENALTIES: Record<Severity, number> = {
  [Severity.Critical]: 15,
  [Severity.High]: 8,
  [Severity.Medium]: 3,
  [Severity.Low]: 1,
};

const CRITICAL_CAP = 40;

export function calculateScore(findings: Finding[]): number {
  const base = 100;
  let totalPenalty = 0;
  let hasCritical = false;

  for (const finding of findings) {
    totalPenalty += PENALTIES[finding.severity];
    if (finding.severity === Severity.Critical) {
      hasCritical = true;
    }
  }

  let score = Math.max(0, base - totalPenalty);

  if (hasCritical && score > CRITICAL_CAP) {
    score = CRITICAL_CAP;
  }

  return score;
}

export function getScoreGrade(score: number): {
  grade: string;
  label: string;
  color: "green" | "yellow" | "red" | "magenta";
} {
  if (score >= 90)
    return { grade: "A+", label: "Excellent", color: "green" };
  if (score >= 80) return { grade: "A", label: "Good", color: "green" };
  if (score >= 70)
    return { grade: "B", label: "Acceptable", color: "yellow" };
  if (score >= 50) return { grade: "C", label: "Needs Work", color: "yellow" };
  if (score >= 30) return { grade: "D", label: "Poor", color: "red" };
  return { grade: "F", label: "Critical", color: "magenta" };
}
