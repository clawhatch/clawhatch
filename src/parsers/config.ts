/**
 * Parser for openclaw.json (JSON5 format).
 */

import { readFile } from "node:fs/promises";
import JSON5 from "json5";
import type { OpenClawConfig } from "../types.js";

/**
 * Check for exotic JSON5 values that could be unexpected.
 * JSON5 allows Infinity, -Infinity, NaN, and hexadecimal literals.
 * These are usually unintentional and may cause issues.
 */
export function checkExoticValues(raw: string): string[] {
  const warnings: string[] = [];

  // Check for Infinity, -Infinity, NaN (as unquoted values)
  if (/:\s*Infinity\b/.test(raw)) {
    warnings.push("Config contains 'Infinity' value — this may be unintentional");
  }
  if (/:\s*-Infinity\b/.test(raw)) {
    warnings.push("Config contains '-Infinity' value — this may be unintentional");
  }
  if (/:\s*NaN\b/.test(raw)) {
    warnings.push("Config contains 'NaN' value — this may be unintentional");
  }
  // Check for hexadecimal literals (0x...)
  if (/:\s*0x[0-9a-fA-F]+/.test(raw)) {
    warnings.push("Config contains hexadecimal literal — consider using decimal notation for clarity");
  }

  return warnings;
}

export async function parseConfig(
  configPath: string
): Promise<OpenClawConfig | null> {
  try {
    const raw = await readFile(configPath, "utf-8");

    // FIX: Check for exotic JSON5 values and log warnings
    const warnings = checkExoticValues(raw);
    for (const warning of warnings) {
      console.error(`  Warning: ${warning}`);
    }

    return JSON5.parse(raw) as OpenClawConfig;
  } catch {
    return null;
  }
}

/**
 * Read raw config text (for regex-based secret scanning).
 */
export async function readConfigRaw(
  configPath: string
): Promise<string | null> {
  try {
    return await readFile(configPath, "utf-8");
  } catch {
    return null;
  }
}
