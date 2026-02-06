/**
 * Parser for openclaw.json (JSON5 format).
 */

import { readFile } from "node:fs/promises";
import JSON5 from "json5";
import type { OpenClawConfig } from "../types.js";

export async function parseConfig(
  configPath: string
): Promise<OpenClawConfig | null> {
  try {
    const raw = await readFile(configPath, "utf-8");
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
