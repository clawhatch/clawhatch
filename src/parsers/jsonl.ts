/**
 * Parser for JSONL session log files.
 * Caps reading at 1MB or 1000 lines to prevent scanner hanging on large files.
 */

import { readFile, stat } from "node:fs/promises";
import type { SessionEntry } from "../types.js";

const MAX_BYTES = 1_048_576; // 1MB
const MAX_LINES = 1000;
// FIX: Hard cap for deep mode to prevent OOM on enormous session logs
const DEEP_MAX_BYTES = 50 * 1_048_576; // 50MB

export interface JsonlParseResult {
  entries: SessionEntry[];
  truncated: boolean;
  totalSizeBytes: number;
}

export async function parseJsonl(
  filePath: string,
  deep: boolean = false
): Promise<JsonlParseResult> {
  const fileStat = await stat(filePath);
  const totalSizeBytes = fileStat.size;

  // FIX: Even in deep mode, cap at 50MB to prevent OOM
  const byteLimit = deep ? DEEP_MAX_BYTES : MAX_BYTES;

  let raw: string;
  if (totalSizeBytes > byteLimit) {
    // Read only the first 1MB
    // FIX: Don't set encoding on stream — read as Buffer for accurate byte counting,
    // then convert to string at the end. With encoding: "utf-8", chunk.length gives
    // character count not byte count, which could over-read for multi-byte content.
    const { createReadStream } = await import("node:fs");
    raw = await new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let bytesRead = 0;
      const stream = createReadStream(filePath, {
        highWaterMark: 64 * 1024,
      });
      stream.on("data", (chunk: string | Buffer) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        bytesRead += buf.length;
        chunks.push(buf);
        if (bytesRead >= byteLimit) {
          stream.destroy();
        }
      });
      stream.on("close", () => resolve(Buffer.concat(chunks).toString("utf-8")));
      stream.on("error", reject);
    });
  } else {
    raw = await readFile(filePath, "utf-8");
  }

  const lines = raw.split("\n");
  const maxLines = deep ? lines.length : MAX_LINES;
  const entries: SessionEntry[] = [];
  // FIX: Also flag truncation in deep mode if we hit the 50MB cap
  const truncated = totalSizeBytes > byteLimit || (!deep && lines.length > MAX_LINES);

  for (let i = 0; i < Math.min(lines.length, maxLines); i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      entries.push(JSON.parse(line) as SessionEntry);
    } catch {
      // Skip malformed lines
    }
  }

  return { entries, truncated, totalSizeBytes };
}
