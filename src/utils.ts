/**
 * Shared utility functions for the Clawhatch scanner.
 */

import { stat, readFile } from "node:fs/promises";
import { createReadStream } from "node:fs";

/**
 * Read at most `maxBytes` from a file without loading the entire file into memory.
 * Prevents OOM on huge session logs (which can be hundreds of MB).
 *
 * If the file is smaller than maxBytes, reads it entirely.
 * Otherwise, streams up to maxBytes and returns a truncated string.
 */
export async function readFileCapped(filePath: string, maxBytes: number): Promise<string> {
  const fileStat = await stat(filePath);
  if (fileStat.size <= maxBytes) {
    return readFile(filePath, "utf-8");
  }
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytesRead = 0;
    const stream = createReadStream(filePath, { highWaterMark: 64 * 1024 });
    stream.on("data", (chunk: string | Buffer) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytesRead += buf.length;
      chunks.push(buf);
      if (bytesRead >= maxBytes) {
        stream.destroy();
      }
    });
    stream.on("close", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    stream.on("error", reject);
  });
}
