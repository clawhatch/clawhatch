/**
 * Scanner for markdown files (SOUL.md, AGENTS.md, TOOLS.md, etc.)
 * Looks for secrets, API keys, and sensitive patterns.
 */

import { readFile } from "node:fs/promises";

export interface MarkdownScanResult {
  filePath: string;
  content: string;
  secretMatches: SecretMatch[];
}

export interface SecretMatch {
  pattern: string;
  line: number;
  /** Masked preview — never the full secret */
  preview: string;
}

/**
 * Regex patterns for common API keys and secrets.
 * Each pattern has a name and a regex that matches likely secret values.
 */
const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  // Generic API key patterns
  { name: "Generic API Key", regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?/gi },
  { name: "Generic Secret", regex: /(?:secret|password|passwd|token)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{16,})["']?/gi },

  // Specific provider patterns
  { name: "OpenAI Key", regex: /sk-[a-zA-Z0-9]{32,}/g },
  { name: "Anthropic Key", regex: /sk-ant-[a-zA-Z0-9\-]{32,}/g },
  { name: "Google AI Key", regex: /AIza[a-zA-Z0-9_\-]{35}/g },
  { name: "Gemini Key", regex: /(?:gemini|google)[_-]?(?:api[_-]?)?key\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?/gi },
  { name: "AWS Access Key", regex: /AKIA[A-Z0-9]{16}/g },
  { name: "AWS Secret Key", regex: /(?:aws[_-]?secret|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{40})["']?/gi },
  { name: "Stripe Key", regex: /(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}/g },
  { name: "GitHub Token", regex: /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}/g },
  { name: "Slack Token", regex: /xox[bpras]-[a-zA-Z0-9\-]{10,}/g },
  { name: "Discord Token", regex: /[MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}/g },
  { name: "Telegram Bot Token", regex: /\d{8,10}:[a-zA-Z0-9_-]{35}/g },
  { name: "Private Key Block", regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g },
  { name: "Bearer Token", regex: /(?:bearer|authorization)\s*[:=]\s*["']?bearer\s+([a-zA-Z0-9_\-.]{20,})["']?/gi },

  // High-entropy hex strings (potential keys)
  { name: "Hex Secret (64 chars)", regex: /(?:key|secret|token|hash)\s*[:=]\s*["']?([0-9a-f]{64})["']?/gi },
];

export async function scanMarkdown(
  filePath: string
): Promise<MarkdownScanResult> {
  const content = await readFile(filePath, "utf-8");
  const lines = content.split("\n");
  const secretMatches: SecretMatch[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { name, regex } of SECRET_PATTERNS) {
      // Reset regex lastIndex for global patterns
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(line)) !== null) {
        const fullMatch = match[0];
        // Mask the match — show first 8 chars + "..."
        const preview =
          fullMatch.length > 12
            ? fullMatch.slice(0, 8) + "..." + fullMatch.slice(-4)
            : fullMatch.slice(0, 4) + "****";

        secretMatches.push({
          pattern: name,
          line: i + 1,
          preview,
        });
      }
    }
  }

  return { filePath, content, secretMatches };
}
