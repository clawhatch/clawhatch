/**
 * Generate a secure baseline OpenClaw configuration.
 *
 * Creates openclaw.json, .env, and .gitignore with
 * hardened defaults in the target directory.
 */

import { writeFile, mkdir, access } from "node:fs/promises";
import { join } from "node:path";
import chalk from "chalk";

const SECURE_CONFIG = {
  gateway: {
    bind: "127.0.0.1",
    port: 3000,
    auth: {
      mode: "token",
      token: "${OPENCLAW_AUTH_TOKEN}",
    },
    allowInsecureAuth: false,
    dangerouslyDisableDeviceAuth: false,
  },
  channels: {},
  sandbox: {
    mode: "all",
    workspaceAccess: "ro",
  },
  tools: {
    elevated: [],
    auditLog: true,
    timeout: 30000,
    rateLimit: 60,
  },
  retention: {
    sessionLogTTL: 2592000,
    encryptAtRest: false,
    logRotation: true,
  },
  skills: {
    sandboxed: true,
    verifySignatures: false,
    autoUpdate: false,
  },
  model: {
    default: "claude-sonnet-4-5-20250929",
  },
};

const ENV_TEMPLATE = `# OpenClaw Environment Variables
# Generate a secure token: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
OPENCLAW_AUTH_TOKEN=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
`;

const GITIGNORE_TEMPLATE = `.env
.env.*
credentials/
*.key
*.pem
*.p12
agents/*/sessions/
`;

interface InitResult {
  created: string[];
  skipped: string[];
  directory: string;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function initSecureConfig(
  targetDir: string
): Promise<InitResult> {
  const result: InitResult = { created: [], skipped: [], directory: targetDir };

  // Ensure directory exists
  await mkdir(targetDir, { recursive: true });

  // Write openclaw.json
  const configPath = join(targetDir, "openclaw.json");
  if (await fileExists(configPath)) {
    console.log(chalk.yellow(`  ! Skipping ${configPath} (already exists)`));
    result.skipped.push("openclaw.json");
  } else {
    await writeFile(configPath, JSON.stringify(SECURE_CONFIG, null, 2) + "\n");
    console.log(chalk.green(`  + Created ${configPath}`));
    result.created.push("openclaw.json");
  }

  // Write .env
  const envPath = join(targetDir, ".env");
  if (await fileExists(envPath)) {
    console.log(chalk.yellow(`  ! Skipping ${envPath} (already exists)`));
    result.skipped.push(".env");
  } else {
    await writeFile(envPath, ENV_TEMPLATE);
    console.log(chalk.green(`  + Created ${envPath}`));
    result.created.push(".env");
  }

  // Write .gitignore
  const gitignorePath = join(targetDir, ".gitignore");
  if (await fileExists(gitignorePath)) {
    console.log(chalk.yellow(`  ! Skipping ${gitignorePath} (already exists)`));
    result.skipped.push(".gitignore");
  } else {
    await writeFile(gitignorePath, GITIGNORE_TEMPLATE);
    console.log(chalk.green(`  + Created ${gitignorePath}`));
    result.created.push(".gitignore");
  }

  return result;
}
