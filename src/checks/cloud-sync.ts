/**
 * Cloud Sync Detection check (51).
 *
 * Detects if ~/.openclaw/ is inside a known cloud sync directory
 * (iCloud, OneDrive, Dropbox, Google Drive). If so, credentials
 * are being uploaded to the cloud in plaintext.
 */

import { Severity, type Finding } from "../types.js";
import { platform, homedir } from "node:os";
import { resolve } from "node:path";
import { stat } from "node:fs/promises";

interface CloudService {
  name: string;
  paths: string[];
}

function getCloudServices(): CloudService[] {
  const home = homedir();
  const os = platform();

  const services: CloudService[] = [];

  if (os === "darwin") {
    services.push(
      { name: "iCloud Drive", paths: [`${home}/Library/Mobile Documents`] },
      { name: "Dropbox", paths: [`${home}/Dropbox`, `${home}/Library/CloudStorage/Dropbox`] },
      { name: "OneDrive", paths: [`${home}/OneDrive`, `${home}/Library/CloudStorage/OneDrive-Personal`] },
      { name: "Google Drive", paths: [`${home}/Google Drive`, `${home}/Library/CloudStorage/GoogleDrive`] },
    );
  } else if (os === "win32") {
    services.push(
      { name: "OneDrive", paths: [`${home}\\OneDrive`, `C:\\Users\\${home.split("\\").pop()}\\OneDrive`] },
      { name: "Dropbox", paths: [`${home}\\Dropbox`] },
      { name: "Google Drive", paths: [`${home}\\Google Drive`] },
      { name: "iCloud Drive", paths: [`${home}\\iCloudDrive`] },
    );
  } else {
    // Linux
    services.push(
      { name: "Dropbox", paths: [`${home}/Dropbox`] },
      { name: "Google Drive", paths: [`${home}/Google Drive`] },
      { name: "OneDrive", paths: [`${home}/OneDrive`] },
    );
  }

  return services;
}

export async function runCloudSyncCheck(
  openclawDir: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const resolvedOcDir = resolve(openclawDir).toLowerCase();
  const services = getCloudServices();

  for (const service of services) {
    for (const syncPath of service.paths) {
      try {
        await stat(syncPath);
        // Sync directory exists — check if openclaw dir is inside it
        const resolvedSync = resolve(syncPath).toLowerCase();
        if (resolvedOcDir.startsWith(resolvedSync)) {
          findings.push({
            id: "CLOUD-001",
            severity: Severity.High,
            confidence: "high",
            category: "Cloud Sync",
            title: `OpenClaw directory is inside ${service.name}`,
            description: `${openclawDir} is inside ${syncPath} — credentials are being synced to the cloud`,
            risk: "API keys, OAuth tokens, and session logs are uploaded to cloud storage in plaintext",
            remediation: `Move ~/.openclaw/ outside of ${service.name} or exclude it from sync`,
            autoFixable: false,
          });
          break; // One finding per service
        }
      } catch {
        // Sync dir doesn't exist — skip
      }
    }
  }

  return findings;
}
