/**
 * Network Exposure checks (16-25).
 *
 * Checks gateway binding, auth configuration, proxy settings,
 * insecure auth flags, and SSL/TLS configuration.
 */

import { Severity, type Finding, type OpenClawConfig } from "../types.js";

const WEAK_TOKENS = [
  "password", "secret", "token", "12345678", "test", "admin",
  "changeme", "default", "openclaw", "letmein", "hunter2",
  "abc123", "123456", "qwerty", "password1",
];

/** Returns true if the value is a ${VAR} env reference (resolved at runtime) */
const isEnvRef = (v: string): boolean => /^\$\{.+\}$/.test(v);

export async function runNetworkChecks(
  config: OpenClawConfig
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check 16: Gateway bind is 127.0.0.1 (not 0.0.0.0)
  const bind = config.gateway?.bind;
  if (bind === "0.0.0.0" || bind === "::") {
    findings.push({
      id: "NETWORK-001",
      severity: Severity.Critical,
      confidence: "high",
      category: "Network Exposure",
      title: "Gateway exposed on all interfaces",
      description: `Gateway is bound to ${bind}, making it accessible from any network interface`,
      risk: "Anyone on your network (or the internet if port-forwarded) can control your agent",
      remediation: 'Set gateway.bind to "127.0.0.1" in openclaw.json',
      autoFixable: true,
      fixType: "safe",
    });
  }

  // Check 17: Gateway auth enabled
  const authMode = config.gateway?.auth?.mode;
  if (authMode === "off" || authMode === "disabled" || authMode === "none") {
    findings.push({
      id: "NETWORK-002",
      severity: Severity.Critical,
      confidence: "high",
      category: "Network Exposure",
      title: "Gateway authentication disabled",
      description: "Gateway has no authentication enabled",
      risk: "Anyone who can reach the gateway port can control your agent",
      remediation: 'Set gateway.auth.mode to "token" and generate a secure token',
      autoFixable: true,
      fixType: "safe",
    });
  }

  // Check 18: Auth token length >= 32 characters
  const token = config.gateway?.auth?.token;
  if (authMode === "token" && token && !isEnvRef(token) && token.length < 32) {
    findings.push({
      id: "NETWORK-003",
      severity: Severity.High,
      confidence: "high",
      category: "Network Exposure",
      title: "Weak gateway auth token",
      description: `Auth token is ${token.length} characters (minimum 32 recommended)`,
      risk: "Short tokens are easier to brute-force",
      remediation: "Generate a longer random token (64+ chars recommended)",
      autoFixable: true,
      fixType: "safe",
    });
  }

  // Check 19: Auth token not a common value
  if (token && !isEnvRef(token) && WEAK_TOKENS.includes(token.toLowerCase())) {
    findings.push({
      id: "NETWORK-004",
      severity: Severity.Critical,
      confidence: "high",
      category: "Network Exposure",
      title: "Common auth token detected",
      description: "Auth token matches a commonly-used default value",
      risk: "Easily guessable tokens provide no real security",
      remediation: "Generate a cryptographically random token: openssl rand -hex 32",
      autoFixable: true,
      fixType: "safe",
    });
  }

  // Check 20: trustedProxies configured if relevant
  // We can only flag absence — can't know if they're behind a proxy
  const SAFE_BIND_VALUES = ["127.0.0.1", "localhost", "loopback"];
  const bindValue = config.gateway?.bind;
  if (bindValue && SAFE_BIND_VALUES.includes(bindValue) && !config.gateway?.trustedProxies) {
    // This is fine — localhost/loopback binding doesn't need proxy config
  } else if (
    bindValue &&
    !SAFE_BIND_VALUES.includes(bindValue) &&
    !config.gateway?.trustedProxies
  ) {
    findings.push({
      id: "NETWORK-005",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Network Exposure",
      title: "No trusted proxies configured",
      description:
        "Gateway is exposed beyond localhost but trustedProxies is not configured",
      risk: "If behind a reverse proxy, IP-based restrictions won't work correctly",
      remediation: "Set gateway.trustedProxies if behind a reverse proxy (e.g., nginx, Caddy)",
      autoFixable: false,
    });
  }

  // Check 21: allowInsecureAuth is false
  if (config.gateway?.allowInsecureAuth === true) {
    findings.push({
      id: "NETWORK-006",
      severity: Severity.High,
      confidence: "high",
      category: "Network Exposure",
      title: "Insecure auth allowed",
      description: "gateway.allowInsecureAuth is true — auth tokens sent in cleartext",
      risk: "Auth tokens can be intercepted on the network (man-in-the-middle)",
      remediation: "Set gateway.allowInsecureAuth to false and use HTTPS",
      autoFixable: true,
      fixType: "safe",
    });
  }

  // Check 22: dangerouslyDisableDeviceAuth is false
  if (config.gateway?.dangerouslyDisableDeviceAuth === true) {
    findings.push({
      id: "NETWORK-007",
      severity: Severity.Critical,
      confidence: "high",
      category: "Network Exposure",
      title: "Device authentication disabled",
      description: "gateway.dangerouslyDisableDeviceAuth is true",
      risk: "Any device can connect without verification — bypasses all device-level security",
      remediation: "Set gateway.dangerouslyDisableDeviceAuth to false",
      autoFixable: true,
      fixType: "safe",
    });
  }

  // Check 23: Browser relay port heuristic
  // Heuristic: if gateway port is common and bind is exposed
  const port = config.gateway?.port;
  if (bind === "0.0.0.0" && port) {
    findings.push({
      id: "NETWORK-008",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Network Exposure",
      title: "Gateway port exposed on all interfaces",
      description: `Port ${port} is accessible from any network interface`,
      risk: "Port may be reachable from outside your local machine",
      remediation: "Bind to 127.0.0.1 or configure firewall rules to restrict access",
      autoFixable: false,
    });
  }

  // Check 24: Tailscale Funnel detection (heuristic)
  // We look for funnel-related config or env vars
  // This is best-effort — checking is limited without system access
  // Skip for now — implemented as part of broader network scan if needed

  // Check 25: SSL/TLS for external surfaces
  const SAFE_BIND_TLS = ["127.0.0.1", "localhost", "loopback"];
  if (
    config.gateway?.bind &&
    !SAFE_BIND_TLS.includes(config.gateway.bind)
  ) {
    // Check if there's any TLS/SSL config
    const configStr = JSON.stringify(config);
    if (
      !configStr.includes("ssl") &&
      !configStr.includes("tls") &&
      !configStr.includes("cert") &&
      !configStr.includes("https")
    ) {
      findings.push({
        id: "NETWORK-010",
        severity: Severity.High,
        confidence: "medium",
        category: "Network Exposure",
        title: "No SSL/TLS configured for exposed gateway",
        description: "Gateway is exposed beyond localhost with no TLS configuration detected",
        risk: "All traffic including auth tokens transmitted in cleartext",
        remediation: "Configure SSL/TLS certificates or use a reverse proxy with HTTPS termination",
        autoFixable: false,
      });
    }
  }

  return findings;
}
