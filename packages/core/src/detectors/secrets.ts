import crypto from "crypto";
import { Finding, Severity } from "../types.js";
import { maskSecrets } from "../masking.js";

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const charMap: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    charMap[char] = (charMap[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in charMap) {
    const p = charMap[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const KNOWN_SECRET_REGEXES: Array<{ name: string; pattern: RegExp; defaultSeverity: Severity }> = [
  {
    name: "Stripe Secret Key",
    pattern: /\b(sk_live_[0-9a-zA-Z_]{16,})\b/g,
    defaultSeverity: "critical",
  },
  { name: "Stripe Test Key", pattern: /\b(sk_test_[0-9a-zA-Z_]{16,})\b/g, defaultSeverity: "high" },
  {
    name: "Stripe Restricted Key",
    pattern: /\b(rk_live_[0-9a-zA-Z_]{16,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "Stripe Restricted Test Key",
    pattern: /\b(rk_test_[0-9a-zA-Z_]{16,})\b/g,
    defaultSeverity: "high",
  },
  {
    name: "Supabase Service Role Key",
    pattern: /\b(sbp_[a-f0-9_]{32,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "Supabase Postgres Connection",
    pattern: /postgres:\/\/[^:]+:[^@]+@[^\s"']+/g,
    defaultSeverity: "critical",
  },
  { name: "AWS Access Key", pattern: /\b(AKIA[0-9A-Z]{16})\b/g, defaultSeverity: "critical" },
  {
    name: "GitHub Personal Token",
    pattern: /\b(ghp_[a-zA-Z0-9_]{30,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "GitHub OAuth Token",
    pattern: /\b(gho_[a-zA-Z0-9_]{30,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "GitHub Fine-Grained Token",
    pattern: /\b(github_pat_[a-zA-Z0-9_]{20,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "Private Key Block",
    pattern: /-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----/g,
    defaultSeverity: "critical",
  },
];

const SECRET_VAR_REGEX =
  /(?:api[_-]?key|secret|token|password|auth|credential)\s*[:=]\s*["']([^"']+)["']/gi;

function isLockfileOrPlaceholder(filePath: string, value: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/").toLowerCase();
  if (
    normalizedPath.endsWith("package-lock.json") ||
    normalizedPath.endsWith("pnpm-lock.yaml") ||
    normalizedPath.endsWith("yarn.lock") ||
    normalizedPath.endsWith("bun.lockb")
  ) {
    return true;
  }

  const valLower = value.toLowerCase();
  if (
    valLower.includes("your_") ||
    valLower.includes("example") ||
    valLower.includes("placeholder") ||
    valLower.includes("xxx") ||
    valLower.includes("0000000000") ||
    valLower.includes("<key>")
  ) {
    return true;
  }

  return false;
}

function generateFindingId(): string {
  return crypto.randomUUID();
}

function generateFingerprint(
  ruleId: string,
  filePath: string,
  line: number,
  tokenType: string
): string {
  const normPath = filePath.replace(/\\/g, "/").toLowerCase();
  return crypto
    .createHash("sha256")
    .update(`${ruleId}:${normPath}:${tokenType}:${line}`)
    .digest("hex");
}

function pathBasename(p: string): string {
  const parts = p.split("/");
  return parts[parts.length - 1] || p;
}

function pathDirname(p: string): string {
  const parts = p.split("/");
  if (parts.length <= 1) return "";
  return parts.slice(0, parts.length - 1).join("/");
}

function resolveRelativeImport(fromFile: string, importSpecifier: string): string {
  const fromDir = pathDirname(fromFile);
  let resolved =
    importSpecifier.startsWith("./") || importSpecifier.startsWith("../")
      ? fromDir
        ? `${fromDir}/${importSpecifier}`
        : importSpecifier
      : importSpecifier;

  // Clean up ./ and ../ segments
  const parts = resolved.split("/");
  const stack: string[] = [];
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (stack.length > 0) stack.pop();
    } else {
      stack.push(part);
    }
  }

  let result = stack.join("/");
  // Strip .js / .ts extension to get base path for flexible matching
  result = result.replace(/\.(?:ts|tsx|js|jsx)$/, "");
  return result;
}

export async function detectSecrets(files: Map<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Pass 1: Identify 'use client' files and files imported by 'use client' components
  const useClientFiles = new Set<string>();
  const importedByUseClient = new Set<string>();

  for (const [relPath, content] of files.entries()) {
    const normalizedPath = relPath.replace(/\\/g, "/");
    if (/^\s*["']use client["']/m.test(content)) {
      useClientFiles.add(normalizedPath);

      // Extract import statements
      const importRegex = /import\s+.*?\s+from\s+["']([^"']+)["']/g;
      let match: RegExpExecArray | null;
      while ((match = importRegex.exec(content)) !== null) {
        const importSpecifier = match[1];
        if (importSpecifier.startsWith(".")) {
          const resolvedPathBase = resolveRelativeImport(normalizedPath, importSpecifier);
          importedByUseClient.add(resolvedPathBase);
        }
      }
    }
  }

  // Pass 2: Detect secrets in all files
  for (const [relPath, content] of files.entries()) {
    const normalizedPath = relPath.replace(/\\/g, "/");
    const normalizedBase = normalizedPath.replace(/\.(?:ts|tsx|js|jsx)$/, "");

    // 1. Check committed env files
    const isEnvFile =
      /^\.env(?:\.[a-z0-9_-]+)*$/i.test(pathBasename(normalizedPath)) &&
      !normalizedPath.endsWith(".example") &&
      !normalizedPath.endsWith(".template");

    if (isEnvFile) {
      const lines = content.split(/\r?\n/);
      let startLine = 1;
      let endLine = Math.max(1, lines.length);

      let hasSecrets = false;
      let firstSecretFound = false;
      lines.forEach((line, index) => {
        if (line.includes("=") && !line.startsWith("#")) {
          const val = line.split("=")[1]?.trim() || "";
          if (val && !isLockfileOrPlaceholder(normalizedPath, val)) {
            hasSecrets = true;
            if (!firstSecretFound) {
              startLine = index + 1;
              firstSecretFound = true;
            }
          }
        }
      });

      if (hasSecrets) {
        findings.push({
          id: generateFindingId(),
          ruleId: "committed-env-file",
          title: "Committed Environment File with Secrets",
          severity: "critical",
          confidenceTier: "proven",
          file: normalizedPath,
          lineRange: { startLine, endLine },
          evidenceChain: [
            {
              kind: "config",
              file: normalizedPath,
              line: startLine,
              maskedSnippet: maskSecrets(lines[startLine - 1] || ""),
              confidence: "high",
              note: "Committed .env file detected in repository",
            },
          ],
          unresolvedSteps: [],
          explanation:
            "Environment configuration file containing credentials was committed to source control.",
          fingerprint: generateFingerprint("committed-env-file", normalizedPath, 1, "env-file"),
        });
      }
    }

    // 2. Check for secret token regexes and high entropy assignments in code files
    const isClientContext =
      useClientFiles.has(normalizedPath) ||
      importedByUseClient.has(normalizedPath) ||
      importedByUseClient.has(normalizedBase);
    const lines = content.split(/\r?\n/);

    lines.forEach((lineText, lineIdx) => {
      const lineNumber = lineIdx + 1;

      // Check known secret regex formats
      for (const { name, pattern, defaultSeverity } of KNOWN_SECRET_REGEXES) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = pattern.exec(lineText)) !== null) {
          const secretValue = match[0];
          if (isLockfileOrPlaceholder(normalizedPath, secretValue)) continue;

          const ruleId = isClientContext ? "use-client-secret-leak" : "hardcoded-secret";
          const title = isClientContext
            ? `Secret Key Exposed in Client Component Context (${name})`
            : `Hardcoded Secret Detected (${name})`;

          findings.push({
            id: generateFindingId(),
            ruleId,
            title,
            severity: isClientContext ? "critical" : defaultSeverity,
            confidenceTier: "proven",
            file: normalizedPath,
            lineRange: { startLine: lineNumber, endLine: lineNumber },
            evidenceChain: [
              {
                kind: "sink",
                file: normalizedPath,
                line: lineNumber,
                maskedSnippet: maskSecrets(lineText),
                confidence: "high",
                note: `${name} detected in file`,
              },
            ],
            unresolvedSteps: [],
            explanation: `Found hardcoded secret ${name} in source file. Secret values must never be stored in source code.`,
            fingerprint: generateFingerprint(ruleId, normalizedPath, lineNumber, name),
          });
        }
      }

      // Check high entropy string assignments
      SECRET_VAR_REGEX.lastIndex = 0;
      let varMatch: RegExpExecArray | null;
      while ((varMatch = SECRET_VAR_REGEX.exec(lineText)) !== null) {
        const assignedVal = varMatch[1];
        if (assignedVal.length >= 16 && !isLockfileOrPlaceholder(normalizedPath, assignedVal)) {
          const entropy = calculateShannonEntropy(assignedVal);
          if (entropy >= 3.5) {
            const ruleId = isClientContext ? "use-client-secret-leak" : "hardcoded-secret";
            findings.push({
              id: generateFindingId(),
              ruleId,
              title: "Hardcoded High-Entropy Secret Variable Assignment",
              severity: "high",
              confidenceTier: "likely",
              file: normalizedPath,
              lineRange: { startLine: lineNumber, endLine: lineNumber },
              evidenceChain: [
                {
                  kind: "sink",
                  file: normalizedPath,
                  line: lineNumber,
                  maskedSnippet: maskSecrets(lineText),
                  confidence: "high",
                  note: "High entropy secret variable assignment",
                },
              ],
              unresolvedSteps: [],
              explanation:
                "Variable assignment contains a high-entropy string literal resembling an API secret or token.",
              fingerprint: generateFingerprint(
                ruleId,
                normalizedPath,
                lineNumber,
                "high-entropy-var"
              ),
            });
          }
        }
      }
    });
  }

  return findings;
}
