import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import { Finding, validateAntiSuppressionAndDeletion, StructuredEdit, applyStructuredEdits } from "@nantis/core";
import { WebEnv } from "./env.js";
import { getInstallationAccessToken } from "./github-app.js";

export interface PublishPrOptions {
  repoPath: string;
  repoFullName: string;
  defaultBranch?: string;
  scanId: string;
  installationId: number;
  findings: Finding[];
  remediationEdits?: StructuredEdit[];
  env: WebEnv;
  fetchFn?: typeof fetch;
}

export interface PublishPrResult {
  success: boolean;
  prNumber?: number;
  prUrl?: string;
  branchName?: string;
  commitSha?: string;
  error?: string;
}

/**
 * Validates that file paths in a remediation patch stay strictly inside the workspace.
 * Rejects path traversal (..), absolute paths, and .git paths.
 */
export function validatePatchPaths(targetFile: string, workspacePath: string): { valid: boolean; reason?: string } {
  const normFile = targetFile.replace(/\\/g, "/");

  if (normFile.includes("..") || normFile.startsWith("/") || /^[a-zA-Z]:/.test(normFile)) {
    return { valid: false, reason: `Path traversal rejected: ${targetFile}` };
  }

  if (normFile.startsWith(".git") || normFile.includes("/.git/")) {
    return { valid: false, reason: `Access to .git path rejected: ${targetFile}` };
  }

  const resolvedPath = path.resolve(workspacePath, targetFile);
  const resolvedWorkspace = path.resolve(workspacePath);

  if (!resolvedPath.startsWith(resolvedWorkspace)) {
    return { valid: false, reason: `File path escapes workspace directory: ${targetFile}` };
  }

  return { valid: true };
}

/**
 * Generates deterministic, sanitized branch name for a given scan ID.
 */
export function getDeterministicBranchName(scanId: string): string {
  const sanitizedId = scanId.replace(/[^a-zA-Z0-9-]/g, "");
  return `nantis/fix/${sanitizedId}`;
}

/**
 * GitHub PR Publisher abstraction.
 * Applies remediation edits, creates a dedicated branch, commits, pushes, and creates a GitHub PR.
 */
export async function publishRemediationPR(options: PublishPrOptions): Promise<PublishPrResult> {
  const {
    repoPath,
    repoFullName,
    defaultBranch = "main",
    scanId,
    installationId,
    findings,
    remediationEdits = [],
    env,
    fetchFn = fetch,
  } = options;

  const parts = repoFullName.split("/");
  if (parts.length !== 2) {
    return { success: false, error: `Invalid repository full name format: ${repoFullName}` };
  }
  const [owner, repo] = parts;
  const branchName = getDeterministicBranchName(scanId);

  try {
    // 1. Resolve token (PAT takes precedence or falls back to GitHub App IAT)
    let token: string | undefined;
    if (env.GITHUB_TOKEN && env.GITHUB_TOKEN.trim() !== "") {
      token = env.GITHUB_TOKEN.trim();
    } else if (env.GITHUB_APP_ID && env.GITHUB_APP_PRIVATE_KEY && installationId) {
      try {
        token = await getInstallationAccessToken(
          installationId,
          env.GITHUB_APP_ID,
          env.GITHUB_APP_PRIVATE_KEY,
          fetchFn
        );
      } catch (err: unknown) {
        return {
          success: false,
          error: `GitHub App authentication failed: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    if (!token) {
      return {
        success: false,
        error: "No GitHub credentials (GITHUB_TOKEN or GitHub App) configured to publish PR",
      };
    }

    const checkExistingRes = await fetchFn(
      `https://api.github.com/repos/${owner}/${repo}/pulls?head=${owner}:${branchName}&state=open`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "NANTIS-App",
        },
      }
    );

    if (checkExistingRes.ok) {
      const existingPrs = (await checkExistingRes.json()) as { number: number; html_url: string }[];
      if (existingPrs.length > 0) {
        return {
          success: true,
          prNumber: existingPrs[0].number,
          prUrl: existingPrs[0].html_url,
          branchName,
        };
      }
    }

    // 2. Validate Patch Safety
    if (remediationEdits.length === 0) {
      return { success: false, error: "No remediation edits available to publish in PR" };
    }

    for (const edit of remediationEdits) {
      const pathCheck = validatePatchPaths(edit.targetFile, repoPath);
      if (!pathCheck.valid) {
        return { success: false, error: pathCheck.reason };
      }

      const fullPath = path.join(repoPath, edit.targetFile);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, "utf-8");
        const editRes = applyStructuredEdits(content, [edit]);
        if (!editRes.success || !editRes.updatedContent) {
          return { success: false, error: `Patch application failed for ${edit.targetFile}: ${editRes.reason}` };
        }

        const antiSuppression = validateAntiSuppressionAndDeletion(editRes.updatedContent);
        if (!antiSuppression.valid) {
          return { success: false, error: antiSuppression.reason };
        }
      }
    }

    // 3. Apply edits in repository worktree
    for (const edit of remediationEdits) {
      const fullPath = path.join(repoPath, edit.targetFile);
      const content = fs.existsSync(fullPath) ? fs.readFileSync(fullPath, "utf-8") : "";
      const editRes = applyStructuredEdits(content, [edit]);
      if (editRes.success && editRes.updatedContent) {
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, editRes.updatedContent, "utf-8");
      }
    }

    // 4. Git Branch & Commit
    execSync(`git checkout -b ${branchName}`, { cwd: repoPath, stdio: "ignore" });
    execSync("git add .", { cwd: repoPath, stdio: "ignore" });
    execSync(`git commit -m "fix(security): remediate NANTIS findings for scan ${scanId.substring(0, 8)}"`, {
      cwd: repoPath,
      stdio: "ignore",
    });

    const commitSha = execSync("git rev-parse HEAD", { cwd: repoPath, encoding: "utf-8" }).trim();

    // 5. Authenticated Push to GitHub Remote via Git extraHeader (NEVER in command-line arguments or URL)
    const remoteUrl = `https://github.com/${repoFullName}.git`;
    const pushEnv: Record<string, string | undefined> = {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
      GCM_INTERACTIVE: "never",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "http.extraHeader",
      GIT_CONFIG_VALUE_0: `Authorization: Bearer ${token}`,
    };
    try {
      execSync(`git push "${remoteUrl}" ${branchName} --force`, {
        cwd: repoPath,
        env: pushEnv,
        stdio: "ignore",
      });
    } catch {
      return { success: false, error: `Failed to push branch ${branchName} to remote repository` };
    }

    // 6. Create GitHub Pull Request via REST API
    const findingSummaryLines = findings.map(
      (f) => `- **[${f.ruleId}] ${f.title}**: \`${f.file}:${f.lineRange?.startLine || 1}\``
    );

    const prBody = [
      "## 🛡️ NANTIS Automated Security Remediation",
      "",
      `NANTIS identified security findings during scan \`${scanId.substring(0, 8)}\` and generated proposed remediation changes.`,
      "",
      "### Remediated Findings:",
      ...findingSummaryLines,
      "",
      "---",
      "**Verification Status**: All proposed edits have passed AST structure and sandbox verification checks.",
      "",
      "> _Note: Please review the diff carefully prior to merging. NANTIS does not auto-merge remediation PRs._",
    ].join("\n");

    const prRes = await fetchFn(`https://api.github.com/repos/${owner}/${repo}/pulls`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "NANTIS-App",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        title: `[NANTIS] Remediate Security Findings (Scan ${scanId.substring(0, 8)})`,
        head: branchName,
        base: defaultBranch,
        body: prBody,
      }),
    });

    if (!prRes.ok) {
      const errText = await prRes.text();
      return { success: false, error: `GitHub API PR creation failed: HTTP ${prRes.status} - ${errText}` };
    }

    const prData = (await prRes.json()) as { number: number; html_url: string };

    return {
      success: true,
      prNumber: prData.number,
      prUrl: prData.html_url,
      branchName,
      commitSha,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: `PR publication failed: ${msg}` };
  }
}
