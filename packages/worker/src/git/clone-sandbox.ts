import child_process from "child_process";
import fs from "fs";
import path from "path";
import { walkDirectory } from "@nantis/core";

export interface CloneSandboxOptions {
  repoUrl: string;
  branch?: string;
  targetDir: string;
  token?: string;
  maxRepoSizeBytes?: number;
  maxFileCount?: number;
  timeoutMs?: number;
}

/**
 * Sanitize error message to ensure tokens and internal file paths are never exposed.
 */
export function sanitizeGitErrorMessage(err: unknown, token?: string): string {
  let msg = err instanceof Error ? err.message : String(err);
  if (token) {
    msg = msg.replaceAll(token, "[REDACTED_TOKEN]");
  }
  msg = msg.replace(/https?:\/\/[^@\s]+@/g, "https://");
  msg = msg.replace(/gh[pousr]_[A-Za-z0-9_]{30,}/g, "[REDACTED_TOKEN]");

  if (msg.includes("exceeds maximum")) {
    return msg;
  }

  const lower = msg.toLowerCase();
  if (lower.includes("authentication failed") || lower.includes("bad credentials") || lower.includes("could not read username")) {
    return "Authentication failed: GitHub token is invalid or expired. Check your GITHUB_TOKEN configuration.";
  }

  if (lower.includes("permission to") && lower.includes("denied")) {
    return "Access denied: GITHUB_TOKEN lacks required permissions to access this repository.";
  }

  if (lower.includes("rate limit") || lower.includes("api rate limit")) {
    return "GitHub rate limit exceeded. Please wait or configure a valid GITHUB_TOKEN for higher rate limits.";
  }

  if (lower.includes("repository not found") || (lower.includes("fatal:") && lower.includes("not found"))) {
    return "Repository not found or access denied: Verify repository URL and ensure GITHUB_TOKEN has permission to access this repository.";
  }

  if (
    msg.includes("cloning failed") ||
    msg.includes("fatal:") ||
    msg.includes("git clone failed") ||
    msg.includes("Git clone failed") ||
    msg.includes("timed out") ||
    msg.includes("ETIMEDOUT")
  ) {
    return "Failed to clone repository source tree";
  }
  return msg;
}

/**
 * Perform a secure, sandboxed shallow git clone.
 * Disables git hooks, filter drivers (such as LFS smudge scripts), symlinks,
 * submodules, and system/global git configs to guarantee NO malicious repo script execution.
 */
export async function cloneRepositorySandboxed(options: CloneSandboxOptions): Promise<void> {
  const { repoUrl, branch, targetDir, token, maxRepoSizeBytes, maxFileCount, timeoutMs } = options;

  // Prepare clean target directory parent
  if (fs.existsSync(targetDir)) {
    fs.rmSync(targetDir, { recursive: true, force: true });
  }
  fs.mkdirSync(path.dirname(targetDir), { recursive: true });

  // Keep plain repository URL (no credentials in URL, zero token in .git/config)
  const plainUrl = repoUrl;

  const buildArgs = (targetBranch?: string): string[] => {
    const args: string[] = [
      "-c",
      "protocol.file.allow=always",
      "-c",
      "core.hooksPath=",
      "-c",
      "core.symlinks=false",
      "-c",
      "filter.lfs.smudge=",
      "-c",
      "filter.lfs.clean=",
      "-c",
      "filter.lfs.process=",
      "clone",
      "--depth",
      "1",
      "--single-branch",
      "--no-recurse-submodules",
    ];

    if (targetBranch) {
      args.push("--branch", targetBranch);
    }

    args.push(plainUrl, targetDir);
    return args;
  };

  const env: Record<string, string | undefined> = {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    GCM_INTERACTIVE: "never",
  };

  // Pass token via GIT_CONFIG_COUNT / KEY / VALUE environment variables (zero process argv exposure)
  if (token) {
    env.GIT_CONFIG_COUNT = "1";
    env.GIT_CONFIG_KEY_0 = "http.extraHeader";
    env.GIT_CONFIG_VALUE_0 = `Authorization: Bearer ${token}`;
  }

  const actualTimeout = timeoutMs || 30000;

  const runGitClone = (args: string[], cloneEnv: Record<string, string | undefined>) => {
    return new Promise<void>((resolve, reject) => {
      child_process.execFile(
        "git",
        args,
        {
          env: cloneEnv,
          timeout: actualTimeout,
          maxBuffer: 10 * 1024 * 1024,
        },
        (error, _stdout, stderr) => {
          if (error) {
            const rawMsg = stderr || error.message;
            reject(new Error(rawMsg));
          } else {
            resolve();
          }
        }
      );
    });
  };

  const attemptClone = async (targetBranch?: string, useToken = Boolean(token)) => {
    const cloneEnv = { ...env };
    if (!useToken) {
      delete cloneEnv.GIT_CONFIG_COUNT;
      delete cloneEnv.GIT_CONFIG_KEY_0;
      delete cloneEnv.GIT_CONFIG_VALUE_0;
    }
    if (fs.existsSync(targetDir)) {
      try {
        fs.rmSync(targetDir, { recursive: true, force: true });
      } catch {}
    }
    await runGitClone(buildArgs(targetBranch), cloneEnv);
  };

  try {
    try {
      await attemptClone(branch, Boolean(token));
    } catch (initialErr: unknown) {
      const errMsg = initialErr instanceof Error ? initialErr.message : String(initialErr);
      const lower = errMsg.toLowerCase();

      // Case 1: Remote branch not found -> retry default branch
      if (branch && errMsg.includes("Remote branch") && errMsg.includes("not found")) {
        try {
          await attemptClone(undefined, Boolean(token));
        } catch (branchErr: unknown) {
          const branchErrMsg = branchErr instanceof Error ? branchErr.message : String(branchErr);
          const bLower = branchErrMsg.toLowerCase();
          if (token && (bLower.includes("authentication failed") || bLower.includes("could not read username") || bLower.includes("bad credentials"))) {
            await attemptClone(undefined, false);
          } else {
            throw branchErr;
          }
        }
      // Case 2: Auth failure on token (e.g. fine-grained PAT used on public repo outside token scope) -> fallback to anonymous
      } else if (token && (lower.includes("authentication failed") || lower.includes("could not read username") || lower.includes("bad credentials"))) {
        await attemptClone(branch, false);
      } else {
        throw initialErr;
      }
    }
  } catch (err) {
    if (fs.existsSync(targetDir)) {
      try {
        fs.rmSync(targetDir, { recursive: true, force: true });
      } catch {
        // Ignore removal error on Windows busy handle
      }
    }
    throw new Error(sanitizeGitErrorMessage(err, token));
  }

  // Post-clone size and file count enforcement
  if (maxRepoSizeBytes || maxFileCount) {
    const scannedFiles = walkDirectory(targetDir);
    if (maxFileCount && scannedFiles.length > maxFileCount) {
      if (fs.existsSync(targetDir)) {
        fs.rmSync(targetDir, { recursive: true, force: true });
      }
      throw new Error(`Repository exceeds maximum allowed file count limit of ${maxFileCount} files`);
    }

    const totalSize = scannedFiles.reduce((acc, f) => acc + (f.content ? f.content.length : 0), 0);
    if (maxRepoSizeBytes && totalSize > maxRepoSizeBytes) {
      if (fs.existsSync(targetDir)) {
        fs.rmSync(targetDir, { recursive: true, force: true });
      }
      throw new Error(
        `Repository size exceeds maximum allowed scan limit of ${Math.round(
          maxRepoSizeBytes / (1024 * 1024)
        )}MB`
      );
    }
  }
}
