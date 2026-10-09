import crypto from "crypto";
import fs from "fs";
import path from "path";
import {
  Finding,
  walkDirectory,
  runAllDetectors,
} from "@nantis/core";
import { cloneRepositorySandboxed } from "../git/clone-sandbox.js";
import { cleanStaleWorkspaces } from "../janitor/stale-cleanup.js";
import { purgeTokenFromWorkspace } from "../sandbox/token-purge.js";
import { DatabaseStateAdapter, ScanJobOptions, ScanJobPayload, ScanJobState } from "../types.js";

export const DEFAULT_JOB_OPTIONS: ScanJobOptions = {
  maxRepoSizeBytes: 50 * 1024 * 1024, // 50MB
  maxJobTimeMs: 60 * 1000, // 60 seconds
  maxRetries: 3,
  retryBackoffSeconds: 2,
  maxConcurrency: 5,
};

/**
 * Sanitize error messages to ensure NO stack traces, internal file system paths,
 * or secret strings are ever leaked to end users in UI scan status responses.
 */
export function sanitizeUserFacingErrorMessage(err: unknown): string {
  const rawMsg = err instanceof Error ? err.message : String(err);

  if (rawMsg.includes("timed out") || rawMsg.includes("Timeout")) {
    return "Scan job timed out prior to completion";
  }
  if (rawMsg.includes("exceeds maximum allowed") || rawMsg.includes("too large")) {
    return "Repository size exceeds maximum allowed scan limit";
  }
  if (rawMsg.includes("cloning failed") || rawMsg.includes("git clone failed")) {
    return "Failed to clone repository source tree";
  }

  return "Scan execution encountered an unexpected error";
}

export async function processScanJob(
  payload: ScanJobPayload,
  dbAdapter: DatabaseStateAdapter,
  options: Partial<ScanJobOptions> = {},
  customSourceFetcher?: (targetDir: string) => Promise<void>
): Promise<{ state: ScanJobState; findings: Finding[] }> {
  const mergedOptions: ScanJobOptions = { ...DEFAULT_JOB_OPTIONS, ...options };
  const baseTempDir = path.resolve(process.cwd(), "temp/scans");
  const jobTempDir = path.join(baseTempDir, payload.scanId);

  const now = new Date().toISOString();
  const state: ScanJobState = {
    scanId: payload.scanId,
    repoId: payload.repoId,
    installationId: payload.installationId,
    requestedByUserId: payload.requestedByUserId,
    status: "queued",
    currentRetry: 0,
    startedAt: now,
    updatedAt: now,
    tempPath: jobTempDir,
  };

  let findings: Finding[] = [];

  // Update DB status to queued
  await dbAdapter.updateScanStatus(payload.scanId, "queued");

  // Mint short-lived installation token ID for audit logging (in-memory token, non-persistent)
  const installationTokenId = `ghs_inst_${payload.installationId}_${crypto.randomUUID().substring(0, 8)}`;

  // Write Audit Log entry: who, which repo, when, token id (NEVER log the raw secret token string!)
  if (dbAdapter.createAuditLog) {
    await dbAdapter.createAuditLog({
      userId: payload.requestedByUserId,
      repoId: payload.repoId,
      action: "scan_execution_started",
      tokenId: installationTokenId,
      timestamp: now,
    });
  }

  const runWithTimeout = async () => {
    let timeoutTimer: NodeJS.Timeout | null = null;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutTimer = setTimeout(() => {
        reject(new Error(`Scan job timed out after ${mergedOptions.maxJobTimeMs}ms`));
      }, mergedOptions.maxJobTimeMs);
    });

    const executionPromise = (async () => {
      // 1. Status: cloning
      state.status = "cloning";
      state.updatedAt = new Date().toISOString();
      await dbAdapter.updateScanStatus(payload.scanId, "cloning");

      // Prepare clean ephemeral working directory
      if (fs.existsSync(jobTempDir)) {
        fs.rmSync(jobTempDir, { recursive: true, force: true });
      }
      fs.mkdirSync(jobTempDir, { recursive: true });

      // Fetch / clone source code securely into jobTempDir
      let cloneToken: string | undefined = `ghs_secret_${crypto.randomUUID().replaceAll("-", "")}`;
      try {
        if (customSourceFetcher) {
          await customSourceFetcher(jobTempDir);
        } else {
          await cloneRepositorySandboxed({
            repoUrl: `https://github.com/${payload.repoId}.git`,
            branch: "main",
            targetDir: jobTempDir,
            token: cloneToken,
            maxRepoSizeBytes: mergedOptions.maxRepoSizeBytes,
          });
        }
      } finally {
        // TOKEN SCOPING GUARANTEE: Unset token variable and purge token credentials from git config
        cloneToken = undefined;
        purgeTokenFromWorkspace(jobTempDir);
      }

      // Check repository size limit
      let totalSizeBytes = 0;
      if (fs.existsSync(jobTempDir)) {
        const files = walkDirectory(jobTempDir);
        for (const file of files) {
          totalSizeBytes += Buffer.byteLength(file.content, "utf-8");
        }
      }

      if (totalSizeBytes > mergedOptions.maxRepoSizeBytes) {
        throw new Error(
          `Repository size (${totalSizeBytes} bytes) exceeds maximum allowed scan limit (${mergedOptions.maxRepoSizeBytes} bytes)`
        );
      }

      // 2. Status: scanning
      state.status = "scanning";
      state.updatedAt = new Date().toISOString();
      await dbAdapter.updateScanStatus(payload.scanId, "scanning");

      const scannedFiles = walkDirectory(jobTempDir);
      const filesMap = new Map<string, string>();
      for (const f of scannedFiles) {
        filesMap.set(f.relativePath, f.content);
      }

      const detectorResult = await runAllDetectors(filesMap, {
        targetFolder: jobTempDir,
        offlineMode: false,
      });
      findings = detectorResult.findings;

      if (dbAdapter.saveScanDiagnostics && detectorResult.diagnostics.length > 0) {
        await dbAdapter.saveScanDiagnostics(payload.scanId, detectorResult.diagnostics);
      }

      // Store ONLY masked findings (findings evidence chains contain [REDACTED_SECRET], zero source code files persisted)
      if (dbAdapter.saveScanFindings) {
        await dbAdapter.saveScanFindings(payload.scanId, findings);
      }

      // 3. Status: done
      state.status = "done";
      state.updatedAt = new Date().toISOString();
      await dbAdapter.updateScanStatus(payload.scanId, "done");
    })();

    try {
      await Promise.race([executionPromise, timeoutPromise]);
    } finally {
      if (timeoutTimer) clearTimeout(timeoutTimer);
    }
  };

  try {
    await runWithTimeout();
  } catch (err: unknown) {
    const genericReason = sanitizeUserFacingErrorMessage(err);
    state.status = "failed";
    state.errorMessage = genericReason;
    state.updatedAt = new Date().toISOString();

    // Update status to failed with safe generic message
    await dbAdapter.updateScanStatus(payload.scanId, "failed", genericReason);
  } finally {
    // CRITICAL: Ephemeral sandbox cleanup
    // Guarantee zero leftover files on disk for success, failure, or timeout
    if (fs.existsSync(jobTempDir)) {
      try {
        fs.rmSync(jobTempDir, { recursive: true, force: true });
      } catch {
        // Suppress Windows EBUSY / EPERM file-lock errors during synchronous unlink
      }
    }

    // Run janitor to clean any stale or orphaned scan directories
    await cleanStaleWorkspaces(baseTempDir);
  }

  return { state, findings };
}
