import { Finding, ScanDiagnostic } from "@nantis/core";
import { DEFAULT_JOB_OPTIONS, processScanJob } from "../processor/scan-processor.js";
import { PgBossScanJobQueue } from "./pgboss-queue.js";
import {
  AuditLogPayload,
  DatabaseStateAdapter,
  JobStatus,
  ScanJobOptions,
  ScanJobPayload,
  ScanJobState,
} from "../types.js";

export class InMemoryDbAdapter implements DatabaseStateAdapter {
  private scanStatuses = new Map<string, { status: JobStatus; errorMessage?: string }>();
  private scanFindings = new Map<string, Finding[]>();
  private scanDiagnostics = new Map<string, ScanDiagnostic[]>();
  private auditLogs: AuditLogPayload[] = [];

  async updateScanStatus(scanId: string, status: JobStatus, errorMessage?: string): Promise<void> {
    this.scanStatuses.set(scanId, { status, errorMessage });
  }

  async getScanStatus(scanId: string): Promise<{ status: JobStatus; errorMessage?: string }> {
    return (
      this.scanStatuses.get(scanId) || {
        status: "queued",
      }
    );
  }

  async saveScanFindings(scanId: string, findings: Finding[]): Promise<void> {
    this.scanFindings.set(scanId, findings);
  }

  async getScanFindings(scanId: string): Promise<Finding[]> {
    return this.scanFindings.get(scanId) || [];
  }

  async saveScanDiagnostics(scanId: string, diagnostics: ScanDiagnostic[]): Promise<void> {
    this.scanDiagnostics.set(scanId, diagnostics);
  }

  async getScanDiagnostics(scanId: string): Promise<ScanDiagnostic[]> {
    return this.scanDiagnostics.get(scanId) || [];
  }

  async createAuditLog(payload: AuditLogPayload): Promise<void> {
    this.auditLogs.push(payload);
  }

  async getAuditLogs(): Promise<AuditLogPayload[]> {
    return [...this.auditLogs];
  }

  clear() {
    this.scanStatuses.clear();
    this.scanFindings.clear();
    this.scanDiagnostics.clear();
    this.auditLogs = [];
  }
}

export class ScanJobQueue {
  private options: ScanJobOptions;
  private dbAdapter: DatabaseStateAdapter;
  private pgBossQueue?: PgBossScanJobQueue;
  private jobStates = new Map<string, ScanJobState>();
  private activeConcurrency = 0;
  private queue: {
    payload: ScanJobPayload;
    optionsOverride?: Partial<ScanJobOptions>;
    customFetcher?: (dir: string) => Promise<void>;
  }[] = [];

  constructor(
    dbAdapter: DatabaseStateAdapter = new InMemoryDbAdapter(),
    options: Partial<ScanJobOptions> = {},
    dbConfig?: string | object
  ) {
    this.dbAdapter = dbAdapter;
    this.options = { ...DEFAULT_JOB_OPTIONS, ...options };

    const usePostgres = process.env.USE_POSTGRES === "true";
    const connectionString = dbConfig || (usePostgres ? process.env.DATABASE_URL : undefined);
    if (connectionString) {
      this.pgBossQueue = new PgBossScanJobQueue(this.dbAdapter, connectionString, this.options);
    }
  }

  async enqueueJob(
    payload: ScanJobPayload,
    optionsOverride: Partial<ScanJobOptions> = {},
    customFetcher?: (dir: string) => Promise<void>
  ): Promise<ScanJobState> {
    if (this.pgBossQueue) {
      return this.pgBossQueue.enqueueJob(payload, optionsOverride, customFetcher);
    }

    const now = new Date().toISOString();
    const initialState: ScanJobState = {
      scanId: payload.scanId,
      repoId: payload.repoId,
      installationId: payload.installationId,
      requestedByUserId: payload.requestedByUserId,
      status: "queued",
      currentRetry: 0,
      startedAt: now,
      updatedAt: now,
    };

    this.jobStates.set(payload.scanId, initialState);
    await this.dbAdapter.updateScanStatus(payload.scanId, "queued");

    this.queue.push({ payload, optionsOverride, customFetcher });
    setImmediate(() => this.processNextQueueItem());

    return initialState;
  }

  private async processNextQueueItem() {
    if (this.activeConcurrency >= this.options.maxConcurrency || this.queue.length === 0) {
      return;
    }

    const item = this.queue.shift();
    if (!item) return;

    this.activeConcurrency++;

    const mergedOpts: ScanJobOptions = { ...this.options, ...item.optionsOverride };
    let attempt = 0;

    const executeAttempt = async (): Promise<void> => {
      attempt++;
      const result = await processScanJob(
        item.payload,
        this.dbAdapter,
        mergedOpts,
        item.customFetcher
      );

      result.state.currentRetry = attempt;
      this.jobStates.set(item.payload.scanId, result.state);

      if (
        result.state.status === "failed" &&
        attempt <= mergedOpts.maxRetries &&
        result.state.errorMessage !== "Repository size exceeds maximum allowed scan limit"
      ) {
        // Retry with backoff
        const backoffMs = mergedOpts.retryBackoffSeconds * 1000 * Math.pow(2, attempt - 1);

        await new Promise((resolve) => setTimeout(resolve, backoffMs));
        return executeAttempt();
      }
    };

    try {
      await executeAttempt();
    } finally {
      this.activeConcurrency--;
      setImmediate(() => this.processNextQueueItem());
    }
  }

  async getJobStatus(scanId: string): Promise<{ status: JobStatus; errorMessage?: string } | null> {
    if (this.pgBossQueue) {
      return this.pgBossQueue.getJobStatus(scanId);
    }
    return this.dbAdapter.getScanStatus(scanId);
  }

  getJobState(scanId: string): ScanJobState | undefined {
    if (this.pgBossQueue) {
      return this.pgBossQueue.getJobState(scanId);
    }
    return this.jobStates.get(scanId);
  }

  async waitForJobCompletion(scanId: string, timeoutMs = 5000): Promise<ScanJobState> {
    if (this.pgBossQueue) {
      return this.pgBossQueue.waitForJobCompletion(scanId, timeoutMs);
    }

    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const state = this.getJobState(scanId);
      const dbStatus = await this.getJobStatus(scanId);
      if (
        state &&
        (state.status === "done" ||
          (state.status === "failed" && state.currentRetry > this.options.maxRetries))
      ) {
        if (dbStatus && (dbStatus.status === "done" || dbStatus.status === "failed")) {
          return state;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`waitForJobCompletion timed out for scan ${scanId}`);
  }

  getActiveConcurrencyCount(): number {
    if (this.pgBossQueue) {
      return this.pgBossQueue.getActiveConcurrencyCount();
    }
    return this.activeConcurrency;
  }

  getPendingQueueLength(): number {
    if (this.pgBossQueue) {
      return this.pgBossQueue.getPendingQueueLength();
    }
    return this.queue.length;
  }

  async stop(): Promise<void> {
    if (this.pgBossQueue) {
      await this.pgBossQueue.stop();
    }
  }
}
