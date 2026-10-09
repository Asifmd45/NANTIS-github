import { Finding, ScanDiagnostic } from "@nantis/core";
import { JobStatus } from "@nantis/worker";
import { updateGitHubCheckRun } from "../lib/github-checks.js";
import { WebEnv } from "../lib/env.js";
import {
  AuditLogRow,
  FalsePositiveReportRow,
  FindingLabelRow,
  FindingRow,
  GithubInstallationRow,
  RepositoryRow,
  ScanRow,
  UserInstallationRow,
  UserRepoSnapshotRow,
  UserRow,
  WebhookDeliveryRow,
} from "./schema.js";

export class DatabaseClient {
  private users = new Map<string, UserRow>();
  private installations = new Map<number, GithubInstallationRow>();
  private repositories = new Map<string, RepositoryRow>();
  private scans = new Map<string, ScanRow>();
  private findings = new Map<string, FindingRow>();
  private falsePositiveReports = new Map<string, FalsePositiveReportRow>();
  private findingLabels = new Map<string, FindingLabelRow>();
  private scanDiagnosticsMap = new Map<string, ScanDiagnostic[]>();
  private webhookDeliveries = new Map<string, WebhookDeliveryRow>();
  private auditLogs: AuditLogRow[] = [];

  // User Repository Permissions (represents GitHub confirmed access)
  private userRepoAccess = new Set<string>(); // key: `${userId}:${repoId}`

  // Users Operations
  async upsertUser(data: {
    github_user_id: number;
    github_login: string;
    avatar_url: string;
  }): Promise<UserRow> {
    const existing = Array.from(this.users.values()).find(
      (u) => u.github_user_id === data.github_user_id
    );

    const now = new Date().toISOString();
    if (existing) {
      existing.github_login = data.github_login;
      existing.avatar_url = data.avatar_url;
      existing.updated_at = now;
      return existing;
    }

    const newUser: UserRow = {
      id: crypto.randomUUID(),
      github_user_id: data.github_user_id,
      github_login: data.github_login,
      avatar_url: data.avatar_url,
      created_at: now,
      updated_at: now,
    };
    this.users.set(newUser.id, newUser);
    return newUser;
  }

  async getUserById(id: string): Promise<UserRow | null> {
    return this.users.get(id) || null;
  }

  async getUserByGithubId(githubUserId: number): Promise<UserRow | null> {
    return Array.from(this.users.values()).find((u) => u.github_user_id === githubUserId) || null;
  }

  // GitHub Installations Operations
  async upsertInstallation(data: {
    installation_id: number;
    target_type: "User" | "Organization";
    target_id: number;
    account_name: string;
  }): Promise<GithubInstallationRow> {
    const existing = this.installations.get(data.installation_id);
    const now = new Date().toISOString();

    if (existing) {
      existing.account_name = data.account_name;
      existing.updated_at = now;
      return existing;
    }

    const newInstallation: GithubInstallationRow = {
      id: crypto.randomUUID(),
      installation_id: data.installation_id,
      target_type: data.target_type,
      target_id: data.target_id,
      account_name: data.account_name,
      created_at: now,
      updated_at: now,
    };
    this.installations.set(data.installation_id, newInstallation);
    return newInstallation;
  }

  async deleteInstallation(installationId: number): Promise<boolean> {
    return this.installations.delete(installationId);
  }

  async getInstallationByGithubId(installationId: number): Promise<GithubInstallationRow | null> {
    return this.installations.get(installationId) || null;
  }

  async getInstallation(ref: string | number): Promise<GithubInstallationRow | null> {
    if (typeof ref === "number") {
      return this.installations.get(ref) || null;
    }
    const parsedNum = Number(ref);
    if (!Number.isNaN(parsedNum) && this.installations.has(parsedNum)) {
      return this.installations.get(parsedNum)!;
    }
    return Array.from(this.installations.values()).find((i) => i.id === ref) || null;
  }

  // Repositories Operations
  async upsertRepository(data: {
    id?: string;
    installation_id: string;
    github_repo_id: number;
    name: string;
    full_name: string;
    private: boolean;
    default_branch: string;
  }): Promise<RepositoryRow> {
    const existing = Array.from(this.repositories.values()).find(
      (r) => r.github_repo_id === data.github_repo_id
    );
    const now = new Date().toISOString();

    if (existing) {
      existing.name = data.name;
      existing.full_name = data.full_name;
      existing.private = data.private;
      existing.default_branch = data.default_branch;
      existing.updated_at = now;
      return existing;
    }

    const newRepo: RepositoryRow = {
      id: data.id || crypto.randomUUID(),
      installation_id: data.installation_id,
      github_repo_id: data.github_repo_id,
      name: data.name,
      full_name: data.full_name,
      private: data.private,
      default_branch: data.default_branch,
      created_at: now,
      updated_at: now,
    };
    this.repositories.set(newRepo.id, newRepo);
    return newRepo;
  }

  async getRepositoryById(id: string): Promise<RepositoryRow | null> {
    return this.repositories.get(id) || null;
  }

  async getRepositoryByGithubId(githubRepoId: number): Promise<RepositoryRow | null> {
    return Array.from(this.repositories.values()).find((r) => r.github_repo_id === githubRepoId) || null;
  }

  async getRepositoryByFullName(fullName: string): Promise<RepositoryRow | null> {
    return Array.from(this.repositories.values()).find((r) => r.full_name === fullName) || null;
  }

  // Scans Operations
  async createScan(data: {
    id?: string;
    repository_id: string;
    status: ScanRow["status"];
    trigger_type: "manual" | "webhook_push" | "webhook_pr";
    commit_sha: string;
    branch: string;
    github_check_run_id?: number | null;
    triggered_by_user_id?: string | null;
  }): Promise<ScanRow> {
    const newScan: ScanRow = {
      id: data.id || crypto.randomUUID(),
      repository_id: data.repository_id,
      status: data.status,
      trigger_type: data.trigger_type,
      commit_sha: data.commit_sha,
      branch: data.branch,
      github_check_run_id: data.github_check_run_id || null,
      triggered_by_user_id: data.triggered_by_user_id,
      started_at: new Date().toISOString(),
    };
    this.scans.set(newScan.id, newScan);
    return newScan;
  }

  async updateScanCheckRunId(scanId: string, checkRunId: number): Promise<void> {
    const scan = this.scans.get(scanId);
    if (scan) {
      scan.github_check_run_id = checkRunId;
    }
  }

  async updateScanPublication(
    scanId: string,
    data: {
      github_pr_number?: number | null;
      github_pr_url?: string | null;
      github_branch?: string | null;
      publication_status?: "not_created" | "pending" | "published" | "failed" | null;
      publication_error?: string | null;
    }
  ): Promise<void> {
    const scan = this.scans.get(scanId);
    if (scan) {
      if (data.github_pr_number !== undefined) scan.github_pr_number = data.github_pr_number;
      if (data.github_pr_url !== undefined) scan.github_pr_url = data.github_pr_url;
      if (data.github_branch !== undefined) scan.github_branch = data.github_branch;
      if (data.publication_status !== undefined) scan.publication_status = data.publication_status;
      if (data.publication_error !== undefined) scan.publication_error = data.publication_error;
    }
  }

  async getScanById(id: string): Promise<ScanRow | null> {
    return this.scans.get(id) || null;
  }

  async getScansForRepository(repositoryId: string): Promise<ScanRow[]> {
    return Array.from(this.scans.values()).filter((s) => s.repository_id === repositoryId);
  }

  async getAllScans(): Promise<ScanRow[]> {
    return Array.from(this.scans.values());
  }

  async getAllFindings(): Promise<FindingRow[]> {
    return Array.from(this.findings.values());
  }

  async getAllRepositories(): Promise<RepositoryRow[]> {
    return Array.from(this.repositories.values());
  }

  async getPreviousCompletedScan(repositoryId: string, currentScanId?: string): Promise<ScanRow | null> {
    const repoScans = Array.from(this.scans.values())
      .filter((s) => s.repository_id === repositoryId && s.id !== currentScanId && (s.status === "done" || s.status === "completed"))
      .sort((a, b) => new Date(b.started_at || 0).getTime() - new Date(a.started_at || 0).getTime());
    return repoScans[0] || null;
  }

  async updateScanStatus(
    scanId: string,
    status: ScanRow["status"],
    errorMessage?: string
  ): Promise<void> {
    const scan = this.scans.get(scanId);
    if (scan) {
      scan.status = status;
      if (status === "done" || status === "completed" || status === "failed") {
        scan.completed_at = new Date().toISOString();
      }
      if (errorMessage !== undefined) {
        scan.error_message = errorMessage;
      }

      if (scan.github_check_run_id) {
        const repo = await this.getRepositoryById(scan.repository_id);
        if (repo && repo.full_name) {
          const parts = repo.full_name.split("/");
          if (parts.length === 2) {
            const [owner, repoName] = parts;
            const findings =
              status === "done" || status === "completed" || status === "failed"
                ? await this.getFindingsForScan(scanId)
                : [];
            const diagnostics =
              status === "done" || status === "completed" || status === "failed"
                ? await this.getScanDiagnostics(scanId)
                : [];

            const env: WebEnv = {
              GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID || "test",
              GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET || "test",
              GITHUB_APP_ID: process.env.GITHUB_APP_ID || "test",
              GITHUB_APP_PRIVATE_KEY: process.env.GITHUB_APP_PRIVATE_KEY || "test",
              GITHUB_WEBHOOK_SECRET: process.env.GITHUB_WEBHOOK_SECRET || "test",
              SESSION_SECRET: process.env.SESSION_SECRET || "test",
              DATABASE_URL: process.env.DATABASE_URL || "postgresql://localhost:5432/nantis",
              NODE_ENV: "test",
            };

            updateGitHubCheckRun({
              owner,
              repo: repoName,
              checkRunId: scan.github_check_run_id,
              installationId: Number(repo.installation_id) || 1,
              status,
              scanId,
              findings,
              diagnostics,
              errorMessage,
              env,
            }).catch(() => {});
          }
        }
      }
    }
  }

  async getScanStatus(scanId: string): Promise<{ status: JobStatus; errorMessage?: string }> {
    const scan = this.scans.get(scanId);
    if (!scan) return { status: "queued" };
    return {
      status: scan.status as JobStatus,
      errorMessage: scan.error_message || undefined,
    };
  }

  async saveScanFindings(scanId: string, findings: Finding[]): Promise<void> {
    for (const f of findings) {
      await this.createFinding({
        ...f,
        scan_id: scanId,
      });
    }
  }

  async saveScanDiagnostics(scanId: string, diagnostics: ScanDiagnostic[]): Promise<void> {
    const existing = this.scanDiagnosticsMap.get(scanId) || [];
    this.scanDiagnosticsMap.set(scanId, [...existing, ...diagnostics]);
  }

  async getScanDiagnostics(scanId: string): Promise<ScanDiagnostic[]> {
    return this.scanDiagnosticsMap.get(scanId) || [];
  }

  // Findings Operations
  async createFinding(data: Omit<FindingRow, "db_id"> & { db_id?: string }): Promise<FindingRow> {
    const newFinding: FindingRow = {
      ...data,
      db_id: data.db_id || crypto.randomUUID(),
    };
    this.findings.set(newFinding.db_id, newFinding);
    return newFinding;
  }

  async getFindingById(id: string): Promise<FindingRow | null> {
    return (
      this.findings.get(id) ||
      Array.from(this.findings.values()).find((f) => f.db_id === id || f.id === id) ||
      null
    );
  }

  async getFindingsForScan(scanId: string): Promise<FindingRow[]> {
    return Array.from(this.findings.values()).filter((f) => f.scan_id === scanId);
  }

  // Access Control Operations
  async grantRepoAccess(userId: string, repoId: string): Promise<void> {
    this.userRepoAccess.add(`${userId}:${repoId}`);
  }

  async revokeRepoAccess(userId: string, repoId: string): Promise<void> {
    this.userRepoAccess.delete(`${userId}:${repoId}`);
  }

  async revokeAllAccessForUser(userId: string): Promise<void> {
    for (const key of Array.from(this.userRepoAccess.keys())) {
      if (key.startsWith(`${userId}:`)) {
        this.userRepoAccess.delete(key);
      }
    }
  }

  async checkUserRepoAccess(userId: string, repoId: string): Promise<boolean> {
    return this.userRepoAccess.has(`${userId}:${repoId}`);
  }

  async getUserAccessibleRepositories(userId: string): Promise<RepositoryRow[]> {
    const accessible: RepositoryRow[] = [];
    for (const repo of this.repositories.values()) {
      if (this.userRepoAccess.has(`${userId}:${repo.id}`)) {
        accessible.push(repo);
      }
    }
    return accessible;
  }

  // Audit Log Operations
  async createAuditLog(
    entry:
      | Omit<AuditLogRow, "id" | "timestamp">
      | { userId: string; repoId: string; action: string; tokenId: string; timestamp?: string }
  ): Promise<AuditLogRow> {
    if ("userId" in entry) {
      const newEntry: AuditLogRow = {
        id: crypto.randomUUID(),
        user_id: entry.userId,
        action: entry.action,
        target_resource: entry.repoId,
        ip_address: "127.0.0.1",
        user_agent: "nantis-worker",
        timestamp: entry.timestamp || new Date().toISOString(),
        details: { tokenId: entry.tokenId },
      };
      this.auditLogs.push(newEntry);
      return newEntry;
    }

    const newEntry: AuditLogRow = {
      ...entry,
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
    };
    this.auditLogs.push(newEntry);
    return newEntry;
  }

  async getAuditLogs(): Promise<AuditLogRow[]> {
    return [...this.auditLogs];
  }

  // False Positive Report Operations
  async createFalsePositiveReport(data: {
    rule_id: string;
    fingerprint: string;
    user_note: string;
    user_id?: string | null;
  }): Promise<FalsePositiveReportRow> {
    const report: FalsePositiveReportRow = {
      id: crypto.randomUUID(),
      rule_id: data.rule_id,
      fingerprint: data.fingerprint,
      user_note: data.user_note,
      user_id: data.user_id || null,
      created_at: new Date().toISOString(),
    };
    this.falsePositiveReports.set(report.id, report);
    return report;
  }

  async getFalsePositiveReports(): Promise<FalsePositiveReportRow[]> {
    return Array.from(this.falsePositiveReports.values());
  }

  // Finding Labels Operations
  async setFindingLabel(data: {
    user_id: string;
    finding_id: string;
    repo_full_name: string;
    rule_id: string;
    file: string;
    line: number;
    label: "real_issue" | "false_positive" | "not_sure";
  }): Promise<FindingLabelRow> {
    const key = `${data.user_id}:${data.finding_id}`;
    const existing = this.findingLabels.get(key);
    const now = new Date().toISOString();

    if (existing) {
      existing.label = data.label;
      existing.created_at = now;
      return existing;
    }

    const row: FindingLabelRow = {
      id: crypto.randomUUID(),
      user_id: data.user_id,
      finding_id: data.finding_id,
      repo_full_name: data.repo_full_name,
      rule_id: data.rule_id,
      file: data.file,
      line: data.line,
      label: data.label,
      created_at: now,
    };
    this.findingLabels.set(key, row);
    return row;
  }

  async getFindingLabel(userId: string, findingId: string): Promise<FindingLabelRow | null> {
    return this.findingLabels.get(`${userId}:${findingId}`) || null;
  }

  async getFindingLabelsForRepo(userId: string, repoFullName: string): Promise<FindingLabelRow[]> {
    return Array.from(this.findingLabels.values()).filter(
      (l) => l.user_id === userId && l.repo_full_name.toLowerCase() === repoFullName.toLowerCase()
    );
  }

  async exportFindingLabelsJson(userId: string, repoFullName?: string): Promise<string> {
    const labels = Array.from(this.findingLabels.values()).filter(
      (l) => l.user_id === userId && (!repoFullName || l.repo_full_name.toLowerCase() === repoFullName.toLowerCase())
    );
    return JSON.stringify(labels, null, 2);
  }

  private userRepoSnapshots = new Map<string, UserRepoSnapshotRow>(); // key: `${userId}:${githubRepoId}`
  private userInstallations = new Map<string, UserInstallationRow>(); // key: `${userId}:${installationId}`
  private anonymousRateLimits = new Map<string, { count: number; dayStartMs: number }>();
  private userSnapshotTaken = new Set<string>();

  // User Repo Access Snapshot Operations (Comparing by numeric github_repo_id)
  async saveUserRepoSnapshot(
    userId: string,
    repos: {
      github_repo_id: number;
      repo_name: string;
      full_name: string;
      installation_id: number;
      private: boolean;
      html_url?: string;
    }[],
    ttlMs = 3600000
  ): Promise<void> {
    const now = Date.now();
    const fetchedAt = new Date(now).toISOString();
    const expiresAt = new Date(now + ttlMs).toISOString();

    this.userSnapshotTaken.add(userId);

    // Clear old snapshot for this user
    for (const key of Array.from(this.userRepoSnapshots.keys())) {
      if (key.startsWith(`${userId}:`)) {
        this.userRepoSnapshots.delete(key);
      }
    }

    for (const r of repos) {
      const key = `${userId}:${r.github_repo_id}`;
      const row: UserRepoSnapshotRow = {
        id: crypto.randomUUID(),
        user_id: userId,
        github_repo_id: r.github_repo_id,
        repo_name: r.repo_name,
        full_name: r.full_name,
        installation_id: r.installation_id,
        private: r.private,
        html_url: r.html_url,
        fetched_at: fetchedAt,
        expires_at: expiresAt,
      };
      this.userRepoSnapshots.set(key, row);
    }
  }

  async getUserUnexpiredSnapshot(userId: string, nowMs: number = Date.now()): Promise<UserRepoSnapshotRow[]> {
    const valid: UserRepoSnapshotRow[] = [];
    for (const row of this.userRepoSnapshots.values()) {
      if (row.user_id === userId) {
        const expiresAtMs = new Date(row.expires_at).getTime();
        if (expiresAtMs > nowMs) {
          valid.push(row);
        }
      }
    }
    return valid;
  }

  async checkUserRepoSnapshotValid(
    userId: string,
    githubRepoId: number,
    nowMs: number = Date.now()
  ): Promise<UserRepoSnapshotRow | null> {
    const key = `${userId}:${githubRepoId}`;
    const row = this.userRepoSnapshots.get(key);
    if (row) {
      const expiresAtMs = new Date(row.expires_at).getTime();
      if (expiresAtMs <= nowMs) {
        return null;
      }
      return row;
    }

    // Fallback for dev mode / legacy tests where user has zero snapshot records set up
    if (!this.userSnapshotTaken.has(userId)) {
      const repo = await this.getRepositoryByGithubId(githubRepoId);
      if (repo && this.userRepoAccess.has(`${userId}:${repo.id}`)) {
        return {
          id: `synth_${repo.id}`,
          user_id: userId,
          github_repo_id: githubRepoId,
          repo_name: repo.name,
          full_name: repo.full_name,
          installation_id: Number(repo.installation_id) || 1,
          private: repo.private,
          html_url: `https://github.com/${repo.full_name}`,
          fetched_at: new Date().toISOString(),
          expires_at: new Date(nowMs + 3600000).toISOString(),
        };
      }
    }

    return null;
  }

  async clearUserRepoSnapshot(userId: string): Promise<void> {
    for (const key of Array.from(this.userRepoSnapshots.keys())) {
      if (key.startsWith(`${userId}:`)) {
        this.userRepoSnapshots.delete(key);
      }
    }
    this.revokeAllAccessForUser(userId);
  }

  // Webhook Deletion Helpers
  async deleteSnapshotsForInstallation(installationId: number): Promise<void> {
    for (const [key, row] of Array.from(this.userRepoSnapshots.entries())) {
      if (row.installation_id === installationId) {
        this.userRepoSnapshots.delete(key);
      }
    }
    this.installations.delete(installationId);
  }

  async deleteSnapshotsForRepo(githubRepoId: number): Promise<void> {
    for (const [key, row] of Array.from(this.userRepoSnapshots.entries())) {
      if (row.github_repo_id === githubRepoId) {
        this.userRepoSnapshots.delete(key);
      }
    }
  }

  // User Installation Mapping Operations
  async linkUserInstallation(userId: string, installationId: number, htmlUrl?: string): Promise<UserInstallationRow> {
    const key = `${userId}:${installationId}`;
    const existing = this.userInstallations.get(key);
    if (existing) {
      if (htmlUrl) existing.html_url = htmlUrl;
      return existing;
    }

    const row: UserInstallationRow = {
      id: crypto.randomUUID(),
      user_id: userId,
      installation_id: installationId,
      html_url: htmlUrl || `https://github.com/settings/installations/${installationId}`,
      created_at: new Date().toISOString(),
    };
    this.userInstallations.set(key, row);
    return row;
  }

  async getUserInstallations(userId: string): Promise<UserInstallationRow[]> {
    return Array.from(this.userInstallations.values()).filter((i) => i.user_id === userId);
  }

  async checkUserInstallationAccess(userId: string, installationId: number): Promise<boolean> {
    return this.userInstallations.has(`${userId}:${installationId}`);
  }

  async revokeUserInstallation(userId: string, installationId: number): Promise<void> {
    this.userInstallations.delete(`${userId}:${installationId}`);
    for (const [key, row] of Array.from(this.userRepoSnapshots.entries())) {
      if (row.user_id === userId && row.installation_id === installationId) {
        this.userRepoSnapshots.delete(key);
      }
    }
  }

  // Path B Anonymous Scan Rate Limiter
  async checkAnonymousRateLimit(
    key: string,
    dailyCap = 20
  ): Promise<{ allowed: boolean; remaining: number }> {
    const now = Date.now();
    const dayMs = 24 * 60 * 60 * 1000;
    const entry = this.anonymousRateLimits.get(key);

    if (!entry || now - entry.dayStartMs > dayMs) {
      this.anonymousRateLimits.set(key, { count: 1, dayStartMs: now });
      return { allowed: true, remaining: dailyCap - 1 };
    }

    if (entry.count >= dailyCap) {
      return { allowed: false, remaining: 0 };
    }

    entry.count += 1;
    return { allowed: true, remaining: dailyCap - entry.count };
  }

  // Webhook Delivery Deduplication
  async recordWebhookDelivery(
    deliveryId: string,
    eventType: string,
    action?: string | null
  ): Promise<boolean> {
    if (this.webhookDeliveries.has(deliveryId)) {
      return false; // Already processed
    }

    const row: WebhookDeliveryRow = {
      id: crypto.randomUUID(),
      delivery_id: deliveryId,
      event_type: eventType,
      action: action || null,
      processed_at: new Date().toISOString(),
    };
    this.webhookDeliveries.set(deliveryId, row);
    return true; // Successfully recorded new delivery
  }

  // Utility reset for testing
  resetInMemoryData() {
    this.users.clear();
    this.installations.clear();
    this.repositories.clear();
    this.scans.clear();
    this.findings.clear();
    this.falsePositiveReports.clear();
    this.findingLabels.clear();
    this.userRepoAccess.clear();
    this.userRepoSnapshots.clear();
    this.userInstallations.clear();
    this.anonymousRateLimits.clear();
    this.userSnapshotTaken.clear();
    this.scanDiagnosticsMap.clear();
    this.webhookDeliveries.clear();
    this.auditLogs = [];
  }
}

import { PostgresDatabaseClient } from "./postgres-client.js";
export { PostgresDatabaseClient };

export type IDatabaseClient = DatabaseClient | PostgresDatabaseClient;

export function createDatabaseClient(): IDatabaseClient {
  const dbUrl = process.env.DATABASE_URL;
  const nodeEnv = process.env.NODE_ENV;

  if (nodeEnv === "production") {
    if (!dbUrl) {
      throw new Error(
        "CRITICAL DATABASE CONFIGURATION ERROR: Production mode requires DATABASE_URL to be set for PostgreSQL persistence. Production will NOT fall back to volatile in-memory storage."
      );
    }
    return new PostgresDatabaseClient(dbUrl);
  }

  // In development and test environments, use Postgres if explicitly enabled, otherwise in-memory storage
  if (process.env.USE_POSTGRES === "true" && dbUrl) {
    return new PostgresDatabaseClient(dbUrl);
  }

  return new DatabaseClient();
}

export const db = createDatabaseClient();
