import fs from "fs";
import path from "path";
import pg from "pg";
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
} from "./schema.js";

const { Pool } = pg;

export class PostgresDatabaseClient {
  public pool: pg.Pool;

  constructor(connectionStringOrConfig?: string | pg.PoolConfig) {
    if (typeof connectionStringOrConfig === "string") {
      this.pool = new Pool({ connectionString: connectionStringOrConfig });
    } else if (connectionStringOrConfig) {
      this.pool = new Pool(connectionStringOrConfig);
    } else {
      const connectionString =
        process.env.DATABASE_URL || "postgres://postgres:postgres@localhost:5432/nantis";
      this.pool = new Pool({ connectionString });
    }
  }

  async runMigrations(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version INT PRIMARY KEY,
          name TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      const migrations = [
        { version: 1, name: "001_initial_schema", file: "migrations/001_initial_schema.sql" },
        { version: 2, name: "002_add_pr_publication_columns", file: "migrations/002_add_pr_publication_columns.sql" },
      ];

      for (const m of migrations) {
        const migrationPath = path.resolve(__dirname, m.file);
        if (fs.existsSync(migrationPath)) {
          const res = await client.query("SELECT version FROM schema_migrations WHERE version = $1", [m.version]);
          if (res.rowCount === 0) {
            const sql = fs.readFileSync(migrationPath, "utf-8");
            await client.query(sql);
            await client.query(
              "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
              [m.version, m.name]
            );
          }
        }
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // Users Operations
  async upsertUser(data: {
    github_user_id: number;
    github_login: string;
    avatar_url: string;
  }): Promise<UserRow> {
    const query = `
      INSERT INTO users (github_user_id, github_login, avatar_url, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (github_user_id) DO UPDATE SET
        github_login = EXCLUDED.github_login,
        avatar_url = EXCLUDED.avatar_url,
        updated_at = NOW()
      RETURNING *;
    `;
    const res = await this.pool.query<UserRow>(query, [
      data.github_user_id,
      data.github_login,
      data.avatar_url,
    ]);
    return res.rows[0];
  }

  async getUserById(id: string): Promise<UserRow | null> {
    const res = await this.pool.query<UserRow>("SELECT * FROM users WHERE id = $1", [id]);
    return res.rows[0] || null;
  }

  async getUserByGithubId(githubUserId: number): Promise<UserRow | null> {
    const res = await this.pool.query<UserRow>(
      "SELECT * FROM users WHERE github_user_id = $1",
      [githubUserId]
    );
    return res.rows[0] || null;
  }

  // GitHub Installations Operations
  async upsertInstallation(data: {
    installation_id: number;
    target_type: "User" | "Organization";
    target_id: number;
    account_name: string;
  }): Promise<GithubInstallationRow> {
    const query = `
      INSERT INTO github_installations (installation_id, target_type, target_id, account_name, updated_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (installation_id) DO UPDATE SET
        target_type = EXCLUDED.target_type,
        target_id = EXCLUDED.target_id,
        account_name = EXCLUDED.account_name,
        updated_at = NOW()
      RETURNING *;
    `;
    const res = await this.pool.query<GithubInstallationRow>(query, [
      data.installation_id,
      data.target_type,
      data.target_id,
      data.account_name,
    ]);
    return res.rows[0];
  }

  async deleteInstallation(installationId: number): Promise<boolean> {
    const res = await this.pool.query(
      "DELETE FROM github_installations WHERE installation_id = $1",
      [installationId]
    );
    return (res.rowCount || 0) > 0;
  }

  async getInstallationByGithubId(installationId: number): Promise<GithubInstallationRow | null> {
    const res = await this.pool.query<GithubInstallationRow>(
      "SELECT * FROM github_installations WHERE installation_id = $1",
      [installationId]
    );
    return res.rows[0] || null;
  }

  async getInstallation(ref: string | number): Promise<GithubInstallationRow | null> {
    if (typeof ref === "number") {
      return this.getInstallationByGithubId(ref);
    }
    const parsed = Number(ref);
    if (!Number.isNaN(parsed)) {
      const byGithubId = await this.getInstallationByGithubId(parsed);
      if (byGithubId) return byGithubId;
    }
    const res = await this.pool.query<GithubInstallationRow>(
      "SELECT * FROM github_installations WHERE id = $1",
      [ref]
    );
    return res.rows[0] || null;
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
    const query = `
      INSERT INTO repositories (id, installation_id, github_repo_id, name, full_name, private, default_branch, updated_at)
      VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7, NOW())
      ON CONFLICT (github_repo_id) DO UPDATE SET
        installation_id = EXCLUDED.installation_id,
        name = EXCLUDED.name,
        full_name = EXCLUDED.full_name,
        private = EXCLUDED.private,
        default_branch = EXCLUDED.default_branch,
        updated_at = NOW()
      RETURNING *;
    `;
    const res = await this.pool.query<RepositoryRow>(query, [
      data.id || null,
      data.installation_id,
      data.github_repo_id,
      data.name,
      data.full_name,
      data.private,
      data.default_branch,
    ]);
    return res.rows[0];
  }

  async getRepositoryById(id: string): Promise<RepositoryRow | null> {
    const res = await this.pool.query<RepositoryRow>("SELECT * FROM repositories WHERE id = $1", [
      id,
    ]);
    return res.rows[0] || null;
  }

  async getRepositoryByGithubId(githubRepoId: number): Promise<RepositoryRow | null> {
    const res = await this.pool.query<RepositoryRow>(
      "SELECT * FROM repositories WHERE github_repo_id = $1",
      [githubRepoId]
    );
    return res.rows[0] || null;
  }

  async getRepositoryByFullName(fullName: string): Promise<RepositoryRow | null> {
    const res = await this.pool.query<RepositoryRow>(
      "SELECT * FROM repositories WHERE LOWER(full_name) = LOWER($1)",
      [fullName]
    );
    return res.rows[0] || null;
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
    const query = `
      INSERT INTO scans (id, repository_id, status, trigger_type, commit_sha, branch, github_check_run_id, triggered_by_user_id, started_at)
      VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, NOW())
      RETURNING *;
    `;
    const res = await this.pool.query<ScanRow>(query, [
      data.id || null,
      data.repository_id,
      data.status,
      data.trigger_type,
      data.commit_sha,
      data.branch,
      data.github_check_run_id || null,
      data.triggered_by_user_id || null,
    ]);
    return res.rows[0];
  }

  async updateScanCheckRunId(scanId: string, checkRunId: number): Promise<void> {
    const query = "UPDATE scans SET github_check_run_id = $1 WHERE id = $2;";
    await this.pool.query(query, [checkRunId, scanId]);
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
    const query = `
      UPDATE scans
      SET github_pr_number = COALESCE($1, github_pr_number),
          github_pr_url = COALESCE($2, github_pr_url),
          github_branch = COALESCE($3, github_branch),
          publication_status = COALESCE($4, publication_status),
          publication_error = COALESCE($5, publication_error)
      WHERE id = $6;
    `;
    await this.pool.query(query, [
      data.github_pr_number ?? null,
      data.github_pr_url ?? null,
      data.github_branch ?? null,
      data.publication_status ?? null,
      data.publication_error ?? null,
      scanId,
    ]);
  }

  async getScanById(id: string): Promise<ScanRow | null> {
    const res = await this.pool.query<ScanRow>("SELECT * FROM scans WHERE id = $1", [id]);
    return res.rows[0] || null;
  }

  async getScansForRepository(repositoryId: string): Promise<ScanRow[]> {
    const res = await this.pool.query<ScanRow>(
      "SELECT * FROM scans WHERE repository_id = $1 ORDER BY started_at DESC",
      [repositoryId]
    );
    return res.rows;
  }

  async getAllScans(): Promise<ScanRow[]> {
    const res = await this.pool.query<ScanRow>("SELECT * FROM scans ORDER BY started_at DESC LIMIT 50;");
    return res.rows;
  }

  async getAllFindings(): Promise<FindingRow[]> {
    const res = await this.pool.query<FindingRow>("SELECT * FROM findings ORDER BY created_at DESC LIMIT 100;");
    return res.rows;
  }

  async getAllRepositories(): Promise<RepositoryRow[]> {
    const res = await this.pool.query<RepositoryRow>("SELECT * FROM repositories ORDER BY created_at DESC LIMIT 50;");
    return res.rows;
  }

  async getPreviousCompletedScan(repositoryId: string, currentScanId?: string): Promise<ScanRow | null> {
    const query = `
      SELECT * FROM scans
      WHERE repository_id = $1 AND ($2::uuid IS NULL OR id != $2::uuid) AND status IN ('done', 'completed')
      ORDER BY started_at DESC LIMIT 1;
    `;
    const res = await this.pool.query<ScanRow>(query, [repositoryId, currentScanId || null]);
    return res.rows[0] || null;
  }

  async updateScanStatus(
    scanId: string,
    status: ScanRow["status"],
    errorMessage?: string
  ): Promise<void> {
    const isFinished = status === "done" || status === "completed" || status === "failed";
    const query = `
      UPDATE scans
      SET status = $1,
          completed_at = CASE WHEN $2 THEN NOW() ELSE completed_at END,
          error_message = COALESCE($3, error_message)
      WHERE id = $4
      RETURNING *;
    `;
    const res = await this.pool.query<ScanRow>(query, [status, isFinished, errorMessage || null, scanId]);
    const scan = res.rows[0];

    if (scan && scan.github_check_run_id) {
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
            checkRunId: Number(scan.github_check_run_id),
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

  async getScanStatus(scanId: string): Promise<{ status: JobStatus; errorMessage?: string }> {
    const scan = await this.getScanById(scanId);
    if (!scan) return { status: "queued" };
    return {
      status: scan.status as JobStatus,
      errorMessage: scan.error_message || undefined,
    };
  }

  // Findings Operations
  async createFinding(data: Omit<FindingRow, "db_id"> & { db_id?: string }): Promise<FindingRow> {
    const query = `
      INSERT INTO findings (
        db_id, scan_id, finding_id, rule_id, title, severity, confidence_tier, file,
        start_line, end_line, explanation, evidence_chain, unresolved_steps, fingerprint
      )
      VALUES (
        COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
      )
      RETURNING *;
    `;
    const res = await this.pool.query<FindingRow>(query, [
      data.db_id || null,
      data.scan_id,
      data.id || crypto.randomUUID(),
      data.ruleId,
      data.title,
      data.severity,
      data.confidenceTier || "needs-review",
      data.file,
      data.lineRange?.startLine || 1,
      data.lineRange?.endLine || 1,
      data.explanation,
      JSON.stringify(data.evidenceChain || []),
      JSON.stringify(data.unresolvedSteps || []),
      data.fingerprint,
    ]);
    return res.rows[0];
  }

  async saveScanFindings(scanId: string, findings: Finding[]): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const f of findings) {
        const query = `
          INSERT INTO findings (
            scan_id, finding_id, rule_id, title, severity, confidence_tier, file,
            start_line, end_line, explanation, evidence_chain, unresolved_steps, fingerprint
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);
        `;
        await client.query(query, [
          scanId,
          f.id || crypto.randomUUID(),
          f.ruleId,
          f.title,
          f.severity,
          f.confidenceTier || "needs-review",
          f.file,
          f.lineRange?.startLine || 1,
          f.lineRange?.endLine || 1,
          f.explanation,
          JSON.stringify(f.evidenceChain || []),
          JSON.stringify(f.unresolvedSteps || []),
          f.fingerprint,
        ]);
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async getFindingById(id: string): Promise<FindingRow | null> {
    const res = await this.pool.query<FindingRow>(
      "SELECT * FROM findings WHERE db_id = $1 OR finding_id = $1",
      [id]
    );
    return res.rows[0] || null;
  }

  async getFindingsForScan(scanId: string): Promise<FindingRow[]> {
    const res = await this.pool.query<FindingRow>(
      "SELECT * FROM findings WHERE scan_id = $1 ORDER BY start_line ASC",
      [scanId]
    );
    return res.rows;
  }

  // Diagnostics Operations
  async saveScanDiagnostics(scanId: string, diagnostics: ScanDiagnostic[]): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const d of diagnostics) {
        const query = `
          INSERT INTO scan_diagnostics (scan_id, kind, detector_id, detector_name, message, fatal)
          VALUES ($1, $2, $3, $4, $5, $6);
        `;
        await client.query(query, [
          scanId,
          d.kind,
          d.detectorId || null,
          d.detectorName || null,
          d.message,
          d.fatal || false,
        ]);
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async getScanDiagnostics(scanId: string): Promise<ScanDiagnostic[]> {
    const res = await this.pool.query<{
      kind: string;
      detector_id: string;
      detector_name: string;
      message: string;
      fatal: boolean;
      created_at: string;
    }>("SELECT * FROM scan_diagnostics WHERE scan_id = $1", [scanId]);

    return res.rows.map((r) => ({
      kind: r.kind as ScanDiagnostic["kind"],
      detectorId: r.detector_id || undefined,
      detectorName: r.detector_name || undefined,
      message: r.message,
      fatal: r.fatal,
      timestamp: r.created_at,
    }));
  }

  // Access Control Operations
  async grantRepoAccess(userId: string, repoId: string): Promise<void> {
    const query = `
      INSERT INTO user_repo_access (user_id, repository_id)
      VALUES ($1, $2)
      ON CONFLICT (user_id, repository_id) DO NOTHING;
    `;
    await this.pool.query(query, [userId, repoId]);
  }

  async revokeRepoAccess(userId: string, repoId: string): Promise<void> {
    await this.pool.query(
      "DELETE FROM user_repo_access WHERE user_id = $1 AND repository_id = $2",
      [userId, repoId]
    );
  }

  async revokeAllAccessForUser(userId: string): Promise<void> {
    await this.pool.query("DELETE FROM user_repo_access WHERE user_id = $1", [userId]);
  }

  async checkUserRepoAccess(userId: string, repoId: string): Promise<boolean> {
    const res = await this.pool.query(
      "SELECT 1 FROM user_repo_access WHERE user_id = $1 AND repository_id = $2",
      [userId, repoId]
    );
    return (res.rowCount || 0) > 0;
  }

  async getUserAccessibleRepositories(userId: string): Promise<RepositoryRow[]> {
    const query = `
      SELECT r.* FROM repositories r
      INNER JOIN user_repo_access ura ON r.id = ura.repository_id
      WHERE ura.user_id = $1
      ORDER BY r.name ASC;
    `;
    const res = await this.pool.query<RepositoryRow>(query, [userId]);
    return res.rows;
  }

  // Audit Log Operations
  async createAuditLog(
    entry:
      | Omit<AuditLogRow, "id" | "timestamp">
      | { userId: string; repoId: string; action: string; tokenId: string; timestamp?: string }
  ): Promise<AuditLogRow> {
    if ("userId" in entry) {
      const query = `
        INSERT INTO audit_logs (user_id, action, target_resource, ip_address, user_agent, timestamp, details)
        VALUES ($1, $2, $3, '127.0.0.1', 'nantis-worker', COALESCE($4::timestamptz, NOW()), $5)
        RETURNING *;
      `;
      const res = await this.pool.query<AuditLogRow>(query, [
        entry.userId,
        entry.action,
        entry.repoId,
        entry.timestamp || null,
        JSON.stringify({ tokenId: entry.tokenId }),
      ]);
      return res.rows[0];
    }

    const query = `
      INSERT INTO audit_logs (user_id, action, target_resource, ip_address, user_agent, timestamp, details)
      VALUES ($1, $2, $3, $4, $5, NOW(), $6)
      RETURNING *;
    `;
    const res = await this.pool.query<AuditLogRow>(query, [
      entry.user_id || null,
      entry.action,
      entry.target_resource,
      entry.ip_address,
      entry.user_agent,
      JSON.stringify(entry.details || {}),
    ]);
    return res.rows[0];
  }

  async getAuditLogs(): Promise<AuditLogRow[]> {
    const res = await this.pool.query<AuditLogRow>(
      "SELECT * FROM audit_logs ORDER BY timestamp DESC"
    );
    return res.rows;
  }

  // False Positive Report Operations
  async createFalsePositiveReport(data: {
    rule_id: string;
    fingerprint: string;
    user_note: string;
    user_id?: string | null;
  }): Promise<FalsePositiveReportRow> {
    const query = `
      INSERT INTO false_positive_reports (rule_id, fingerprint, user_note, user_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;
    const res = await this.pool.query<FalsePositiveReportRow>(query, [
      data.rule_id,
      data.fingerprint,
      data.user_note,
      data.user_id || null,
    ]);
    return res.rows[0];
  }

  async getFalsePositiveReports(): Promise<FalsePositiveReportRow[]> {
    const res = await this.pool.query<FalsePositiveReportRow>(
      "SELECT * FROM false_positive_reports ORDER BY created_at DESC"
    );
    return res.rows;
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
    const query = `
      INSERT INTO finding_labels (user_id, finding_id, repo_full_name, rule_id, file, line, label)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (user_id, finding_id) DO UPDATE SET
        label = EXCLUDED.label,
        created_at = NOW()
      RETURNING *;
    `;
    const res = await this.pool.query<FindingLabelRow>(query, [
      data.user_id,
      data.finding_id,
      data.repo_full_name,
      data.rule_id,
      data.file,
      data.line,
      data.label,
    ]);
    return res.rows[0];
  }

  async getFindingLabel(userId: string, findingId: string): Promise<FindingLabelRow | null> {
    const res = await this.pool.query<FindingLabelRow>(
      "SELECT * FROM finding_labels WHERE user_id = $1 AND finding_id = $2",
      [userId, findingId]
    );
    return res.rows[0] || null;
  }

  async getFindingLabelsForRepo(userId: string, repoFullName: string): Promise<FindingLabelRow[]> {
    const res = await this.pool.query<FindingLabelRow>(
      "SELECT * FROM finding_labels WHERE user_id = $1 AND LOWER(repo_full_name) = LOWER($2)",
      [userId, repoFullName]
    );
    return res.rows;
  }

  async exportFindingLabelsJson(userId: string, repoFullName?: string): Promise<string> {
    const query = repoFullName
      ? "SELECT * FROM finding_labels WHERE user_id = $1 AND LOWER(repo_full_name) = LOWER($2)"
      : "SELECT * FROM finding_labels WHERE user_id = $1";
    const params = repoFullName ? [userId, repoFullName] : [userId];
    const res = await this.pool.query<FindingLabelRow>(query, params);
    return JSON.stringify(res.rows, null, 2);
  }

  // User Repo Access Snapshot Operations
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
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("DELETE FROM user_repo_snapshots WHERE user_id = $1", [userId]);
      const expiresAt = new Date(Date.now() + ttlMs).toISOString();

      for (const r of repos) {
        const query = `
          INSERT INTO user_repo_snapshots (user_id, github_repo_id, repo_name, full_name, installation_id, private, html_url, expires_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
        `;
        await client.query(query, [
          userId,
          r.github_repo_id,
          r.repo_name,
          r.full_name,
          r.installation_id,
          r.private,
          r.html_url || null,
          expiresAt,
        ]);
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async getUserUnexpiredSnapshot(userId: string, nowMs: number = Date.now()): Promise<UserRepoSnapshotRow[]> {
    const res = await this.pool.query<UserRepoSnapshotRow>(
      "SELECT * FROM user_repo_snapshots WHERE user_id = $1 AND expires_at > $2::timestamptz",
      [userId, new Date(nowMs).toISOString()]
    );
    return res.rows;
  }

  async checkUserRepoSnapshotValid(
    userId: string,
    githubRepoId: number,
    nowMs: number = Date.now()
  ): Promise<UserRepoSnapshotRow | null> {
    const res = await this.pool.query<UserRepoSnapshotRow>(
      "SELECT * FROM user_repo_snapshots WHERE user_id = $1 AND github_repo_id = $2 AND expires_at > $3::timestamptz",
      [userId, githubRepoId, new Date(nowMs).toISOString()]
    );
    if (res.rows[0]) return res.rows[0];

    // Fallback if user has no snapshots
    const countRes = await this.pool.query("SELECT COUNT(*) FROM user_repo_snapshots WHERE user_id = $1", [userId]);
    const totalSnapshots = parseInt(countRes.rows[0].count, 10);
    if (totalSnapshots === 0) {
      const repo = await this.getRepositoryByGithubId(githubRepoId);
      if (repo && (await this.checkUserRepoAccess(userId, repo.id))) {
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
    await this.pool.query("DELETE FROM user_repo_snapshots WHERE user_id = $1", [userId]);
    await this.revokeAllAccessForUser(userId);
  }

  async deleteSnapshotsForInstallation(installationId: number): Promise<void> {
    await this.pool.query("DELETE FROM user_repo_snapshots WHERE installation_id = $1", [
      installationId,
    ]);
    await this.pool.query("DELETE FROM github_installations WHERE installation_id = $1", [
      installationId,
    ]);
  }

  async deleteSnapshotsForRepo(githubRepoId: number): Promise<void> {
    await this.pool.query("DELETE FROM user_repo_snapshots WHERE github_repo_id = $1", [
      githubRepoId,
    ]);
  }

  // User Installation Mapping Operations
  async linkUserInstallation(
    userId: string,
    installationId: number,
    htmlUrl?: string
  ): Promise<UserInstallationRow> {
    const query = `
      INSERT INTO user_installations (user_id, installation_id, html_url)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id, installation_id) DO UPDATE SET
        html_url = COALESCE(EXCLUDED.html_url, user_installations.html_url)
      RETURNING *;
    `;
    const res = await this.pool.query<UserInstallationRow>(query, [
      userId,
      installationId,
      htmlUrl || `https://github.com/settings/installations/${installationId}`,
    ]);
    return res.rows[0];
  }

  async getUserInstallations(userId: string): Promise<UserInstallationRow[]> {
    const res = await this.pool.query<UserInstallationRow>(
      "SELECT * FROM user_installations WHERE user_id = $1",
      [userId]
    );
    return res.rows;
  }

  async checkUserInstallationAccess(userId: string, installationId: number): Promise<boolean> {
    const res = await this.pool.query(
      "SELECT 1 FROM user_installations WHERE user_id = $1 AND installation_id = $2",
      [userId, installationId]
    );
    return (res.rowCount || 0) > 0;
  }

  async revokeUserInstallation(userId: string, installationId: number): Promise<void> {
    await this.pool.query(
      "DELETE FROM user_installations WHERE user_id = $1 AND installation_id = $2",
      [userId, installationId]
    );
    await this.pool.query(
      "DELETE FROM user_repo_snapshots WHERE user_id = $1 AND installation_id = $2",
      [userId, installationId]
    );
  }

  // Rate Limiting Operations
  async checkAnonymousRateLimit(
    key: string,
    dailyCap = 20
  ): Promise<{ allowed: boolean; remaining: number }> {
    const now = Date.now();
    const dayMs = 24 * 60 * 60 * 1000;

    const res = await this.pool.query<{ count: number; day_start_ms: string }>(
      "SELECT count, day_start_ms FROM anonymous_rate_limits WHERE key = $1",
      [key]
    );

    const row = res.rows[0];
    if (!row || now - parseInt(row.day_start_ms, 10) > dayMs) {
      await this.pool.query(
        `INSERT INTO anonymous_rate_limits (key, count, day_start_ms)
         VALUES ($1, 1, $2)
         ON CONFLICT (key) DO UPDATE SET count = 1, day_start_ms = EXCLUDED.day_start_ms;`,
        [key, now]
      );
      return { allowed: true, remaining: dailyCap - 1 };
    }

    if (row.count >= dailyCap) {
      return { allowed: false, remaining: 0 };
    }

    await this.pool.query("UPDATE anonymous_rate_limits SET count = count + 1 WHERE key = $1", [
      key,
    ]);
    return { allowed: true, remaining: dailyCap - (row.count + 1) };
  }

  // Webhook Delivery Deduplication
  async recordWebhookDelivery(
    deliveryId: string,
    eventType: string,
    action?: string | null
  ): Promise<boolean> {
    const query = `
      INSERT INTO webhook_deliveries (delivery_id, event_type, action, processed_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (delivery_id) DO NOTHING
      RETURNING delivery_id;
    `;
    const res = await this.pool.query(query, [deliveryId, eventType, action || null]);
    return (res.rowCount || 0) > 0;
  }

  resetInMemoryData(): void {
    // No-op for postgres client, or truncate tables for testing
    this.resetDataForTesting().catch(() => {});
  }

  async resetDataForTesting(): Promise<void> {
    await this.pool.query(`
      TRUNCATE TABLE users, github_installations, repositories, scans, findings,
                     scan_diagnostics, user_repo_access, audit_logs, false_positive_reports,
                     finding_labels, user_repo_snapshots, user_installations, anonymous_rate_limits,
                     webhook_deliveries
      CASCADE;
    `);
  }
}

