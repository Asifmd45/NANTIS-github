import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import {
  escapeHtml,
  getDefaultHeaders,
  getOrCreateCsrfToken,
  renderPageLayout,
} from "./ui-templates.js";

/**
 * Helper to extract authenticated user and repositories.
 */
async function getUserContext(req: RequestContext, env: WebEnv) {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  let userLogin: string | undefined = undefined;
  let userId: string = "dev-user-id";
  let isAuthenticated = false;

  if (token) {
    const session = decodeSession(token, env.SESSION_SECRET);
    if (session) {
      userLogin = session.githubLogin;
      userId = session.userId;
      isAuthenticated = true;
    }
  }

  const csrfToken = getOrCreateCsrfToken(userId);
  const userRepos = await db.getUserAccessibleRepositories(userId);
  return { userId, userLogin, isAuthenticated, csrfToken, userRepos };
}

/**
 * GET /scans - Scans history & management page
 */
export async function renderScansPage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const { userLogin, csrfToken, userRepos } = await getUserContext(req, env);

  // Fetch scans for user's repos or all recent scans in dev
  const allScans = await db.getAllScans();
  const allRepos = await db.getAllRepositories();
  const repoMap = new Map(allRepos.map((r) => [r.id, r]));

  // Sort scans by started_at descending
  const sortedScans = [...allScans].sort(
    (a, b) => new Date(b.started_at || 0).getTime() - new Date(a.started_at || 0).getTime()
  );

  const scanRowsHtml = await Promise.all(
    sortedScans.map(async (scan) => {
      const repo = repoMap.get(scan.repository_id);
      const repoName = repo ? repo.full_name : "sample/demo-repo";
      const findings = await db.getFindingsForScan(scan.id);
      const critCount = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;

      const statusBadge =
        scan.status === "done" || scan.status === "completed"
          ? `<span style="background: #dcfce7; color: #15803d; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px;">COMPLETED</span>`
          : scan.status === "running"
          ? `<span style="background: #e0e7ff; color: #4338ca; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px;">RUNNING</span>`
          : scan.status === "failed"
          ? `<span style="background: #fee2e2; color: #b91c1c; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px;">FAILED</span>`
          : `<span style="background: #f1f5f9; color: #475569; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px;">QUEUED</span>`;

      return `
        <tr style="border-bottom: 1px solid var(--border-color);">
          <td style="padding: 12px 16px; font-weight: 600; font-size: 13px;">
            <a href="/scans/${escapeHtml(scan.id)}" style="color: #0f172a; text-decoration: none;">${escapeHtml(repoName)}</a>
            <div style="font-size: 11px; color: var(--text-muted); font-family: monospace;">${escapeHtml(scan.commit_sha.slice(0, 8))} (${escapeHtml(scan.branch)})</div>
          </td>
          <td style="padding: 12px 16px;">${statusBadge}</td>
          <td style="padding: 12px 16px; font-size: 12px; color: #0f172a; font-weight: 700;">
            ${findings.length} findings
            ${critCount > 0 ? `<span style="color: #dc2626; font-size: 11px; margin-left: 4px;">(${critCount} high/crit)</span>` : ""}
          </td>
          <td style="padding: 12px 16px; font-size: 12px; color: var(--text-muted);">
            ${escapeHtml(scan.started_at ? new Date(scan.started_at).toLocaleString() : "Recent")}
          </td>
          <td style="padding: 12px 16px; text-align: right;">
            <a href="/scans/${escapeHtml(scan.id)}" class="btn btn-black" style="padding: 4px 10px; font-size: 11px; font-weight: 600;">View Findings →</a>
            <a href="/scans/${escapeHtml(scan.id)}/report" class="btn btn-outline" style="padding: 4px 10px; font-size: 11px; margin-left: 6px;">Report</a>
          </td>
        </tr>
      `;
    })
  );

  const content = `
    <div style="max-width: 1000px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
        <div>
          <h1 style="font-size: 28px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; margin-bottom: 4px;">Security Scans</h1>
          <p style="color: #64748b; font-size: 14px;">Historical and active AST security analysis runs across connected repositories.</p>
        </div>
        <div style="display: flex; gap: 10px;">
          <a href="/api/dev/scan-sample-demo" class="btn btn-black" style="font-size: 13px; font-weight: 600;">⚡ Run Demo Scan (1-click)</a>
          <a href="/repos" class="btn btn-outline" style="font-size: 13px;">Manage Repositories</a>
        </div>
      </div>

      <div class="ui-card" style="padding: 0; overflow: hidden;">
        <div style="padding: 16px 20px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; background: #fafafa;">
          <span style="font-weight: 700; font-size: 14px; color: #0f172a;">All Scans (${sortedScans.length})</span>
          <span style="font-size: 12px; color: #64748b;">Deterministic AST + Groq LLM Verification</span>
        </div>
        ${
          sortedScans.length === 0
            ? `<div style="text-align: center; padding: 48px 20px; color: var(--text-muted); font-size: 14px;">
                <p style="margin-bottom: 16px;">No scans have been performed yet.</p>
                <a href="/api/dev/scan-sample-demo" class="btn btn-black">Run Your First Demo Scan ➔</a>
              </div>`
            : `<div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; text-align: left;">
                  <thead>
                    <tr style="border-bottom: 1px solid var(--border-color); background: #f8fafc; font-size: 12px; color: #64748b; text-transform: uppercase;">
                      <th style="padding: 10px 16px;">Repository & Commit</th>
                      <th style="padding: 10px 16px;">Status</th>
                      <th style="padding: 10px 16px;">Findings</th>
                      <th style="padding: 10px 16px;">Triggered</th>
                      <th style="padding: 10px 16px; text-align: right;">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${scanRowsHtml.join("")}
                  </tbody>
                </table>
              </div>`
        }
      </div>
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Security Scans",
      userLogin,
      csrfToken,
      userRepos,
      scansCount: sortedScans.length,
      activeNav: "scans",
      content,
    }),
  };
}

/**
 * GET /findings - Global findings review table
 */
export async function renderFindingsPage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const { userLogin, csrfToken, userRepos } = await getUserContext(req, env);

  const allFindings = await db.getAllFindings();
  const allScans = await db.getAllScans();
  const scanMap = new Map(allScans.map((s) => [s.id, s]));

  const findingsRowsHtml = allFindings.map((f) => {
    const scan = scanMap.get(f.scan_id);
    const sevColor =
      f.severity === "critical"
        ? "#dc2626"
        : f.severity === "high"
        ? "#ea580c"
        : f.severity === "medium"
        ? "#d97706"
        : "#2563eb";

    const tierClass =
      f.confidenceTier === "proven"
        ? "chip-proven"
        : f.confidenceTier === "likely"
        ? "chip-likely"
        : f.confidenceTier === "hygiene"
        ? "chip-hygiene"
        : "chip-review";

    const lineNum = f.lineRange?.startLine || 1;

    return `
      <tr style="border-bottom: 1px solid var(--border-color);">
        <td style="padding: 12px 16px;">
          <span style="font-weight: 700; color: ${sevColor}; font-size: 12px; text-transform: uppercase;">
            ${escapeHtml(f.severity)}
          </span>
        </td>
        <td style="padding: 12px 16px;">
          <span class="chip-tier ${tierClass}">${escapeHtml(f.confidenceTier || "likely")}</span>
        </td>
        <td style="padding: 12px 16px;">
          <strong style="color: #0f172a; font-size: 13px;">${escapeHtml(f.ruleId)}</strong>
          <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(f.explanation?.slice(0, 75) || "")}...</div>
        </td>
        <td style="padding: 12px 16px; font-family: monospace; font-size: 12px; color: #334155;">
          ${escapeHtml(f.file)}:${lineNum}
        </td>
        <td style="padding: 12px 16px; text-align: right;">
          <a href="/findings/${escapeHtml(f.db_id || f.id)}/fix" class="btn btn-black" style="padding: 4px 10px; font-size: 11px; font-weight: 600;">
            Review in Sandbox ➔
          </a>
          ${
            scan
              ? `<a href="/scans/${escapeHtml(scan.id)}" class="btn btn-outline" style="padding: 4px 10px; font-size: 11px; margin-left: 6px;">Scan</a>`
              : ""
          }
        </td>
      </tr>
    `;
  });

  const content = `
    <div style="max-width: 1050px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
        <div>
          <h1 style="font-size: 28px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; margin-bottom: 4px;">Security Findings</h1>
          <p style="color: #64748b; font-size: 14px;">Identified AST security findings with deterministic evidence chains and patch capabilities.</p>
        </div>
        <div style="display: flex; gap: 10px;">
          <a href="/fixes" class="btn btn-outline" style="font-size: 13px;">View Fixable Patches</a>
        </div>
      </div>

      <div class="ui-card" style="padding: 0; overflow: hidden;">
        <div style="padding: 16px 20px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; background: #fafafa;">
          <span style="font-weight: 700; font-size: 14px; color: #0f172a;">All Findings (${allFindings.length})</span>
          <span style="font-size: 12px; color: #64748b;">Deterministic AST + Groq AI Hunters</span>
        </div>
        ${
          allFindings.length === 0
            ? `<div style="text-align: center; padding: 48px 20px; color: var(--text-muted); font-size: 14px;">
                <p style="margin-bottom: 16px;">No findings recorded yet. Run a scan to detect security vulnerabilities.</p>
                <a href="/api/dev/scan-sample-demo" class="btn btn-black">Run Sample Demo Scan ➔</a>
              </div>`
            : `<div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; text-align: left;">
                  <thead>
                    <tr style="border-bottom: 1px solid var(--border-color); background: #f8fafc; font-size: 12px; color: #64748b; text-transform: uppercase;">
                      <th style="padding: 10px 16px;">Severity</th>
                      <th style="padding: 10px 16px;">Tier</th>
                      <th style="padding: 10px 16px;">Rule & Rationale</th>
                      <th style="padding: 10px 16px;">Location</th>
                      <th style="padding: 10px 16px; text-align: right;">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${findingsRowsHtml.join("")}
                  </tbody>
                </table>
              </div>`
        }
      </div>
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Security Findings",
      userLogin,
      csrfToken,
      userRepos,
      scansCount: allScans.length,
      activeNav: "findings",
      content,
    }),
  };
}

/**
 * GET /fixes - Remediation sandbox dashboard
 */
export async function renderFixesPage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const { userLogin, csrfToken, userRepos } = await getUserContext(req, env);
  const allFindings = await db.getAllFindings();

  const supportedRules = new Set(["idor.owner-column.v1", "rules.stripe.v1"]);
  const fixableFindings = allFindings.filter((f) => supportedRules.has(f.ruleId));

  const fixesRowsHtml = fixableFindings.map((f) => {
    const lineNum = f.lineRange?.startLine || 1;
    return `
      <div class="ui-card" style="margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; padding: 16px 20px;">
        <div>
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
            <strong style="color: #0f172a; font-size: 14px;">${escapeHtml(f.ruleId)}</strong>
            <span style="background: #e0e7ff; color: #4338ca; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px;">AST PATCH READY</span>
          </div>
          <div style="font-size: 12px; font-family: monospace; color: #475569;">
            ${escapeHtml(f.file)}:${lineNum}
          </div>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
            Deterministic AST patch available with containerized sandbox verification.
          </div>
        </div>
        <div>
          <a href="/findings/${escapeHtml(f.db_id || f.id)}/fix" class="btn btn-black" style="padding: 8px 16px; font-size: 12px; font-weight: 600;">
            Review &amp; Apply Fix in Sandbox ➔
          </a>
        </div>
      </div>
    `;
  });

  const content = `
    <div style="max-width: 900px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
      <div>
        <h1 style="font-size: 28px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; margin-bottom: 4px;">Interactive Remediation Sandbox</h1>
        <p style="color: #64748b; font-size: 14px;">Safely review, test, and apply AST-generated patches in hermetic sandbox environments.</p>
      </div>

      <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 18px; font-size: 13px; color: #475569; display: flex; gap: 16px; align-items: center;">
        <span style="font-size: 24px;">🛡️</span>
        <div>
          <strong style="color: #0f172a;">Hermetic Verification Guarantees:</strong>
          Patches are verified in zero-network containers without access to production credentials or live environments.
        </div>
      </div>

      <div>
        <h2 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 12px;">Available Fixes (${fixableFindings.length})</h2>
        ${
          fixableFindings.length === 0
            ? `<div class="ui-card" style="text-align: center; padding: 40px 20px; color: var(--text-muted); font-size: 14px;">
                <p style="margin-bottom: 12px;">No automated AST patches pending. Run the sample demo scan to inspect fixable IDOR vulnerabilities.</p>
                <a href="/api/dev/scan-sample-demo" class="btn btn-black">Run Demo Scan ➔</a>
              </div>`
            : fixesRowsHtml.join("")
        }
      </div>
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Interactive Remediation Sandbox",
      userLogin,
      csrfToken,
      userRepos,
      activeNav: "fixes",
      content,
    }),
  };
}

/**
 * GET /pull-requests - Pull Request automation status
 */
export async function renderPullRequestsPage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const { userLogin, csrfToken, userRepos } = await getUserContext(req, env);

  const content = `
    <div style="max-width: 800px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
      <div>
        <h1 style="font-size: 28px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; margin-bottom: 4px;">Pull Request Automation</h1>
        <p style="color: #64748b; font-size: 14px;">Automated remediation branch creation and Pull Request publishing via GitHub App.</p>
      </div>

      <div class="ui-card">
        <h2 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
          <span>🤖</span> GitHub App Integration Status
        </h2>
        <div style="display: flex; flex-direction: column; gap: 10px; font-size: 13px; color: #334155;">
          <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border-color);">
            <span>GitHub App Slug</span>
            <strong style="font-family: monospace;">${escapeHtml(env.GITHUB_APP_SLUG || "nantis-security")}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border-color);">
            <span>OAuth Client ID</span>
            <strong style="font-family: monospace;">${escapeHtml(env.GITHUB_CLIENT_ID)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 8px 0;">
            <span>PR Publishing Mode</span>
            <span style="background: #dcfce7; color: #15803d; font-weight: 700; padding: 2px 8px; border-radius: 999px; font-size: 11px;">DIRECT / AUTOMATED</span>
          </div>
        </div>
      </div>

      <div class="ui-card" style="text-align: center; padding: 36px 20px;">
        <h3 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 8px;">Automated PR Flow</h3>
        <p style="color: #64748b; font-size: 13px; max-width: 500px; margin: 0 auto 20px auto;">
          When you approve an AST fix in the Sandbox, NANTIS commits the verified patch to a dedicated security branch and opens a Pull Request on your repository.
        </p>
        <a href="/fixes" class="btn btn-black">Review Fixes &amp; Open PR ➔</a>
      </div>
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Pull Requests",
      userLogin,
      csrfToken,
      userRepos,
      activeNav: "pull-requests",
      content,
    }),
  };
}

/**
 * GET /settings - Environment & integrations status dashboard
 */
export async function renderSettingsPage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const { userLogin, csrfToken, userRepos } = await getUserContext(req, env);

  const hasGroq = Boolean(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY.trim().length > 0);
  const hasDb = Boolean(process.env.DATABASE_URL);
  const hasStripe = Boolean(process.env.STRIPE_SECRET_KEY);

  const content = `
    <div style="max-width: 800px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
      <div>
        <h1 style="font-size: 28px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; margin-bottom: 4px;">Platform Settings &amp; Integrations</h1>
        <p style="color: #64748b; font-size: 14px;">Verify connection status for GitHub, Groq AI, PostgreSQL, and billing services.</p>
      </div>

      <div class="ui-card">
        <h2 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 16px;">Integration Status Matrix</h2>
        <div style="display: flex; flex-direction: column; gap: 14px;">
          <!-- GitHub OAuth -->
          <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #f8fafc; border-radius: 8px;">
            <div>
              <strong style="color: #0f172a; font-size: 13px;">GitHub OAuth &amp; GitHub App</strong>
              <div style="font-size: 12px; color: #64748b;">Client ID: <code>${escapeHtml(env.GITHUB_CLIENT_ID)}</code></div>
            </div>
            <span style="background: #dcfce7; color: #15803d; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px;">CONNECTED</span>
          </div>

          <!-- Groq AI -->
          <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #f8fafc; border-radius: 8px;">
            <div>
              <strong style="color: #0f172a; font-size: 13px;">Groq LLM Investigator</strong>
              <div style="font-size: 12px; color: #64748b;">Model: <code>llama-3.3-70b-versatile</code></div>
            </div>
            <span style="background: ${hasGroq ? "#dcfce7" : "#fee2e2"}; color: ${hasGroq ? "#15803d" : "#b91c1c"}; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px;">
              ${hasGroq ? "ACTIVE (GROQ_API_KEY)" : "MISSING KEY"}
            </span>
          </div>

          <!-- Database -->
          <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #f8fafc; border-radius: 8px;">
            <div>
              <strong style="color: #0f172a; font-size: 13px;">Persistence Engine (PostgreSQL / In-Memory)</strong>
              <div style="font-size: 12px; color: #64748b;">
                ${hasDb ? `URL: <code>${escapeHtml(env.DATABASE_URL.replace(/:[^:@]+@/, ":****@"))}</code>` : "In-Memory Engine Active"}
              </div>
            </div>
            <span style="background: #dcfce7; color: #15803d; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px;">
              ${process.env.USE_POSTGRES === "true" ? "POSTGRESQL CONNECTED" : "IN-MEMORY DEV READY"}
            </span>
          </div>

          <!-- Stripe -->
          <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #f8fafc; border-radius: 8px;">
            <div>
              <strong style="color: #0f172a; font-size: 13px;">Stripe Payments &amp; Webhooks</strong>
              <div style="font-size: 12px; color: #64748b;">Pro Plan Subscription Handler</div>
            </div>
            <span style="background: ${hasStripe ? "#dcfce7" : "#f1f5f9"}; color: ${hasStripe ? "#15803d" : "#475569"}; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px;">
              ${hasStripe ? "CONFIGURED" : "NOT SET"}
            </span>
          </div>
        </div>
      </div>

      <!-- Quick Session Actions -->
      <div class="ui-card">
        <h2 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 12px;">Development Session Controls</h2>
        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
          <a href="/auth/dev-login" class="btn btn-black" style="font-size: 13px;">⚡ Quick Dev Login</a>
          <a href="/auth/disconnect" class="btn btn-outline" style="font-size: 13px; color: #dc2626; border-color: #fca5a5;">Disconnect GitHub</a>
          <a href="/auth/logout" class="btn btn-outline" style="font-size: 13px;">Log Out</a>
        </div>
      </div>
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Settings & Integrations",
      userLogin,
      csrfToken,
      userRepos,
      activeNav: "settings",
      content,
    }),
  };
}
