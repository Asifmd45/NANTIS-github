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

export async function renderHomePage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  let userLogin: string | undefined = undefined;
  let userId: string = "dev-user-id";

  if (token) {
    const session = decodeSession(token, env.SESSION_SECRET);
    if (session) {
      userLogin = session.githubLogin;
      userId = session.userId;
    }
  }

  const csrfToken = getOrCreateCsrfToken(userId);

  // Get recent scans from db
  const repos = await db.getUserAccessibleRepositories(userId);
  const recentScansList: { scanId: string; repoName: string; status: string; date: string }[] = [];

  for (const repo of repos) {
    const scans = await db.getScansForRepository(repo.id);
    for (const scan of scans) {
      recentScansList.push({
        scanId: scan.id,
        repoName: repo.full_name,
        status: scan.status,
        date: scan.started_at || "Recent",
      });
    }
  }

  const recentScansHtml =
    recentScansList.length === 0
      ? `<div style="text-align: center; padding: 32px 16px; background: #f8fafc; border: 1px dashed var(--border-color); border-radius: 8px; color: var(--text-muted); font-size: 13px;">
          No recent scans yet. Paste a public GitHub repository URL above to launch your first static security scan.
        </div>`
      : `<div style="display: flex; flex-direction: column; gap: 10px;">
          ${recentScansList
            .slice(-5)
            .reverse()
            .map(
              (s) => `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; background: #ffffff; border-radius: 8px; border: 1px solid var(--border-color); box-shadow: 0 1px 2px rgba(0,0,0,0.02);">
              <div>
                <strong style="color: #0f172a; font-size: 14px; font-weight: 700;">${escapeHtml(s.repoName)}</strong>
                <span style="font-size: 12px; color: var(--text-muted); margin-left: 10px; font-family: monospace;">ID: ${escapeHtml(s.scanId.slice(0, 8))}</span>
              </div>
              <div>
                <a href="/scans/${escapeHtml(s.scanId)}" class="btn btn-white-outline" style="padding: 6px 14px; font-size: 12px;">View Findings →</a>
              </div>
            </div>
          `
            )
            .join("")}
        </div>`;

  const content = `
    <div style="max-width: 840px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
      <div style="text-align: center; margin-bottom: 8px;">
        <h1 style="font-size: 32px; font-weight: 800; color: #0f172a; letter-spacing: -0.03em; margin-bottom: 8px;">
          AST Vulnerability & Static Security Review
        </h1>
        <p style="color: #64748b; font-size: 15px; max-width: 650px; margin: 0 auto; line-height: 1.5;">
          High-fidelity AST security analysis, deterministic fix engine, and interactive finding classification.
        </p>
        <p style="color: #475569; font-size: 13px; font-weight: 500; margin-top: 12px; background: #f1f5f9; padding: 8px 16px; border-radius: 999px; display: inline-block;">
          NANTIS gets read-only access to only the repositories you choose, and you can change this anytime on GitHub.
        </p>
      </div>

      <!-- Quick Action / Authentication Card -->
      <div class="ui-card" style="background: #ffffff;">
        ${
          userLogin
            ? `
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;">
                <div>
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #22c55e;"></span>
                    <h3 style="font-size: 16px; font-weight: 700; color: #0f172a; margin: 0;">Signed in as <strong>@${escapeHtml(userLogin)}</strong></h3>
                  </div>
                  <p style="color: #64748b; font-size: 13px; margin: 4px 0 0 0;">Choose repositories to scan or launch a sample demo scan directly.</p>
                </div>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                  <a href="/api/dev/scan-sample-demo" class="btn btn-black" style="padding: 9px 18px; font-size: 13px; font-weight: 600;">
                    ⚡ Run Demo Scan (1-click)
                  </a>
                  <a href="/repos" class="btn btn-outline" style="padding: 9px 16px; font-size: 13px;">
                    📁 Repositories
                  </a>
                  <a href="/findings" class="btn btn-outline" style="padding: 9px 16px; font-size: 13px;">
                    Findings
                  </a>
                </div>
              </div>
            `
            : `
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                <div>
                  <h3 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">Get Started with NANTIS</h3>
                  <p style="color: #64748b; font-size: 13px; margin: 0;">Sign in with GitHub or use local 1-click dev mode to test scans immediately.</p>
                </div>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                  <a href="/auth/dev-login" class="btn btn-black" style="padding: 9px 18px; font-size: 13px; font-weight: 700;">
                    ⚡ Quick Dev Login (1-click)
                  </a>
                  <a href="/api/dev/scan-sample-demo" class="btn btn-white-outline" style="padding: 9px 16px; font-size: 13px; font-weight: 600;">
                    🚀 Run Demo Scan
                  </a>
                  <a href="/auth/login" class="btn btn-outline" style="padding: 9px 16px; font-size: 13px;">
                    Connect GitHub ↗
                  </a>
                </div>
              </div>
            `
        }
      </div>

      <div class="ui-card">
        <h2 style="font-size: 18px; font-weight: 700; color: #0f172a; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
          <span>🔍</span> Scan Public GitHub Repository
        </h2>
        
        <form action="/api/dev/scan-public-repo" method="POST" style="display: flex; flex-direction: column; gap: 16px;">
          <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
          
          <div>
            <label style="display: block; font-size: 13px; font-weight: 600; color: #475569; margin-bottom: 6px;">
              Repository URL
            </label>
            <input 
              type="url" 
              name="repoUrl" 
              placeholder="https://github.com/owner/repo" 
              required 
              style="width: 100%; font-family: monospace; font-size: 14px; padding: 12px 16px; border: 1px solid var(--border-color); border-radius: 8px; background: #ffffff; color: #0f172a; outline: none;"
            />
          </div>

          <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
            <div style="font-size: 13px; color: #64748b; font-weight: 500;">
              Public GitHub repositories only.
            </div>
            <button type="submit" class="btn btn-black" style="padding: 10px 24px; font-size: 13px; font-weight: 600;">
              Scan Repository
            </button>
          </div>
        </form>
      </div>

      <div class="ui-card">
        <h3 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 16px;">
          ⚡ Dev Mode: Local Folder Scanning
        </h3>
        
        <form action="/api/dev/scan" method="POST" style="display: flex; flex-direction: column; gap: 10px; margin-bottom: 24px;">
          <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
          <label style="font-size: 13px; font-weight: 600; color: #475569;">
            Local Folder Path (Development Mode)
          </label>
          <div style="display: flex; gap: 12px; align-items: center;">
            <input 
              type="text" 
              name="folder" 
              value="${escapeHtml(process.cwd())}" 
              placeholder="E.g. C:\\path\\to\\project"
              style="flex: 1; font-family: monospace; font-size: 13px; padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 8px; background: #ffffff; color: #0f172a; outline: none;"
            />
            <button type="submit" class="btn btn-white-outline" style="white-space: nowrap;">
              Scan Local Directory
            </button>
          </div>
        </form>

        <hr style="border: 0; border-top: 1px solid var(--border-color); margin: 24px 0;" />

        <h4 style="font-size: 14px; font-weight: 700; color: #0f172a; margin-bottom: 14px;">
          Recent Scans
        </h4>
        ${recentScansHtml}
      </div>
    </div>
  `;

  const html = renderPageLayout({
    title: "Public Repo Scan Console",
    userLogin,
    csrfToken,
    userRepos: repos,
    scansCount: recentScansList.length,
    activeNav: "scans",
    content,
  });

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: html,
  };
}
