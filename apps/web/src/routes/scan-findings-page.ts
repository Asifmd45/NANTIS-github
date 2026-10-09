import { db } from "../db/client.js";
import { assertRepoAccess, NotFoundError } from "../lib/access-control.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import { renderScanFindingsContent, ScanFindingsRenderData } from "./scan-findings-renderer.js";
import {
  escapeHtml,
  getDefaultHeaders,
  getOrCreateCsrfToken,
  renderPageLayout,
} from "./ui-templates.js";

function extractUserIdFromRequest(req: RequestContext, env: WebEnv): string | undefined {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) return undefined;
  const session = decodeSession(token, env.SESSION_SECRET);
  return session?.userId;
}

export async function renderScanFindingsPage(
  req: RequestContext,
  scanId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  const scan = await db.getScanById(scanId);

  if (!scan) {
    return {
      status: 404,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "404 Not Found",
        content: `
          <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
            <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
            <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
            <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
          </div>
        `,
      }),
    };
  }

  let repo;
  let isAnonymous = false;

  if (userId) {
    try {
      const access = await assertRepoAccess(userId, scan.repository_id);
      repo = access.repository;
    } catch (err) {
      if (err instanceof NotFoundError) {
        return {
          status: 404,
          headers: getDefaultHeaders(),
          body: renderPageLayout({
            title: "404 Not Found",
            content: `
              <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
                <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
                <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
                <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
              </div>
            `,
          }),
        };
      }
      throw err;
    }
  } else {
    repo = await db.getRepositoryById(scan.repository_id);
    if (!repo || repo.private) {
      return {
        status: 404,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "404 Not Found",
          content: `
            <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
              <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
              <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
              <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
            </div>
          `,
        }),
      };
    }
    isAnonymous = true;
  }

  const csrfToken = getOrCreateCsrfToken(userId || "anonymous");

  if (scan.status === "failed") {
    const errorMsg = scan.error_message || "The repository could not be cloned or scanned.";
    return {
      status: 200,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: `Scan Failed - ${repo.full_name}`,
        userLogin: userId ? "user" : undefined,
        csrfToken,
        content: `
          <div class="ui-card" style="max-width: 680px; margin: 40px auto; border-left: 4px solid #dc2626; padding: 32px 28px;">
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
              <span style="font-size: 32px;">❌</span>
              <div>
                <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin: 0;">Scan Failed</h2>
                <div style="font-size: 13px; color: #64748b; margin-top: 2px;">Repository: <code>${escapeHtml(repo.full_name)}</code></div>
              </div>
            </div>
            <p style="color: #b91c1c; font-weight: 600; font-size: 14px; margin-bottom: 12px;">
              ${escapeHtml(errorMsg)}
            </p>
            <p style="color: #64748b; font-size: 13px; margin-bottom: 24px; line-height: 1.5;">
              Please check that the repository URL is public, contains source files, and the remote server is accessible.
            </p>
            <div style="display: flex; gap: 12px;">
              <a href="/" class="btn btn-black">&larr; Back to Home</a>
              <a href="/repos" class="btn btn-white-outline">Repositories</a>
            </div>
          </div>
        `,
      }),
    };
  }

  if (scan.status === "queued" || scan.status === "cloning" || scan.status === "scanning") {
    return {
      status: 200,
      headers: {
        ...getDefaultHeaders(),
        "Refresh": "2",
      },
      body: renderPageLayout({
        title: `Scanning ${repo.full_name}...`,
        content: `
          <div class="ui-card" style="max-width: 600px; margin: 60px auto; text-align: center; padding: 48px 24px;">
            <div style="font-size: 36px; margin-bottom: 16px;">⏳</div>
            <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">
              Scan in Progress...
            </h2>
            <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">
              Status: <strong style="text-transform: capitalize;">${escapeHtml(scan.status)}</strong> for <code>${escapeHtml(repo.full_name)}</code>. This page will automatically update once analysis finishes.
            </p>
            <div style="font-size: 12px; color: #94a3b8;">Auto-refreshing every 2 seconds...</div>
          </div>
        `,
      }),
    };
  }

  const findings = await db.getFindingsForScan(scanId);
  const totalScansCount = (await db.getScansForRepository(scan.repository_id)).length;
  const prevScan = await db.getPreviousCompletedScan(scan.repository_id, scan.id);

  let prevCrit = 0, prevHigh = 0, prevMed = 0, prevLow = 0;
  if (prevScan) {
    const prevFindings = await db.getFindingsForScan(prevScan.id);
    prevCrit = prevFindings.filter((f) => f.severity === "critical").length;
    prevHigh = prevFindings.filter((f) => f.severity === "high").length;
    prevMed = prevFindings.filter((f) => f.severity === "medium").length;
    prevLow = prevFindings.filter((f) => f.severity === "low").length;
  }

  const userLabels = new Map<string, string>();
  for (const f of findings) {
    const lbl = userId ? await db.getFindingLabel(userId, f.db_id || f.id) : null;
    if (lbl) {
      userLabels.set(f.db_id || f.id, lbl.label);
    }
  }

  const userRepos = userId ? await db.getUserAccessibleRepositories(userId) : [];
  const diagnostics = await db.getScanDiagnostics(scanId);

  const content = renderScanFindingsContent({
    scan,
    repo,
    isAnonymous,
    csrfToken,
    findings: findings as unknown as ScanFindingsRenderData["findings"],
    prevScan,
    prevCounts: { crit: prevCrit, high: prevHigh, med: prevMed, low: prevLow },
    userLabels,
    totalScansCount,
    diagnostics,
  });

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: `Scan Findings - ${repo.full_name}`,
      userLogin: userId ? "test-user" : undefined,
      csrfToken,
      content,
      activeNav: "findings",
      repoName: repo.full_name,
      userRepos,
      scansCount: totalScansCount,
    }),
  };
}
