import fs from "fs";
import path from "path";
import {
  Finding,
  FixResult,
  PatchSafetyGate,
  applyStructuredEdits,
  generateFixForRule,
  processFixInTempSandbox,
  runScan,
  walkDirectory,
} from "@nantis/core";
import { db } from "../db/client.js";
import { assertRepoAccess, NotFoundError } from "../lib/access-control.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import {
  escapeHtml,
  getDefaultHeaders,
  getOrCreateCsrfToken,
  renderPageLayout,
  validateCsrfToken,
} from "./ui-templates.js";

/**
 * Resolves the workspace folder path for a given repository and scan.
 */
export function findWorkspaceForScan(repoName: string, scanId: string): string {
  const candidates: string[] = [];
  if (scanId) {
    candidates.push(path.resolve(process.cwd(), "temp/scans", scanId));
  }
  if (repoName) {
    candidates.push(path.resolve(process.cwd(), "fixtures", repoName));
    candidates.push(path.resolve(process.cwd(), repoName));
  }
  // Only use demo fixture if repoName actually matches it
  if (repoName === "e2e-nextjs-supabase-stripe" || repoName.includes("e2e-nextjs-supabase-stripe")) {
    candidates.push(path.resolve(process.cwd(), "fixtures/e2e-nextjs-supabase-stripe"));
  }
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isDirectory()) {
      return c;
    }
  }
  return "";
}

/**
 * Builds filesMap from workspace directory or from finding snippet fallback.
 */
export function buildWorkspaceFilesMap(workspaceDir: string, finding: Finding): Map<string, string> {
  const filesMap = new Map<string, string>();
  if (workspaceDir && fs.existsSync(workspaceDir)) {
    try {
      const files = walkDirectory(workspaceDir);
      for (const f of files) {
        filesMap.set(f.relativePath.replace(/\\/g, "/"), f.content);
      }
    } catch {
      // Ignore walk errors
    }
  }

  // Ensure target finding file is present if snippet is available
  const normFindingFile = finding.file.replace(/\\/g, "/");
  if (!filesMap.has(normFindingFile)) {
    const rawF = finding as unknown as Record<string, unknown>;
    const snippet = (rawF.codeSnippet as string) || (rawF.snippet as string) || "";
    if (typeof snippet === "string" && snippet.length > 0) {
      filesMap.set(normFindingFile, snippet);
    }
  }

  return filesMap;
}

/**
 * Highlights a unified diff string with HTML spans.
 */
export function formatDiffHtml(diffText: string): string {
  const lines = diffText.split("\n");
  return lines
    .map((line) => {
      const escaped = escapeHtml(line);
      if (line.startsWith("+++") || line.startsWith("---")) {
        return `<div style="color: #94a3b8; font-weight: 700; padding: 1px 8px;">${escaped}</div>`;
      }
      if (line.startsWith("@@")) {
        return `<div style="color: #38bdf8; background: #032b43; padding: 2px 8px; margin: 4px 0;">${escaped}</div>`;
      }
      if (line.startsWith("+")) {
        return `<div style="color: #4ade80; background: rgba(34, 197, 94, 0.12); padding: 1px 8px;">${escaped}</div>`;
      }
      if (line.startsWith("-")) {
        return `<div style="color: #f87171; background: rgba(239, 68, 68, 0.12); padding: 1px 8px;">${escaped}</div>`;
      }
      return `<div style="color: #cbd5e1; padding: 1px 8px;">${escaped}</div>`;
    })
    .join("");
}

export async function renderFixReviewPage(
  req: RequestContext,
  findingId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Unauthorized - NANTIS",
        content: `
          <div class="ui-card" style="max-width: 540px; margin: 40px auto; text-align: center; padding: 40px 24px;">
            <div style="font-size: 36px; margin-bottom: 12px;">🔒</div>
            <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">Authentication Required</h2>
            <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">You must be signed in to review and apply AST remediation patches.</p>
            <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
              <a href="/auth/login" class="btn btn-black">Connect with GitHub</a>
              <a href="/auth/dev-login" class="btn btn-white-outline">⚡ Quick Dev Login</a>
            </div>
          </div>
        `,
      }),
    };
  }

  const session = decodeSession(token, env.SESSION_SECRET);
  if (!session || !session.userId) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Unauthorized - NANTIS",
        content: `
          <div class="ui-card" style="max-width: 540px; margin: 40px auto; text-align: center; padding: 40px 24px;">
            <div style="font-size: 36px; margin-bottom: 12px;">⚠️</div>
            <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">Session Expired</h2>
            <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">Your session is invalid or has expired. Please sign in again.</p>
            <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
              <a href="/auth/login" class="btn btn-black">Connect with GitHub</a>
              <a href="/auth/dev-login" class="btn btn-white-outline">⚡ Quick Dev Login</a>
            </div>
          </div>
        `,
      }),
    };
  }

  const finding = await db.getFindingById(findingId);
  if (!finding) {
    return {
      status: 404,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "404 Finding Not Found",
        userLogin: session.githubLogin,
        content: `<h1>404 Finding Not Found</h1><p>The requested finding ID does not exist.</p>`,
      }),
    };
  }

  const fid = finding.db_id || finding.id || findingId;
  const scan = finding.scan_id ? await db.getScanById(finding.scan_id) : null;
  const repo = scan?.repository_id ? await db.getRepositoryById(scan.repository_id) : null;

  try {
    await assertRepoAccess(session.userId, scan?.repository_id || "");
  } catch (err) {
    if (err instanceof NotFoundError) {
      return {
        status: 404,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "404 Not Found",
          userLogin: session.githubLogin,
          content: `<h1>404 Not Found</h1><p>Finding or scan not found.</p>`,
        }),
      };
    }
    return {
      status: 404,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "404 Not Found",
        userLogin: session.githubLogin,
        content: `<h1>404 Not Found</h1><p>Access denied.</p>`,
      }),
    };
  }

  const csrfToken = getOrCreateCsrfToken(session.userId);
  const repoName = repo?.name || "e2e-nextjs-supabase-stripe";
  const workspaceDir = findWorkspaceForScan(repoName, finding.scan_id);
  const filesMap = buildWorkspaceFilesMap(workspaceDir, finding as unknown as Finding);

  let initialFindings = finding.scan_id ? await db.getFindingsForScan(finding.scan_id) : [];
  if (initialFindings.length <= 1 && workspaceDir && fs.existsSync(workspaceDir)) {
    try {
      const baseScan = await runScan(workspaceDir, { json: true });
      initialFindings = baseScan.findings as unknown as typeof initialFindings;
    } catch {
      // Ignore scan errors
    }
  }

  // Generate fix candidate using existing core patch engine
  let fixResult: FixResult;
  if (workspaceDir && fs.existsSync(workspaceDir)) {
    const proc = await processFixInTempSandbox(
      workspaceDir,
      filesMap,
      finding as unknown as Finding,
      undefined,
      { initialFindings: initialFindings as unknown as Finding[] }
    );
    fixResult = proc.fixResult;
  } else {
    fixResult = generateFixForRule(filesMap, finding as unknown as Finding);
  }

  // Evaluate Patch Safety Gate if fix is automated
  let safetyGateResult = { valid: true, reason: "" };
  if (fixResult.kind === "automated") {
    const gateRes = PatchSafetyGate.validatePatch(
      fixResult.edits,
      fixResult.diff,
      [fixResult.targetFile],
      workspaceDir || process.cwd()
    );
    safetyGateResult = { valid: gateRes.valid, reason: gateRes.reason || "" };
    if (!gateRes.valid && fixResult.verificationReport) {
      fixResult.verificationReport.passed = false;
      fixResult.verificationReport.dropReason = gateRes.reason;
    }
  }

  // --- POST HANDLER: User submits fix approval or rejection ---
  if (req.method === "POST") {
    if (!validateCsrfToken(req, session.userId)) {
      return {
        status: 403,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "403 Invalid CSRF Token",
          userLogin: session.githubLogin,
          content: `<h1>403 Forbidden</h1><p>Invalid or missing CSRF security token.</p>`,
        }),
      };
    }

    let action = "approve";
    if (typeof req.body === "object" && req.body !== null && "action" in req.body) {
      action = String((req.body as Record<string, unknown>).action);
    }

    if (action === "reject") {
      await db.setFindingLabel({
        user_id: session.userId,
        finding_id: fid,
        repo_full_name: repo?.full_name || "repository",
        rule_id: finding.ruleId,
        file: finding.file,
        line: finding.lineRange?.startLine || 1,
        label: "false_positive",
      });

      return {
        status: 200,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "Fix Rejected - NANTIS",
          userLogin: session.githubLogin,
          activeNav: "fixes",
          csrfToken,
          content: `
            <div class="ui-card" style="max-width: 700px; margin: 40px auto; text-align: center; padding: 48px 24px;">
              <div style="font-size: 40px; margin-bottom: 16px;">⊘</div>
              <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">Finding Tagged as False Positive</h2>
              <p style="color: #64748b; margin-bottom: 24px; font-size: 14px; line-height: 1.6;">
                You opted not to apply the proposed patch. The finding for <code>${escapeHtml(finding.ruleId)}</code> has been recorded as false positive.
              </p>
              <a href="/scans/${escapeHtml(finding.scan_id)}" class="btn btn-black">Return to Scan Findings</a>
            </div>
          `,
        }),
      };
    }

    // Action: approve
    if (fixResult.kind !== "automated") {
      return {
        status: 400,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "400 Automated Fix Unavailable",
          userLogin: session.githubLogin,
          activeNav: "fixes",
          content: `
            <div class="ui-card" style="max-width: 700px; margin: 40px auto; border-left: 4px solid #f59e0b;">
              <h2 style="font-size: 20px; font-weight: 800; color: #b45309; margin-bottom: 8px;">Automated Fix Unavailable</h2>
              <p style="color: #475569; font-size: 14px; margin-bottom: 20px;">
                Rule <code>${escapeHtml(finding.ruleId)}</code> does not support automated AST patching. Please remediate manually.
              </p>
              <a href="/findings/${escapeHtml(fid)}/fix" class="btn btn-white-outline">Back to Fix Review</a>
            </div>
          `,
        }),
      };
    }

    if (!safetyGateResult.valid) {
      return {
        status: 400,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "400 Patch Safety Rejected",
          userLogin: session.githubLogin,
          activeNav: "fixes",
          content: `
            <div class="ui-card" style="max-width: 700px; margin: 40px auto; border-left: 4px solid #dc2626;">
              <h2 style="font-size: 20px; font-weight: 800; color: #dc2626; margin-bottom: 8px;">Patch Safety Gate Violation</h2>
              <p style="color: #475569; font-size: 14px; margin-bottom: 20px;">
                ${escapeHtml(safetyGateResult.reason)}
              </p>
              <a href="/findings/${escapeHtml(fid)}/fix" class="btn btn-white-outline">Back to Fix Review</a>
            </div>
          `,
        }),
      };
    }

    // Apply patch to workspace if target file exists
    let appliedToDisk = false;
    if (workspaceDir && fs.existsSync(workspaceDir)) {
      const targetFilePath = path.join(workspaceDir, fixResult.targetFile);
      if (fs.existsSync(targetFilePath)) {
        const beforeContent = fs.readFileSync(targetFilePath, "utf-8");
        const editRes = applyStructuredEdits(beforeContent, fixResult.edits);
        if (editRes.success && editRes.updatedContent) {
          fs.writeFileSync(targetFilePath, editRes.updatedContent, "utf-8");
          appliedToDisk = true;
        }
      }
    }

    // Write audit log
    await db.createAuditLog({
      userId: session.userId,
      repoId: repo?.id || "repo-id",
      action: "patch_approved_and_applied",
      tokenId: `remediation_${fid.slice(0, 8)}`,
      timestamp: new Date().toISOString(),
    });

    // Label finding as confirmed/real issue
    await db.setFindingLabel({
      user_id: session.userId,
      finding_id: fid,
      repo_full_name: repo?.full_name || "repository",
      rule_id: finding.ruleId,
      file: finding.file,
      line: finding.lineRange?.startLine || 1,
      label: "real_issue",
    });

    const successContent = `
      <div style="max-width: 840px; margin: 40px auto;">
        <div class="ui-card" style="border-left: 4px solid #16a34a; padding: 32px 28px;">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
            <span style="font-size: 28px;">✅</span>
            <div>
              <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin: 0;">
                Fix Approved & Applied to Workspace
              </h2>
              <div style="font-size: 13px; color: #64748b; margin-top: 2px;">
                Target file: <code>${escapeHtml(fixResult.targetFile)}</code>
              </div>
            </div>
          </div>

          <p style="color: #475569; font-size: 14px; line-height: 1.6; margin-bottom: 20px;">
            The AST patch for rule <strong>${escapeHtml(finding.ruleId)}</strong> was verified in an isolated sandbox, passed the Patch Safety Gate, and ${appliedToDisk ? "was written to the local workspace file" : "was verified against in-memory snapshots"}.
          </p>

          <div style="margin-bottom: 24px;">
            <div style="font-size: 12px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 8px;">
              Applied Unified Diff
            </div>
            <pre style="background: #0f172a; border-radius: 8px; padding: 16px; overflow-x: auto; font-family: monospace; font-size: 12px; line-height: 1.6; margin: 0;">${formatDiffHtml(fixResult.diff)}</pre>
          </div>

          <div style="display: flex; gap: 12px; align-items: center;">
            <a href="/scans/${escapeHtml(finding.scan_id)}" class="btn btn-black" style="font-size: 13px;">
              Return to Scan Findings
            </a>
            <a href="/findings/${escapeHtml(fid)}/fix" class="btn btn-white-outline" style="font-size: 13px;">
              Review Again
            </a>
          </div>
        </div>
      </div>
    `;

    return {
      status: 200,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "Fix Applied Successfully - NANTIS",
        userLogin: session.githubLogin,
        activeNav: "fixes",
        csrfToken,
        content: successContent,
      }),
    };
  }

  // --- GET: Render Review & Sandbox Interface ---
  const rawFinding = finding as unknown as Record<string, unknown>;
  const codeSnippet =
    (rawFinding.codeSnippet as string) ||
    (rawFinding.snippet as string) ||
    filesMap.get(finding.file) ||
    "// Code snippet not available";

  const snippetLines = codeSnippet.split("\n");
  const startLine = finding.lineRange?.startLine || 1;
  const originalCodeHtml = snippetLines
    .slice(0, 25)
    .map((line, i) => {
      const lineNum = startLine + i;
      return `<div style="display: flex; padding: 2px 8px; font-family: monospace; font-size: 12px; line-height: 1.6;">
        <span style="width: 36px; color: #94a3b8; user-select: none;">${lineNum}</span>
        <span style="flex: 1; color: #334155;">${escapeHtml(line)}</span>
      </div>`;
    })
    .join("");

  let remediationContent = "";

  if (fixResult.kind === "automated") {
    const isVerified = fixResult.verificationReport.passed;
    const diffFormatted = formatDiffHtml(fixResult.diff);

    remediationContent = `
      <!-- Proposed Diff Card -->
      <div class="ui-card" style="margin-bottom: 24px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <div>
            <h3 style="font-size: 16px; font-weight: 800; color: #0f172a; margin: 0;">
              Deterministic AST Patch Diff
            </h3>
            <p style="font-size: 12px; color: #64748b; margin: 4px 0 0 0;">
              Preview proposed code changes for <code>${escapeHtml(fixResult.targetFile)}</code>
            </p>
          </div>
          <span style="background: ${isVerified ? "#dcfce7" : "#fee2e2"}; color: ${isVerified ? "#166534" : "#991b1b"}; font-weight: 700; font-size: 12px; padding: 4px 10px; border-radius: 999px;">
            ${isVerified ? "✓ Verification PASSED" : "✗ Verification FAILED"}
          </span>
        </div>

        <pre style="background: #0f172a; border-radius: 8px; padding: 16px; overflow-x: auto; font-family: monospace; font-size: 12px; line-height: 1.6; margin: 0 0 16px 0;">${diffFormatted}</pre>

        <!-- Verification Ladder Details -->
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px;">
          <div style="font-size: 12px; font-weight: 700; color: #475569; text-transform: uppercase; margin-bottom: 12px;">
            Sandbox Verification Ladder Results
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 12px;">
            <div>
              <div style="color: #64748b;">Checks Run</div>
              <div style="font-weight: 700; color: #0f172a; font-family: monospace;">${escapeHtml(fixResult.verificationReport.checksRun.join(", "))}</div>
            </div>
            <div>
              <div style="color: #64748b;">Proof Status</div>
              <div style="font-weight: 700; color: #0f172a;">${escapeHtml(fixResult.proofLabel)}</div>
            </div>
            <div>
              <div style="color: #64748b;">Risk Level</div>
              <div style="font-weight: 700; color: #0f172a; text-transform: uppercase;">${escapeHtml(fixResult.riskLevel)}</div>
            </div>
            <div>
              <div style="color: #64748b;">Blast Radius</div>
              <div style="font-weight: 700; color: #0f172a;">${fixResult.blastRadius.affectedFiles.length} file(s), ${fixResult.blastRadius.callersAffected.length} caller(s)</div>
            </div>
          </div>
          <div style="margin-top: 12px; font-size: 12px; color: ${isVerified ? "#15803d" : "#b91c1c"}; font-weight: 600;">
            ${escapeHtml(fixResult.verificationReport.summaryText)}
          </div>
          ${!isVerified && fixResult.verificationReport.dropReason ? `<div style="margin-top: 6px; font-size: 11px; color: #dc2626;">Reason: ${escapeHtml(fixResult.verificationReport.dropReason)}</div>` : ""}
        </div>
      </div>

      <!-- User Review & Approval Form -->
      <div class="ui-card" style="border: 2px solid #0f172a; background: #ffffff;">
        <h3 style="font-size: 16px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0;">
          User Review & Approval Required
        </h3>
        <p style="font-size: 13px; color: #64748b; line-height: 1.5; margin: 0 0 20px 0;">
          Review the unified diff and sandbox test results above. Applying this fix will update the workspace file directly.
        </p>

        <form method="POST" action="/findings/${escapeHtml(fid)}/fix" style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
          <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
          <input type="hidden" name="action" value="approve" />
          <button type="submit" class="btn btn-black" style="padding: 10px 24px; font-size: 13px; font-weight: 700;" ${!isVerified ? "disabled title='Verification failed'" : ""}>
            ✓ Approve & Apply Fix
          </button>
          <button type="submit" name="action" value="reject" class="btn btn-white-outline" style="padding: 10px 20px; font-size: 13px; font-weight: 600;">
            ⊘ Reject Fix / Mark False Positive
          </button>
          <a href="/scans/${escapeHtml(finding.scan_id)}" class="btn btn-white-outline" style="padding: 10px 20px; font-size: 13px;">
            Cancel
          </a>
        </form>
      </div>
    `;
  } else {
    // Unsupported rule: display informative banner and actionable guidance
    remediationContent = `
      <div class="ui-card" style="border-left: 4px solid #f59e0b; margin-bottom: 24px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
          <span style="font-size: 24px;">⚠️</span>
          <div>
            <h3 style="font-size: 16px; font-weight: 800; color: #92400e; margin: 0;">
              Automated AST Remediation Unavailable
            </h3>
            <div style="font-size: 12px; color: #b45309; margin-top: 2px;">
              No deterministic AST patch engine exists for rule <code>${escapeHtml(finding.ruleId)}</code>.
            </div>
          </div>
        </div>

        <div style="background: #fffbeb; border: 1px solid #fef3c7; border-radius: 8px; padding: 14px; margin-bottom: 16px; font-size: 13px; color: #78350f; line-height: 1.6;">
          <strong>Engine Explanation:</strong><br />
          ${escapeHtml(fixResult.reason)}
        </div>

        <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-bottom: 8px;">
          Actionable Manual Remediation Guidance
        </div>
        <p style="font-size: 13px; color: #475569; line-height: 1.6; margin: 0 0 16px 0;">
          ${escapeHtml(fixResult.suggestion)}
        </p>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; font-size: 12px; color: #64748b;">
          <strong>Recommended Next Steps:</strong>
          <ol style="margin: 8px 0 0 0; padding-left: 20px; line-height: 1.7;">
            <li>Inspect the code around line ${finding.lineRange?.startLine || 1} in <code>${escapeHtml(finding.file)}</code>.</li>
            <li>Consult the rule specification in the <a href="/rules" style="color: #2563eb; text-decoration: none; font-weight: 600;">Rules Catalog</a>.</li>
            <li>After modifying the file in your repository, run a new scan to verify resolution.</li>
          </ol>
        </div>

        <div style="margin-top: 20px; display: flex; gap: 12px;">
          <form method="POST" action="/findings/${escapeHtml(fid)}/fix" style="display: inline;">
            <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
            <input type="hidden" name="action" value="reject" />
            <button type="submit" class="btn btn-white-outline" style="font-size: 12px; font-weight: 600;">
              Mark as False Positive
            </button>
          </form>
          <a href="/scans/${escapeHtml(finding.scan_id)}" class="btn btn-black" style="font-size: 12px;">
            Return to Scan Findings
          </a>
        </div>
      </div>
    `;
  }

  const content = `
    <div style="max-width: 900px; margin: 0 auto;">
      <!-- Breadcrumb and Page Header -->
      <div style="margin-bottom: 24px;">
        <a href="/scans/${escapeHtml(finding.scan_id)}" style="color: #64748b; text-decoration: none; font-size: 13px; font-weight: 600;">
          &larr; Back to Scan Findings
        </a>
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-top: 10px; gap: 16px;">
          <div>
            <h1 style="font-size: 24px; font-weight: 800; color: #0f172a; margin: 0 0 6px 0;">
              Remediation Sandbox: ${escapeHtml(finding.title)}
            </h1>
            <div style="display: flex; gap: 12px; align-items: center; font-size: 12px; color: #64748b;">
              <span>Rule: <code>${escapeHtml(finding.ruleId)}</code></span>
              <span>&bull;</span>
              <span>File: <code>${escapeHtml(finding.file)}:${finding.lineRange?.startLine || 1}</code></span>
            </div>
          </div>
          <div>
            <span style="background: #fee2e2; color: #dc2626; font-weight: 800; font-size: 11px; padding: 4px 10px; border-radius: 4px; text-transform: uppercase;">
              ${escapeHtml(finding.severity)}
            </span>
          </div>
        </div>
      </div>

      <!-- Original Code Context Card -->
      <div class="ui-card" style="margin-bottom: 24px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h3 style="font-size: 15px; font-weight: 800; color: #0f172a; margin: 0;">
            Original Vulnerable Code
          </h3>
          <span style="font-size: 11px; font-family: monospace; color: #64748b; background: #f1f5f9; padding: 2px 8px; border-radius: 4px;">
            Line ${startLine}
          </span>
        </div>
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;">
          ${originalCodeHtml}
        </div>
        <div style="margin-top: 12px; font-size: 12px; color: #475569; line-height: 1.5;">
          ${escapeHtml(finding.explanation)}
        </div>
      </div>

      <!-- Remediation Section (Automated Diff or Manual Guidance) -->
      ${remediationContent}
    </div>
  `;

  const userRepos = await db.getUserAccessibleRepositories(session.userId);

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: `Remediation Sandbox - ${finding.ruleId}`,
      userLogin: session.githubLogin,
      userRepos,
      csrfToken,
      content,
      activeNav: "fixes",
    }),
  };
}
