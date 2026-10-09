import fs from "fs";
import path from "path";
import { runAllDetectors, runScan, walkDirectory } from "@nantis/core";
import { cloneRepositorySandboxed } from "@nantis/worker";
import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession, encodeSession } from "../lib/session.js";
import { parseAndValidateGitHubUrl } from "../lib/url-validator.js";
import { validatePatConnection } from "../lib/github-pat.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import {
  escapeHtml,
  getDefaultHeaders,
  renderPageLayout,
  validateCsrfToken,
} from "./ui-templates.js";

const userLastScanTime = new Map<string, number>();

/**
 * Validates whether a remote IP address is a local loopback address.
 */
export function isLocalhostAddress(ip?: string): boolean {
  if (!ip) return false;
  const norm = ip.trim().toLowerCase();
  return (
    norm === "127.0.0.1" ||
    norm === "::1" ||
    norm === "::ffff:127.0.0.1" ||
    norm === "localhost"
  );
}

/**
 * Dev-only login handler.
 */
export async function handleDevLogin(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const nodeEnv = process.env.NODE_ENV || env.NODE_ENV;
  if (nodeEnv === "production") {
    return {
      status: 403,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "403 Forbidden",
        content: `<h1>403 Forbidden</h1><p>Dev login is disabled in production mode.</p>`,
      }),
    };
  }

  const remoteIp = req.clientIp || "127.0.0.1";
  if (!isLocalhostAddress(remoteIp)) {
    return {
      status: 403,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "403 Forbidden",
        content: `<h1>403 Forbidden</h1><p>Dev login is restricted to local connections (127.0.0.1).</p>`,
      }),
    };
  }

  // Create or retrieve fake test user in in-memory database
  const devUser = await db.upsertUser({
    github_user_id: 99999,
    github_login: "devuser",
    avatar_url: "https://github.com/images/error/octocat_happy.gif",
  });

  // Ensure dev repository exists
  const devRepo = await db.upsertRepository({
    github_repo_id: 88888,
    name: "local-dev-repo",
    full_name: "devuser/local-dev-repo",
    private: false,
    installation_id: "1",
    default_branch: "main",
  });

  await db.grantRepoAccess(devUser.id, devRepo.id);

  // Mint session token
  const sessionToken = encodeSession(
    {
      userId: devUser.id,
      githubUserId: devUser.github_user_id,
      githubLogin: devUser.github_login,
      createdAt: Date.now(),
    },
    env.SESSION_SECRET
  );

  return {
    status: 302,
    headers: {
      Location: "/repos",
      "Set-Cookie": `nantis_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax`,
    },
    body: "",
  };
}

/**
 * Dev-only local folder scan handler.
 */
export async function handleDevScan(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const nodeEnv = process.env.NODE_ENV || env.NODE_ENV;
  if (nodeEnv === "production") {
    return {
      status: 403,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Dev scan disabled in production mode" }),
    };
  }

  const folderParam =
    typeof req.body === "object" && req.body !== null && "folder" in req.body
      ? String((req.body as Record<string, unknown>).folder)
      : undefined;
  const targetFolder = req.query?.["folder"] || folderParam;
  if (!targetFolder || typeof targetFolder !== "string") {
    return {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Missing required 'folder' parameter" }),
    };
  }

  const allowedRoot = path.resolve(process.env.ALLOWED_SCAN_ROOT || process.cwd());
  const resolvedTarget = path.resolve(targetFolder);

  if (!resolvedTarget.startsWith(allowedRoot)) {
    return {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        error: `Path traversal blocked: target folder '${targetFolder}' is outside ALLOWED_SCAN_ROOT (${allowedRoot})`,
      }),
    };
  }

  if (!fs.existsSync(resolvedTarget) || !fs.statSync(resolvedTarget).isDirectory()) {
    return {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: `Directory does not exist: ${resolvedTarget}` }),
    };
  }

  // Ensure dev user and repo exist in DB
  const devUser = await db.upsertUser({
    github_user_id: 99999,
    github_login: "devuser",
    avatar_url: "https://github.com/images/error/octocat_happy.gif",
  });

  const devRepo = await db.upsertRepository({
    github_repo_id: 88888,
    name: path.basename(resolvedTarget),
    full_name: `devuser/${path.basename(resolvedTarget)}`,
    private: false,
    installation_id: "1",
    default_branch: "main",
  });

  await db.grantRepoAccess(devUser.id, devRepo.id);

  // Run static AST scan (never executes code)
  const { findings } = await runScan(resolvedTarget, { json: true });

  const scan = await db.createScan({
    repository_id: devRepo.id,
    commit_sha: "local-dev-commit",
    branch: "main",
    trigger_type: "manual",
    status: "completed",
  });

  if (findings.length > 0) {
    await db.saveScanFindings(scan.id, findings);
  }

  return {
    status: 302,
    headers: { Location: `/scans/${scan.id}` },
    body: "",
  };
}

/**
 * Handle public GitHub repo shallow clone & static AST scan.
 */
export async function handlePublicRepoScan(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  let session = token ? decodeSession(token, env.SESSION_SECRET) : null;
  let userId = session?.userId;
  let sessionCookie: string | undefined;

  if (!userId) {
    const devUser = await db.upsertUser({
      github_user_id: 99999,
      github_login: "devuser",
      avatar_url: "https://github.com/images/error/octocat_happy.gif",
    });
    userId = devUser.id;
    const sessionToken = encodeSession(
      {
        userId: devUser.id,
        githubUserId: devUser.github_user_id,
        githubLogin: devUser.github_login,
        createdAt: Date.now(),
      },
      env.SESSION_SECRET
    );
    sessionCookie = `nantis_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax`;
  }

  // 1. CSRF Token Validation
  if (!validateCsrfToken(req, userId)) {
    return {
      status: 403,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "403 Invalid CSRF Token",
        content: `<h1>403 Forbidden</h1><p>Invalid or missing CSRF security token.</p>`,
      }),
    };
  }

  // 2. Rate Limiting Check
  const now = Date.now();
  const lastScan = userLastScanTime.get(userId) || 0;
  if (now - lastScan < 2000) {
    return {
      status: 429,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "429 Rate Limit Exceeded",
        content: `<h1>429 Rate Limit Exceeded</h1><p>Scan in progress or cooling down. Please wait a few seconds before scanning another repository.</p>`,
      }),
    };
  }
  userLastScanTime.set(userId, now);

  // 3. Extract and Validate GitHub URL
  let repoUrl = "";
  if (typeof req.body === "object" && req.body !== null && "repoUrl" in req.body) {
    repoUrl = String((req.body as Record<string, unknown>).repoUrl);
  } else if (typeof req.body === "string" && req.body.length > 0) {
    const params = new URLSearchParams(req.body);
    repoUrl = params.get("repoUrl") || "";
  }

  const validated = parseAndValidateGitHubUrl(repoUrl);
  if (!validated.valid) {
    return {
      status: 400,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "400 Invalid Repository URL",
        content: `<h1>400 Invalid GitHub Repository Link</h1><p style="color: #ef4444; font-weight: bold;">${escapeHtml(
          validated.error
        )}</p><p><a href="/" class="btn btn-outline">&larr; Back to Home</a></p>`,
      }),
    };
  }

  const { repo: repoName, fullName, cloneUrl } = validated.data;

  // 4. Create database records and grant access to active userId
  const repoRecord = await db.upsertRepository({
    github_repo_id: Math.abs(hashCode(fullName)),
    name: repoName,
    full_name: fullName,
    private: false,
    installation_id: "1",
    default_branch: "HEAD",
  });

  await db.grantRepoAccess(userId, repoRecord.id);

  // 5. Create scan record in database
  const scan = await db.createScan({
    repository_id: repoRecord.id,
    commit_sha: "head-shallow",
    branch: "HEAD",
    trigger_type: "manual",
    status: "cloning",
  });

  // Prepare ephemeral scan directory for this scan
  const targetDir = path.resolve(process.cwd(), "temp/scans", scan.id);
  if (fs.existsSync(targetDir)) {
    try {
      fs.rmSync(targetDir, { recursive: true, force: true });
    } catch {}
  }
  fs.mkdirSync(targetDir, { recursive: true });

  try {
    // 6. Execute sandboxed clone (uses PAT if configured, otherwise anonymous)
    const patToken = env.GITHUB_TOKEN || process.env.GITHUB_TOKEN;
    await cloneRepositorySandboxed({
      repoUrl: cloneUrl,
      targetDir,
      token: patToken,
      maxRepoSizeBytes: 50 * 1024 * 1024,
      timeoutMs: 45000,
    });

    // 7. Update status to scanning and walk files
    await db.updateScanStatus(scan.id, "scanning");
    const scannedFiles = walkDirectory(targetDir);
    const filesMap = new Map<string, string>();
    for (const f of scannedFiles) {
      filesMap.set(f.relativePath, f.content);
    }

    // 8. Run all detectors against actual repository files
    const detectorResult = await runAllDetectors(filesMap, {
      targetFolder: targetDir,
      offlineMode: false,
    });

    if (detectorResult.diagnostics && detectorResult.diagnostics.length > 0) {
      await db.saveScanDiagnostics(scan.id, detectorResult.diagnostics);
    }
    await db.saveScanFindings(scan.id, detectorResult.findings);
    await db.updateScanStatus(scan.id, "completed");

    await db.createAuditLog({
      userId,
      repoId: repoRecord.id,
      action: "public_repo_scan_completed",
      tokenId: `scan_${scan.id.slice(0, 8)}`,
      timestamp: new Date().toISOString(),
    });
  } catch (err: unknown) {
    const rawErr = err instanceof Error ? err.message : String(err);
    console.error(`[Public Repo Scan Error] ${fullName}:`, rawErr);
    await db.updateScanStatus(scan.id, "failed", rawErr);
  }

  const headers: Record<string, string> = { Location: `/scans/${scan.id}` };
  if (sessionCookie) {
    headers["Set-Cookie"] = sessionCookie;
  }

  return {
    status: 302,
    headers,
    body: "",
  };
}

/**
 * Handle saving finding label classification
 */
export async function handleSetFindingLabel(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  let userId = "dev-user-id";
  if (token) {
    const session = decodeSession(token, env.SESSION_SECRET);
    if (session) {
      userId = session.userId;
    }
  }

  if (!validateCsrfToken(req, userId)) {
    return {
      status: 403,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid CSRF token" }),
    };
  }

  const body = (typeof req.body === "object" && req.body !== null ? req.body : {}) as Record<string, unknown>;
  const findingId = (req.path || "").match(/\/api\/findings\/([^/]+)\/label/)?.[1] || String(body.finding_id || "");
  const repoFullName = String(body.repo_full_name || "");
  const ruleId = String(body.rule_id || "");
  const file = String(body.file || "");
  const line = Number(body.line || 1);
  const label = body.label as "real_issue" | "false_positive" | "not_sure";

  if (!findingId || !label || !["real_issue", "false_positive", "not_sure"].includes(label)) {
    return {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid label parameter" }),
    };
  }

  const labelRow = await db.setFindingLabel({
    user_id: userId,
    finding_id: findingId,
    repo_full_name: repoFullName,
    rule_id: ruleId,
    file,
    line,
    label,
  });

  return {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ success: true, label: labelRow }),
  };
}

/**
 * Handle JSON export of user finding labels
 */
export async function handleExportLabels(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  let userId = "dev-user-id";
  if (token) {
    const session = decodeSession(token, env.SESSION_SECRET);
    if (session) {
      userId = session.userId;
    }
  }

  const repoQuery = req.query?.["repo"];
  const jsonExport = await db.exportFindingLabelsJson(userId, repoQuery);

  return {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Disposition": 'attachment; filename="nantis-finding-labels.json"',
    },
    body: jsonExport,
  };
}

function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return hash;
}

/**
 * Dev-only sample demo scan handler.
 * Scans the committed e2e fixture repo (fixtures/e2e-nextjs-supabase-stripe)
 * which always produces 3 real security findings.
 * Accessible at GET /api/dev/scan-sample-demo
 */
export async function handleSampleDemoScan(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const nodeEnv = process.env.NODE_ENV || env.NODE_ENV;
  if (nodeEnv === "production") {
    return {
      status: 403,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Sample demo scan disabled in production mode" }),
    };
  }

  const remoteIp = req.clientIp || "127.0.0.1";
  if (!isLocalhostAddress(remoteIp)) {
    return {
      status: 403,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Sample demo scan is restricted to local connections (127.0.0.1)." }),
    };
  }

  // Find the fixture directory relative to the project root
  const fixtureRelative = "fixtures/e2e-nextjs-supabase-stripe";
  const fixtureAbsolute = path.resolve(process.cwd(), fixtureRelative);

  if (!fs.existsSync(fixtureAbsolute) || !fs.statSync(fixtureAbsolute).isDirectory()) {
    return {
      status: 404,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        error: `Sample demo fixture not found at ${fixtureAbsolute}. Run from the project root.`,
      }),
    };
  }

  // Ensure dev user and repo exist in DB
  const devUser = await db.upsertUser({
    github_user_id: 99999,
    github_login: "devuser",
    avatar_url: "https://github.com/images/error/octocat_happy.gif",
  });

  const demoRepo = await db.upsertRepository({
    github_repo_id: 77777,
    name: "e2e-nextjs-supabase-stripe",
    full_name: "devuser/e2e-nextjs-supabase-stripe",
    private: false,
    installation_id: "1",
    default_branch: "main",
  });

  const token = req.sessionToken || req.cookies?.["nantis_session"];
  let session = token ? decodeSession(token, env.SESSION_SECRET) : null;
  let activeUserId = session?.userId;
  let sessionCookie: string | undefined;

  if (!activeUserId) {
    activeUserId = devUser.id;
    const sessionToken = encodeSession(
      {
        userId: devUser.id,
        githubUserId: devUser.github_user_id,
        githubLogin: devUser.github_login,
        createdAt: Date.now(),
      },
      env.SESSION_SECRET
    );
    sessionCookie = `nantis_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax`;
  }

  await db.grantRepoAccess(activeUserId, demoRepo.id);
  await db.grantRepoAccess(devUser.id, demoRepo.id);

  // Run static AST scan on the fixture directory
  const { findings } = await runScan(fixtureAbsolute, { json: true });

  const scan = await db.createScan({
    repository_id: demoRepo.id,
    commit_sha: "demo-fixture-scan",
    branch: "main",
    trigger_type: "manual",
    status: "completed",
  });

  if (findings.length > 0) {
    await db.saveScanFindings(scan.id, findings);
  }

  const headers: Record<string, string> = { Location: `/scans/${scan.id}` };
  if (sessionCookie) {
    headers["Set-Cookie"] = sessionCookie;
  }

  return {
    status: 302,
    headers,
    body: "",
  };
}

/**
 * Handle GET /api/dev/github-status or /api/github/status
 * Returns diagnostic metadata about the configured GITHUB_TOKEN (user, rate limits, scopes)
 * without ever exposing the raw token.
 */
export async function handleGitHubDiagnostic(
  _req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const token = env.GITHUB_TOKEN || process.env.GITHUB_TOKEN;
  const diagnostic = await validatePatConnection(token);

  return {
    status: 200,
    headers: {
      ...getDefaultHeaders(),
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify(diagnostic),
  };
}


