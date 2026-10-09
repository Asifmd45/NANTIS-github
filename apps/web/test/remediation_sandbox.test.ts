import fs from "fs";
import path from "path";
import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { encodeSession } from "../src/lib/session.js";
import { getOrCreateCsrfToken } from "../src/routes/ui-templates.js";
import { renderFixReviewPage } from "../src/routes/fix-review-page.js";
import { RequestContext } from "../src/routes/api-routes.js";
import {
  PatchSafetyGate,
  validateAntiSuppressionAndDeletion,
  applyStructuredEdits,
} from "@nantis/core";

const TEST_ENV: WebEnv = {
  GITHUB_CLIENT_ID: "client_id_test",
  GITHUB_CLIENT_SECRET: "client_secret_test",
  GITHUB_APP_ID: "12345",
  GITHUB_APP_PRIVATE_KEY: "private_key_test",
  GITHUB_WEBHOOK_SECRET: "whsec_test_secret",
  SESSION_SECRET: "test_secret_32_characters_key_here!!",
  DATABASE_URL: "postgresql://localhost:5432/nantis_test",
  NODE_ENV: "test",
};

const migrationPath = path.resolve(
  process.cwd(),
  "fixtures/e2e-nextjs-supabase-stripe/supabase/migrations/20260101_init.sql"
);
const originalMigration =
  "CREATE TABLE public.invoices (id uuid PRIMARY KEY, user_id uuid, amount integer);\n";

const stripePath = path.resolve(
  process.cwd(),
  "fixtures/e2e-nextjs-supabase-stripe/app/api/webhooks/stripe/route.ts"
);
const originalStripe = fs.existsSync(stripePath)
  ? fs.readFileSync(stripePath, "utf-8")
  : "";

function restoreFixtures() {
  if (fs.existsSync(migrationPath)) {
    fs.writeFileSync(migrationPath, originalMigration, "utf-8");
  }
  if (stripePath && originalStripe && fs.existsSync(stripePath)) {
    fs.writeFileSync(stripePath, originalStripe, "utf-8");
  }
}

describe("Interactive Remediation Sandbox (/findings/:id/fix)", () => {
  let userId: string;
  let unauthorizedUserId: string;
  let repoId: string;
  let scanId: string;
  let validSessionCookie: string;
  let unauthorizedSessionCookie: string;

  beforeEach(async () => {
    restoreFixtures();
    db.resetInMemoryData();

    // 1. Create test user with repo access
    const user = await db.upsertUser({
      github_user_id: 11111,
      github_login: "alice",
      avatar_url: "https://github.com/alice.png",
    });
    userId = user.id;

    // 2. Create unauthorized user
    const unauth = await db.upsertUser({
      github_user_id: 22222,
      github_login: "mallory",
      avatar_url: "https://github.com/mallory.png",
    });
    unauthorizedUserId = unauth.id;

    // 3. Create repository
    const repo = await db.upsertRepository({
      github_repo_id: 99999,
      name: "e2e-nextjs-supabase-stripe",
      full_name: "alice/e2e-nextjs-supabase-stripe",
      private: false,
      installation_id: "1",
      default_branch: "main",
    });
    repoId = repo.id;

    // Grant access only to Alice
    await db.grantRepoAccess(userId, repoId);

    // 4. Create scan
    const scan = await db.createScan({
      repository_id: repoId,
      commit_sha: "test-sha-123",
      branch: "main",
      trigger_type: "manual",
      status: "completed",
    });
    scanId = scan.id;

    // 5. Mint cookies
    validSessionCookie = encodeSession(
      {
        userId,
        githubUserId: 11111,
        githubLogin: "alice",
        createdAt: Date.now(),
      },
      TEST_ENV.SESSION_SECRET
    );

    unauthorizedSessionCookie = encodeSession(
      {
        userId: unauthorizedUserId,
        githubUserId: 22222,
        githubLogin: "mallory",
        createdAt: Date.now(),
      },
      TEST_ENV.SESSION_SECRET
    );
  });

  afterEach(() => {
    restoreFixtures();
  });

  // --- ACCESS CONTROL & AUTHENTICATION ---
  describe("1. Access Control & Authorization", () => {
    it("returns 401 Unauthorized when request has no session token", async () => {
      const req: RequestContext = {
        method: "GET",
        path: "/findings/nonexistent/fix",
        headers: {},
        cookies: {},
        clientIp: "127.0.0.1",
      };

      const res = await renderFixReviewPage(req, "nonexistent", TEST_ENV);
      expect(res.status).toBe(401);
      expect(res.body).toContain("401 Unauthorized");
    });

    it("returns 404 when finding does not exist", async () => {
      const req: RequestContext = {
        method: "GET",
        path: "/findings/nonexistent/fix",
        headers: {},
        cookies: { nantis_session: validSessionCookie },
        clientIp: "127.0.0.1",
      };

      const res = await renderFixReviewPage(req, "nonexistent", TEST_ENV);
      expect(res.status).toBe(404);
      expect(res.body).toContain("404 Finding Not Found");
    });

    it("returns 404 Default Deny when user has no access to repository", async () => {
      const finding = await db.createFinding({
        id: crypto.randomUUID(),
        scan_id: scanId,
        ruleId: "missing-rls-in-migration",
        title: "Missing Row Level Security (RLS) in Migration",
        severity: "high",
        confidenceTier: "proven",
        file: "supabase/migrations/20260101_init.sql",
        lineRange: { startLine: 1, endLine: 2 },
        explanation: "Table invoices without RLS.",
        evidenceChain: [],
        unresolvedSteps: [],
        fingerprint: "fp-rls-1",
      });
      const fid = finding.db_id;

      const req: RequestContext = {
        method: "GET",
        path: `/findings/${fid}/fix`,
        headers: {},
        cookies: { nantis_session: unauthorizedSessionCookie },
        clientIp: "127.0.0.1",
      };

      const res = await renderFixReviewPage(req, fid, TEST_ENV);
      // NANTIS default deny policy: 404 to avoid tenant enumeration
      expect(res.status).toBe(404);
      expect(res.body).toContain("404 Not Found");
    });
  });

  // --- UNSUPPORTED RULES & MANUAL GUIDANCE ---
  describe("2. Unsupported Rules & Manual Guidance", () => {
    it("displays manual remediation guidance and suppresses approval button for unsupported rules", async () => {
      const finding = await db.createFinding({
        id: crypto.randomUUID(),
        scan_id: scanId,
        ruleId: "missing-lockfile",
        title: "Missing Dependency Lockfile",
        severity: "medium",
        confidenceTier: "likely",
        file: "package.json",
        lineRange: { startLine: 1, endLine: 1 },
        explanation: "No lockfile found in repository.",
        evidenceChain: [],
        unresolvedSteps: [],
        fingerprint: "fp-lockfile-1",
      });
      const fid = finding.db_id;

      const req: RequestContext = {
        method: "GET",
        path: `/findings/${fid}/fix`,
        headers: {},
        cookies: { nantis_session: validSessionCookie },
        clientIp: "127.0.0.1",
      };

      const res = await renderFixReviewPage(req, fid, TEST_ENV);
      expect(res.status).toBe(200);
      expect(res.body).toContain("Automated AST Remediation Unavailable");
      expect(res.body).toContain("No automated AST fix rule available for rule ID");
      expect(res.body).toContain("missing-lockfile");
      expect(res.body).toContain("Actionable Manual Remediation Guidance");
      // Must NOT contain the approve button
      expect(res.body).not.toContain("Approve & Apply Fix");
    });
  });

  // --- AUTOMATED AST FIXES & ISOLATED SANDBOX ---
  describe("3. Automated AST Fixes & Verification Sandbox", () => {
    it("generates deterministic patch diff and runs sandbox verification for missing-rls-in-migration", async () => {
      const finding = await db.createFinding({
        id: crypto.randomUUID(),
        scan_id: scanId,
        ruleId: "missing-rls-in-migration",
        title: "Missing Row Level Security (RLS) in Migration",
        severity: "high",
        confidenceTier: "proven",
        file: "supabase/migrations/20260101_init.sql",
        lineRange: { startLine: 1, endLine: 2 },
        explanation: "Table 'invoices' created without RLS.",
        evidenceChain: [
          {
            kind: "source",
            file: "supabase/migrations/20260101_init.sql",
            line: 1,
            maskedSnippet: "CREATE TABLE public.invoices (id uuid PRIMARY KEY, user_id uuid, amount integer);",
            confidence: "high",
            note: "invoices table",
          },
        ],
        unresolvedSteps: [],
        fingerprint: "fp-rls-2",
      });
      const fid = finding.db_id;

      const req: RequestContext = {
        method: "GET",
        path: `/findings/${fid}/fix`,
        headers: {},
        cookies: { nantis_session: validSessionCookie },
        clientIp: "127.0.0.1",
      };

      const res = await renderFixReviewPage(req, fid, TEST_ENV);
      expect(res.status).toBe(200);
      expect(res.body).toContain("Deterministic AST Patch Diff");
      expect(res.body).toContain("ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;");
      expect(res.body).toContain("✓ Verification PASSED");
      expect(res.body).toContain("Approve & Apply Fix");
    });

    it("generates deterministic patch diff and runs sandbox verification for stripe-webhook-no-signature", async () => {
      const finding = await db.createFinding({
        id: crypto.randomUUID(),
        scan_id: scanId,
        ruleId: "stripe-webhook-no-signature",
        title: "Stripe Webhook Missing Signature Verification",
        severity: "critical",
        confidenceTier: "likely",
        file: "app/api/webhooks/stripe/route.ts",
        lineRange: { startLine: 2, endLine: 5 },
        explanation: "Webhook parses body without verifying signature.",
        evidenceChain: [
          {
            kind: "sink",
            file: "app/api/webhooks/stripe/route.ts",
            line: 2,
            maskedSnippet: 'export async function POST(req) {\n  const body = await req.json();\n  return new Response("OK");\n}',
            confidence: "high",
            note: "Stripe webhook",
          },
        ],
        unresolvedSteps: [],
        fingerprint: "fp-stripe-1",
      });
      const fid = finding.db_id;

      const req: RequestContext = {
        method: "GET",
        path: `/findings/${fid}/fix`,
        headers: {},
        cookies: { nantis_session: validSessionCookie },
        clientIp: "127.0.0.1",
      };

      const res = await renderFixReviewPage(req, fid, TEST_ENV);
      expect(res.status).toBe(200);
      expect(res.body).toContain("Deterministic AST Patch Diff");
      expect(res.body).toContain("stripe.webhooks.constructEvent");
      expect(res.body).toContain("✓ Verification PASSED");
      expect(res.body).toContain("Approve & Apply Fix");
    });
  });

  // --- USER APPROVAL & REJECTION FLOWS ---
  describe("4. Fix Approval & Rejection Flow", () => {
    it("successfully applies approved patch, creates audit log, and marks finding as real issue", async () => {
      const finding = await db.createFinding({
        id: crypto.randomUUID(),
        scan_id: scanId,
        ruleId: "missing-rls-in-migration",
        title: "Missing Row Level Security (RLS) in Migration",
        severity: "high",
        confidenceTier: "proven",
        file: "supabase/migrations/20260101_init.sql",
        lineRange: { startLine: 1, endLine: 2 },
        explanation: "Table 'invoices' created without RLS.",
        evidenceChain: [],
        unresolvedSteps: [],
        fingerprint: "fp-rls-approve-1",
      });
      const fid = finding.db_id;

      const csrfToken = getOrCreateCsrfToken(userId);

      const req: RequestContext = {
        method: "POST",
        path: `/findings/${fid}/fix`,
        headers: {},
        cookies: { nantis_session: validSessionCookie },
        clientIp: "127.0.0.1",
        body: {
          _csrf: csrfToken,
          action: "approve",
        },
      };

      const res = await renderFixReviewPage(req, fid, TEST_ENV);
      expect(res.status).toBe(200);
      expect(res.body).toContain("Fix Approved & Applied to Workspace");

      // Verify DB audit log was created
      const auditLogs = db.getAuditLogs ? await db.getAuditLogs() : [];
      expect(auditLogs.some((l) => l.action === "patch_approved_and_applied")).toBe(true);

      // Verify finding label was saved
      const label = await db.getFindingLabel(userId, fid);
      expect(label?.label).toBe("real_issue");
    });

    it("records false_positive label when user rejects the fix", async () => {
      const finding = await db.createFinding({
        id: crypto.randomUUID(),
        scan_id: scanId,
        ruleId: "missing-rls-in-migration",
        title: "Missing Row Level Security (RLS) in Migration",
        severity: "high",
        confidenceTier: "proven",
        file: "supabase/migrations/20260101_init.sql",
        lineRange: { startLine: 1, endLine: 2 },
        explanation: "Table 'invoices' created without RLS.",
        evidenceChain: [],
        unresolvedSteps: [],
        fingerprint: "fp-rls-reject-1",
      });
      const fid = finding.db_id;

      const csrfToken = getOrCreateCsrfToken(userId);

      const req: RequestContext = {
        method: "POST",
        path: `/findings/${fid}/fix`,
        headers: {},
        cookies: { nantis_session: validSessionCookie },
        clientIp: "127.0.0.1",
        body: {
          _csrf: csrfToken,
          action: "reject",
        },
      };

      const res = await renderFixReviewPage(req, fid, TEST_ENV);
      expect(res.status).toBe(200);
      expect(res.body).toContain("Finding Tagged as False Positive");

      // Verify finding label was saved as false_positive
      const label = await db.getFindingLabel(userId, fid);
      expect(label?.label).toBe("false_positive");
    });
  });

  // --- SECURITY CONTROLS & PATCH SAFETY GATE ---
  describe("5. Security Controls, CSRF & Patch Safety Gate", () => {
    it("rejects POST with 403 when CSRF token is invalid", async () => {
      const finding = await db.createFinding({
        id: crypto.randomUUID(),
        scan_id: scanId,
        ruleId: "missing-rls-in-migration",
        title: "Missing Row Level Security (RLS) in Migration",
        severity: "high",
        confidenceTier: "proven",
        file: "supabase/migrations/20260101_init.sql",
        lineRange: { startLine: 1, endLine: 2 },
        explanation: "Table 'invoices' created without RLS.",
        evidenceChain: [],
        unresolvedSteps: [],
        fingerprint: "fp-csrf-1",
      });
      const fid = finding.db_id;

      const req: RequestContext = {
        method: "POST",
        path: `/findings/${fid}/fix`,
        headers: {},
        cookies: { nantis_session: validSessionCookie },
        clientIp: "127.0.0.1",
        body: {
          _csrf: "invalid-token-tampered",
          action: "approve",
        },
      };

      const res = await renderFixReviewPage(req, fid, TEST_ENV);
      expect(res.status).toBe(403);
      expect(res.body).toContain("403 Invalid CSRF Token");
    });

    it("rejects approval with 400 when attempting to approve an unsupported rule", async () => {
      const finding = await db.createFinding({
        id: crypto.randomUUID(),
        scan_id: scanId,
        ruleId: "missing-lockfile",
        title: "Missing Lockfile",
        severity: "high",
        confidenceTier: "proven",
        file: "package.json",
        lineRange: { startLine: 1, endLine: 1 },
        explanation: "No lockfile.",
        evidenceChain: [],
        unresolvedSteps: [],
        fingerprint: "fp-lockfile-approve-block",
      });
      const fid = finding.db_id;

      const csrfToken = getOrCreateCsrfToken(userId);

      const req: RequestContext = {
        method: "POST",
        path: `/findings/${fid}/fix`,
        headers: {},
        cookies: { nantis_session: validSessionCookie },
        clientIp: "127.0.0.1",
        body: {
          _csrf: csrfToken,
          action: "approve",
        },
      };

      const res = await renderFixReviewPage(req, fid, TEST_ENV);
      expect(res.status).toBe(400);
      expect(res.body).toContain("400 Automated Fix Unavailable");
    });

    it("validates that PatchSafetyGate blocks path traversal and forbidden files", () => {
      const traversalEdit = [
        {
          targetFile: "../../etc/shadow",
          targetContent: "target",
          replacementContent: "replacement",
        },
      ];
      const gateRes = PatchSafetyGate.validatePatch(traversalEdit, "", ["../../etc/shadow"]);
      expect(gateRes.valid).toBe(false);
      expect(gateRes.reason).toContain("traversal detected");

      const gitEdit = [
        {
          targetFile: ".git/config",
          targetContent: "target",
          replacementContent: "replacement",
        },
      ];
      const gitGateRes = PatchSafetyGate.validatePatch(gitEdit, "", [".git/config"]);
      expect(gitGateRes.valid).toBe(false);
      expect(gitGateRes.reason).toContain("forbidden .git directory");
    });

    it("validates that anti-suppression blocks eslint-disable and @ts-ignore comments", () => {
      const suppressionDiff = `
--- a/file.ts
+++ b/file.ts
@@ -1,1 +1,2 @@
+// eslint-disable-next-line
 function insecure() {}
`;
      const check = validateAntiSuppressionAndDeletion(suppressionDiff);
      expect(check.valid).toBe(false);
      expect(check.reason).toContain("rule suppression comment");
    });

    it("validates that applyStructuredEdits aborts cleanly on target content mismatch", () => {
      const originalCode = "const x = 10;";
      const result = applyStructuredEdits(originalCode, [
        {
          targetFile: "code.ts",
          targetContent: "const nonExistent = 999;",
          replacementContent: "const y = 20;",
        },
      ]);
      expect(result.success).toBe(false);
      expect(result.reason).toContain("Target content not found in file");
    });
  });
});
