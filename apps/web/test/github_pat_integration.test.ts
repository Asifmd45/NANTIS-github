import { describe, expect, it, beforeEach, vi } from "vitest";
import {
  validatePatConnection,
  checkRepoAccessWithPat,
} from "../src/lib/github-pat.js";
import { sanitizeGitErrorMessage } from "@nantis/worker";
import { handleGitHubDiagnostic } from "../src/routes/dev-routes.js";
import { WebEnv } from "../src/lib/env.js";
import { db } from "../src/db/client.js";
import { RequestContext } from "../src/routes/api-routes.js";

const TEST_ENV: WebEnv = {
  GITHUB_CLIENT_ID: "client_id_test",
  GITHUB_CLIENT_SECRET: "client_secret_test",
  GITHUB_APP_ID: "12345",
  GITHUB_APP_PRIVATE_KEY: "private_key_test",
  GITHUB_WEBHOOK_SECRET: "whsec_test_secret_12345",
  GITHUB_TOKEN: "ghp_validTestToken1234567890abcdefABCDEF",
  SESSION_SECRET: "test_secret_32_bytes_long_string!",
  DATABASE_URL: "postgresql://localhost:5432/nantis_db",
  NODE_ENV: "test",
};

describe("GitHub Personal Access Token (PAT) Integration Suite", () => {
  beforeEach(() => {
    db.resetInMemoryData();
    vi.restoreAllMocks();
  });

  describe("1. PAT Connection Diagnostic (validatePatConnection)", () => {
    it("1.1 returns configured: false when no GITHUB_TOKEN is provided", async () => {
      const diag = await validatePatConnection("");
      expect(diag.configured).toBe(false);
      expect(diag.authenticated).toBe(false);
      expect(diag.message).toContain("No GITHUB_TOKEN configured");
      expect(JSON.stringify(diag)).not.toContain("ghp_");
    });

    it("1.2 validates valid PAT, extracts username, scopes, and rate limits without leaking token", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({
          "x-ratelimit-limit": "5000",
          "x-ratelimit-remaining": "4980",
          "x-ratelimit-reset": "1700000000",
          "x-oauth-scopes": "repo, read:user",
        }),
        json: async () => ({
          login: "octocat",
          id: 583231,
          avatar_url: "https://github.com/images/error/octocat_happy.gif",
        }),
      } as Response);

      const token = "ghp_superSecretToken1234567890abcdefABCDEF";
      const diag = await validatePatConnection(token, mockFetch as unknown as typeof fetch);

      expect(diag.configured).toBe(true);
      expect(diag.authenticated).toBe(true);
      expect(diag.user).toBe("octocat");
      expect(diag.scopes).toEqual(["repo", "read:user"]);
      expect(diag.rateLimit?.remaining).toBe(4980);
      expect(diag.rateLimit?.limit).toBe(5000);
      expect(diag.tokenType).toBe("classic");

      // Verify the secret token is NEVER present in the output
      const serialized = JSON.stringify(diag);
      expect(serialized).not.toContain(token);
      expect(serialized).not.toContain("ghp_");
    });

    it("1.3 identifies fine-grained PAT when x-oauth-scopes is absent", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({
          "x-ratelimit-limit": "5000",
          "x-ratelimit-remaining": "5000",
          "x-ratelimit-reset": "1700000000",
        }),
        json: async () => ({
          login: "fine-grained-user",
          id: 9999,
          avatar_url: "https://github.com/avatar.png",
        }),
      } as Response);

      const diag = await validatePatConnection("github_pat_11AAAA", mockFetch as unknown as typeof fetch);
      expect(diag.authenticated).toBe(true);
      expect(diag.tokenType).toBe("fine-grained");
      expect(diag.scopes).toBeUndefined();
    });

    it("1.4 returns actionable 401 error on invalid / expired token", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        headers: new Headers({
          "x-ratelimit-limit": "60",
          "x-ratelimit-remaining": "59",
        }),
        json: async () => ({ message: "Bad credentials" }),
      } as Response);

      const badToken = "ghp_invalidExpiredToken9999999";
      const diag = await validatePatConnection(badToken, mockFetch as unknown as typeof fetch);

      expect(diag.configured).toBe(true);
      expect(diag.authenticated).toBe(false);
      expect(diag.status).toBe(401);
      expect(diag.error).toContain("Authentication failed");
      expect(JSON.stringify(diag)).not.toContain(badToken);
    });

    it("1.5 returns actionable rate limit error when remaining is 0", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        headers: new Headers({
          "x-ratelimit-limit": "5000",
          "x-ratelimit-remaining": "0",
          "x-ratelimit-reset": "1700000000",
        }),
        json: async () => ({ message: "API rate limit exceeded" }),
      } as Response);

      const diag = await validatePatConnection("ghp_rateLimitedToken", mockFetch as unknown as typeof fetch);
      expect(diag.configured).toBe(true);
      expect(diag.authenticated).toBe(false);
      expect(diag.status).toBe(403);
      expect(diag.error).toContain("rate limit exceeded");
    });

    it("1.6 handles network connection errors gracefully", async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("ENOTFOUND api.github.com"));

      const diag = await validatePatConnection("ghp_testToken", mockFetch as unknown as typeof fetch);
      expect(diag.configured).toBe(true);
      expect(diag.authenticated).toBe(false);
      expect(diag.error).toContain("Network error connecting to GitHub API");
      expect(diag.error).toContain("ENOTFOUND");
    });
  });

  describe("2. Repository Access Check (checkRepoAccessWithPat)", () => {
    it("2.1 successfully verifies access to repository with PAT", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          private: true,
          default_branch: "main",
          full_name: "org/private-repo",
        }),
      } as Response);

      const res = await checkRepoAccessWithPat("org", "private-repo", "ghp_token", mockFetch as unknown as typeof fetch);
      expect(res.accessible).toBe(true);
      expect(res.isPrivate).toBe(true);
      expect(res.defaultBranch).toBe("main");
      expect(res.fullName).toBe("org/private-repo");
    });

    it("2.2 accurately distinguishes 404 (inaccessible or private repo concealed by GitHub)", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        headers: new Headers(),
      } as Response);

      const res = await checkRepoAccessWithPat("org", "hidden-repo", "ghp_token", mockFetch as unknown as typeof fetch);
      expect(res.accessible).toBe(false);
      expect(res.status).toBe(404);
      expect(res.error).toContain("Repository not found or access denied");
    });

    it("2.3 accurately distinguishes 403 permission denied", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        headers: new Headers({ "x-ratelimit-remaining": "500" }),
      } as Response);

      const res = await checkRepoAccessWithPat("org", "forbidden-repo", "ghp_token", mockFetch as unknown as typeof fetch);
      expect(res.accessible).toBe(false);
      expect(res.status).toBe(403);
      expect(res.error).toContain("Access denied: GITHUB_TOKEN lacks permission");
    });
  });

  describe("3. Secret Redaction & Git Error Sanitization", () => {
    it("3.1 redacts personal access token from git clone errors", () => {
      const secret = "ghp_SUPER_SECRET_PAT_TOKEN_VALUE_XYZ";
      const err = new Error(`fatal: Authentication failed for 'https://${secret}@github.com/org/repo.git/'`);
      const sanitized = sanitizeGitErrorMessage(err, secret);

      expect(sanitized).not.toContain(secret);
      expect(sanitized).toContain("Authentication failed: GitHub token is invalid or expired");
    });

    it("3.2 redacts generic GitHub token patterns even if token param not explicitly passed", () => {
      const err = new Error("Git driver warning: ghp_1234567890abcdef1234567890abcdef encountered in output");
      const sanitized = sanitizeGitErrorMessage(err);

      expect(sanitized).not.toContain("ghp_1234567890abcdef1234567890abcdef");
      expect(sanitized).toContain("[REDACTED_TOKEN]");
    });

    it("3.3 produces actionable repository not found message", () => {
      const err = new Error("fatal: repository 'https://github.com/org/private.git/' not found");
      const sanitized = sanitizeGitErrorMessage(err);

      expect(sanitized).toContain("Repository not found or access denied");
    });
  });

  describe("4. Diagnostic Endpoint Handler (/api/dev/github-status)", () => {
    it("4.1 returns diagnostic JSON with 200 OK and no-store cache headers", async () => {
      const req: RequestContext = {
        method: "GET",
        path: "/api/dev/github-status",
        headers: {},
      };

      const res = await handleGitHubDiagnostic(req, TEST_ENV);
      expect(res.status).toBe(200);
      expect(res.headers["Content-Type"]).toBe("application/json");
      expect(res.headers["Cache-Control"]).toBe("no-store");

      const body = JSON.parse(res.body || "{}");
      expect(body).toHaveProperty("configured");
      expect(body).toHaveProperty("authenticated");
      // Must NEVER leak the configured token in the response body
      expect(res.body || "").not.toContain(String(TEST_ENV.GITHUB_TOKEN));
    });
  });
});
