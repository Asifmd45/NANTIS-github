import { describe, expect, it, afterEach } from "vitest";
import path from "path";
import os from "os";
import fs from "fs";
import { isLocalhostAddress, handleDevLogin, handleDevScan, handleSampleDemoScan } from "../src/routes/dev-routes.js";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { RequestContext } from "../src/routes/api-routes.js";

const TEST_ENV: WebEnv = {
  GITHUB_CLIENT_ID: "dev_client_id",
  GITHUB_CLIENT_SECRET: "dev_client_secret",
  GITHUB_APP_ID: "99999",
  GITHUB_APP_PRIVATE_KEY: "dev_private_key",
  GITHUB_WEBHOOK_SECRET: "dev_webhook_secret",
  SESSION_SECRET: "dev_session_secret_32_characters_key_here",
  DATABASE_URL: "postgresql://localhost:5432/test",
  NODE_ENV: "development",
};

describe("Dev Server & Security Controls (apps/web/src/routes/dev-routes.ts)", () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  it("should validate localhost loopback IP addresses correctly", () => {
    expect(isLocalhostAddress("127.0.0.1")).toBe(true);
    expect(isLocalhostAddress("::1")).toBe(true);
    expect(isLocalhostAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isLocalhostAddress("localhost")).toBe(true);

    expect(isLocalhostAddress("192.168.1.100")).toBe(false);
    expect(isLocalhostAddress("10.0.0.1")).toBe(false);
    expect(isLocalhostAddress("8.8.8.8")).toBe(false);
    expect(isLocalhostAddress("")).toBe(false);
    expect(isLocalhostAddress(undefined)).toBe(false);
  });

  it("should REJECT dev login when NODE_ENV is set to production", async () => {
    process.env.NODE_ENV = "production";

    const dummyReq: RequestContext = {
      method: "GET",
      path: "/auth/dev-login",
      headers: {},
      cookies: {},
      clientIp: "127.0.0.1",
    };

    const res = await handleDevLogin(dummyReq, { ...TEST_ENV, NODE_ENV: "production" });

    expect(res.status).toBe(403);
    expect(res.body).toContain("Dev login is disabled in production mode");
  });

  it("should REJECT dev login when request originates from a non-localhost IP address", async () => {
    process.env.NODE_ENV = "development";

    const remoteReq: RequestContext = {
      method: "GET",
      path: "/auth/dev-login",
      headers: {},
      cookies: {},
      clientIp: "192.168.1.100", // Remote non-localhost IP
    };

    const res = await handleDevLogin(remoteReq, TEST_ENV);

    expect(res.status).toBe(403);
    expect(res.body).toContain("restricted to local connections");
  });

  it("should ALLOW dev login from localhost (127.0.0.1) in development mode", async () => {
    process.env.NODE_ENV = "development";

    const localReq: RequestContext = {
      method: "GET",
      path: "/auth/dev-login",
      headers: {},
      cookies: {},
      clientIp: "127.0.0.1",
    };

    const res = await handleDevLogin(localReq, TEST_ENV);

    expect(res.status).toBe(302);
    expect(res.headers.Location).toBe("/repos");
    expect(res.headers["Set-Cookie"]).toContain("nantis_session=");
  });

  it("should BLOCK path traversal when target scan folder is outside ALLOWED_SCAN_ROOT", async () => {
    process.env.NODE_ENV = "development";

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "allowed-root-"));
    const outsideFolder = fs.mkdtempSync(path.join(os.tmpdir(), "outside-folder-"));

    process.env.ALLOWED_SCAN_ROOT = tempRoot;

    try {
      const req: RequestContext = {
        method: "POST",
        path: "/api/dev/scan",
        headers: {},
        cookies: {},
        clientIp: "127.0.0.1",
        body: { folder: outsideFolder }, // Attempt to scan directory outside ALLOWED_SCAN_ROOT
      };

      const res = await handleDevScan(req, TEST_ENV);

      expect(res.status).toBe(400);
      expect(res.body).toContain("Path traversal blocked");
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
      fs.rmSync(outsideFolder, { recursive: true, force: true });
      delete process.env.ALLOWED_SCAN_ROOT;
    }
  });

  it("should REJECT sample demo scan when NODE_ENV is set to production", async () => {
    process.env.NODE_ENV = "production";

    const dummyReq: RequestContext = {
      method: "GET",
      path: "/api/dev/scan-sample-demo",
      headers: {},
      cookies: {},
      clientIp: "127.0.0.1",
    };

    const res = await handleSampleDemoScan(dummyReq, { ...TEST_ENV, NODE_ENV: "production" });

    expect(res.status).toBe(403);
    expect(res.body).toContain("Sample demo scan disabled in production mode");
  });

  it("should REJECT sample demo scan when request originates from a non-localhost IP address", async () => {
    process.env.NODE_ENV = "development";

    const remoteReq: RequestContext = {
      method: "GET",
      path: "/api/dev/scan-sample-demo",
      headers: {},
      cookies: {},
      clientIp: "192.168.1.100",
    };

    const res = await handleSampleDemoScan(remoteReq, TEST_ENV);

    expect(res.status).toBe(403);
    expect(res.body).toContain("restricted to local connections");
  });

  it("should scan sample fixture and persist exactly 3 real findings in development", async () => {
    process.env.NODE_ENV = "development";

    const req: RequestContext = {
      method: "GET",
      path: "/api/dev/scan-sample-demo",
      headers: {},
      cookies: {},
      clientIp: "127.0.0.1",
    };

    const res = await handleSampleDemoScan(req, TEST_ENV);

    expect(res.status).toBe(302);
    expect(res.headers.Location).toMatch(/^\/scans\/[a-f0-9-]+$/);

    const scanId = (res.headers.Location as string).replace("/scans/", "");
    const scan = await db.getScanById(scanId);
    expect(scan).toBeDefined();
    expect(scan?.status).toBe("completed");

    const findings = await db.getFindingsForScan(scanId);
    expect(findings.length).toBe(3);

    const ruleIds = findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toEqual([
      "missing-lockfile",
      "missing-rls-in-migration",
      "stripe-webhook-no-signature",
    ]);
  }, 15000);
});

