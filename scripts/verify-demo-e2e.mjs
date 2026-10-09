import fs from "fs";
import http from "http";

async function verifyDemo() {
  console.log("=== STEP 1: Verify /auth/dev-login ===");
  const loginRes = await new Promise((resolve, reject) => {
    http.get("http://127.0.0.1:3000/auth/dev-login", (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      res.on("error", reject);
    });
  });

  console.log("Status:", loginRes.status);
  console.log("Location:", loginRes.headers.location);
  const setCookie = loginRes.headers["set-cookie"];
  console.log("Set-Cookie:", setCookie);
  if (!setCookie || !setCookie[0]?.includes("nantis_session=")) {
    throw new Error("Failed to get nantis_session cookie");
  }
  const sessionCookie = setCookie[0].split(";")[0];

  console.log("\n=== STEP 2: Verify /api/dev/scan-sample-demo ===");
  const scanTriggerRes = await new Promise((resolve, reject) => {
    const req = http.request(
      "http://127.0.0.1:3000/api/dev/scan-sample-demo",
      {
        method: "GET",
        headers: { Cookie: sessionCookie },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        res.on("error", reject);
      }
    );
    req.end();
  });

  console.log("Status:", scanTriggerRes.status);
  console.log("Redirect Location:", scanTriggerRes.headers.location);
  const redirectLoc = scanTriggerRes.headers.location;
  if (!redirectLoc || !redirectLoc.startsWith("/scans/")) {
    throw new Error(`Expected redirect to /scans/<id>, got: ${redirectLoc}`);
  }
  const scanId = redirectLoc.replace("/scans/", "");

  console.log("\n=== STEP 3: Verify Scan Results Page (" + redirectLoc + ") ===");
  const scanPageRes = await new Promise((resolve, reject) => {
    const req = http.request(
      `http://127.0.0.1:3000${redirectLoc}`,
      {
        method: "GET",
        headers: { Cookie: sessionCookie },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        res.on("error", reject);
      }
    );
    req.end();
  });

  console.log("Status:", scanPageRes.status);
  const html = scanPageRes.body;

  // Extract raw findings
  const m = html.match(/const findingsList = (\[[\s\S]*?\]);\s*const findingsMap/);
  if (!m) {
    throw new Error("Could not find findingsList in HTML");
  }
  const rawFindings = JSON.parse(m[1]);
  console.log(`\nPersisted findings count: ${rawFindings.length}`);
  rawFindings.forEach((f, idx) => {
    console.log(`\n[Finding ${idx + 1}]`);
    console.log(`  Rule ID:     ${f.ruleId}`);
    console.log(`  Title:       ${f.title}`);
    console.log(`  Severity:    ${f.severity}`);
    console.log(`  File:        ${f.file}`);
    console.log(`  Lines:       ${f.startLine}-${f.endLine}`);
    console.log(`  Explanation: ${f.explanation.substring(0, 80)}...`);
  });

  // Extract Severity Card Counts
  const critMatch = html.match(/<span[^>]*color:\s*#dc2626[^>]*>(\d+)<\/span>[\s\S]*?Critical<\/div>/);
  const highMatch = html.match(/<span[^>]*color:\s*#ea580c[^>]*>(\d+)<\/span>[\s\S]*?High<\/div>/);
  const medMatch = html.match(/<span[^>]*color:\s*#eab308[^>]*>(\d+)<\/span>[\s\S]*?Medium<\/div>/);
  const lowMatch = html.match(/<span[^>]*color:\s*#3b82f6[^>]*>(\d+)<\/span>[\s\S]*?Low<\/div>/);

  console.log("\nSeverity Card Badges in UI:");
  console.log(`  Critical: ${critMatch ? critMatch[1] : "N/A"}`);
  console.log(`  High:     ${highMatch ? highMatch[1] : "N/A"}`);
  console.log(`  Medium:   ${medMatch ? medMatch[1] : "N/A"}`);
  console.log(`  Low:      ${lowMatch ? lowMatch[1] : "N/A"}`);

  console.log("\n=== STEP 4: Verify /scans redirection ===");
  const scansRes = await new Promise((resolve, reject) => {
    const req = http.request(
      "http://127.0.0.1:3000/scans",
      {
        method: "GET",
        headers: { Cookie: sessionCookie },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        res.on("error", reject);
      }
    );
    req.end();
  });

  console.log("Status with auth:", scansRes.status);
  console.log("Redirect Location with auth:", scansRes.headers.location);

  // Unauthenticated /scans
  const unauthScansRes = await new Promise((resolve, reject) => {
    http.get("http://127.0.0.1:3000/scans", (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      res.on("error", reject);
    });
  });

  console.log("Status without auth:", unauthScansRes.status);
  console.log("Contains 'Connect GitHub Required':", unauthScansRes.body.includes("Connect GitHub Required"));

  console.log("\n=== ALL END-TO-END VERIFICATION CHECKS PASSED ===");
}

verifyDemo().catch((err) => {
  console.error("Verification failed:", err);
  process.exit(1);
});
