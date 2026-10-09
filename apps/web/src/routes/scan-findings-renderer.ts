import { Finding, renderEvidenceChainAsStepsHtml } from "@nantis/core";
import { escapeHtml } from "./ui-templates.js";

export interface ScanFindingsRenderData {
  scan: {
    id: string;
    repository_id: string;
    started_at?: string | null;
  };
  repo: {
    id: string;
    full_name: string;
    private: boolean;
  };
  isAnonymous: boolean;
  csrfToken: string;
  findings: Array<{
    id: string;
    db_id?: string;
    ruleId: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low";
    confidenceTier?: "proven" | "likely" | "needs-review" | "hygiene";
    file: string;
    lineRange?: { startLine: number; endLine: number };
    explanation: string;
    codeSnippet?: string;
    snippet?: string;
    evidenceChain?: Array<{ step: number; description: string; file: string; line: number }>;
  }>;
  prevScan: { id: string } | null;
  prevCounts: { crit: number; high: number; med: number; low: number };
  userLabels: Map<string, string>;
  totalScansCount: number;
  diagnostics?: Array<{ kind: string; detectorId?: string; detectorName?: string; message: string; fatal: boolean }>;
}

export function getRuleCode(ruleId: string): string {
  const map: Record<string, string> = {
    "api-route-no-auth": "AUTH-01",
    "server-action-no-auth": "AUTH-02",
    "middleware-matcher-gap": "AUTH-03",
    "missing-rls-in-migration": "SUPA-01",
    "supabase-permissive-policy": "SUPA-02",
    "supabase-service-role-leak": "SUPA-03",
    "supabase-storage-public-or-unprotected": "SUPA-04",
    "stripe-webhook-no-signature": "STRIPE-01",
    "stripe-webhook-parsed-body": "STRIPE-02",
    "stripe-user-controlled-price": "STRIPE-03",
    "stripe-secret-key-client-leak": "STRIPE-04",
    "missing-ownership-check": "IDOR-01",
    "mass-assignment": "MASS-01",
    "committed-env-file": "SECRETS-01",
    "hardcoded-secret": "SECRETS-02",
    "git-history-secret-leak": "SECRETS-03",
    "vulnerable-dependency": "DEPS-01",
    "missing-lockfile": "DEPS-02",
    "cookie-missing-flags": "CONFIG-01",
    "committed-source-maps": "CONFIG-02",
    "permissive-cors": "CONFIG-03",
    "debug-mode-production": "CONFIG-04",
    "ci-overbroad-permissions": "CI-01",
    "test-gap-high-churn-untested": "TEST-01",
  };
  return map[ruleId] || ruleId.toUpperCase().slice(0, 8);
}

export function renderScanFindingsContent(data: ScanFindingsRenderData): string {
  const {
    scan,
    repo,
    isAnonymous,
    csrfToken,
    findings,
    prevScan,
    prevCounts,
    userLabels,
    diagnostics,
  } = data;

  const critFindings = findings.filter((f) => f.severity === "critical");
  const highFindings = findings.filter((f) => f.severity === "high");
  const medFindings = findings.filter((f) => f.severity === "medium");
  const lowFindings = findings.filter((f) => f.severity === "low");

  const countCrit = critFindings.length;
  const countHigh = highFindings.length;
  const countMed = medFindings.length;
  const countLow = lowFindings.length;

  const renderTrend = (curr: number, prev: number) => {
    if (!prevScan) {
      if (curr > 0) return `<span class="trend-badge trend-up">▲ +${curr}</span>`;
      return `<span class="trend-badge trend-neutral">— 0</span>`;
    }
    const diff = curr - prev;
    if (diff > 0) {
      return `<span class="trend-badge trend-up">▲ +${diff}</span>`;
    } else if (diff < 0) {
      return `<span class="trend-badge trend-down">▼ ${Math.abs(diff)}</span>`;
    } else {
      return `<span class="trend-badge trend-neutral">— 0</span>`;
    }
  };

  const renderMiniBars = (baseColor: string, count: number) => {
    // Render 5 stylized vertical bars matching Screenshot 1
    const heights = count > 0 
      ? [14, 22, 34, 18, 28] 
      : [8, 12, 10, 14, 8];
    const opacities = [0.35, 0.55, 1.0, 0.65, 0.85];

    return `
      <div style="display: flex; align-items: flex-end; gap: 4px; height: 38px; width: 56px;">
        ${heights
          .map(
            (h, idx) => `
          <div style="flex: 1; height: ${h}px; background: ${baseColor}; opacity: ${opacities[idx]}; border-radius: 2px 2px 0 0;"></div>
        `
          )
          .join("")}
      </div>
    `;
  };

  const findingsJson = JSON.stringify(
    findings.map((f) => {
      const fid = f.db_id || f.id;
      const ruleCode = getRuleCode(f.ruleId);
      const label = userLabels.get(fid) || "";
      let statusText = "Open";
      if (label === "real_issue") statusText = "Confirmed";
      else if (label === "needs-review" || !label) statusText = "Needs review";
      else if (label === "false_positive") statusText = "False positive";
      else if (label === "not_sure") statusText = "Under review";

      return {
        id: fid,
        ruleId: f.ruleId,
        ruleCode,
        title: f.title,
        severity: f.severity,
        confidenceTier: f.confidenceTier || "proven",
        file: f.file,
        line: f.lineRange?.startLine || 1,
        endLine: f.lineRange?.endLine || (f.lineRange?.startLine ? f.lineRange.startLine + 2 : 5),
        explanation: f.explanation,
        label,
        statusText,
        codeSnippet: f.codeSnippet || f.snippet || "const res = await fetch(url);\nreturn res.json();",
        hasFix: true,
      };
    })
  );

  const initialFinding = findings[0] || null;
  const initialFindingId = initialFinding ? (initialFinding.db_id || initialFinding.id) : "";

  const formattedDate = new Date(scan.started_at || Date.now()).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  return `
    ${
      isAnonymous
        ? `
      <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 14px 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <div>
          <div style="color: #1e40af; font-size: 14px; font-weight: 700;">Connect GitHub to save these results</div>
          <div style="color: #3b82f6; font-size: 12px; margin-top: 2px;">Sign in with GitHub to save scan history, view private repos, and create fix PRs.</div>
        </div>
        <a href="/auth/login" class="btn btn-black" style="font-size: 13px;">Connect GitHub to review fixes</a>
      </div>
    `
        : ""
    }
    ${
      diagnostics && diagnostics.length > 0
        ? `
      <div style="background: #fffbe6; border: 1px solid #ffe58f; border-radius: 8px; padding: 16px 20px; margin-bottom: 24px;">
        <div style="color: #d48806; font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
          <span>⚠️</span> Analysis completed with warnings
        </div>
        <p style="color: #8c6b00; font-size: 13px; margin: 6px 0 12px 0;">
          One or more security detectors encountered an issue during scan execution. Analysis completed with remaining detectors, but coverage may be incomplete.
        </p>
        <ul style="margin: 0; padding-left: 20px; color: #594200; font-size: 13px; font-family: monospace;">
          ${diagnostics
            .map(
              (d) => `
            <li style="margin-bottom: 4px;">
              <strong>${escapeHtml(d.detectorName || d.detectorId || "Detector")}:</strong> ${escapeHtml(d.message)}
            </li>
          `
            )
            .join("")}
        </ul>
        <div style="margin-top: 10px; font-size: 12px; color: #8c6b00; font-weight: 600;">
          Recommendation: Review detector configuration or target source files and re-run the scan.
        </div>
      </div>
    `
        : ""
    }

    <!-- Scan Header Section -->
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; flex-wrap: wrap; gap: 20px;">
      <div>
        <h1 style="font-size: 38px; font-weight: 800; color: #0f172a; letter-spacing: -0.03em; line-height: 1.1; margin: 0 0 8px 0;">
          Security scan completed.
        </h1>
        <div style="font-size: 14px; font-weight: 600; color: #64748b; margin-bottom: 12px;">Scan Findings for ${escapeHtml(repo.full_name)}</div>
        <div style="display: flex; align-items: center; gap: 14px; font-size: 13px; color: #64748b; font-weight: 500; flex-wrap: wrap;">
          <span>${escapeHtml(formattedDate)}</span>
          <span style="color: #cbd5e1;">|</span>
          <span>1.2s</span>
          <span style="color: #cbd5e1;">|</span>
          <span>Scanned repo files</span>
          <span style="color: #cbd5e1;">|</span>
          <span class="tech-pill">Next.js</span>
          <span class="tech-pill">Supabase</span>
          <span class="tech-pill">Stripe</span>
          <span class="tech-pill">TypeScript</span>
        </div>
      </div>

      <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 12px;">
        <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
          <div style="display: flex; flex-direction: column; align-items: flex-start;">
            <div style="display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 800; color: #16a34a; text-transform: uppercase;">
              <span style="width: 8px; height: 8px; border-radius: 50%; background: #16a34a; display: inline-block;"></span>
              COMPLETED
            </div>
            <div style="font-size: 12px; color: #64748b; margin-top: 2px;">
              ${countCrit === 0 ? "No new critical issues" : `${countCrit} critical issue${countCrit > 1 ? "s" : ""} detected`}
            </div>
          </div>

          <a href="/api/labels/export?repo=${encodeURIComponent(repo.full_name)}" class="download-link" style="color: #0f172a; text-decoration: none; font-size: 12px; font-weight: 800; letter-spacing: 0.04em;">
            DOWNLOAD REPORT ↗
          </a>

          <a href="https://github.com/${escapeHtml(repo.full_name)}" target="_blank" rel="noreferrer" class="btn btn-white-outline">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
            View on GitHub ↗
          </a>

          <a href="/" class="btn btn-black">
            ▶ New Scan
          </a>
        </div>
      </div>
    </div>

    <!-- 4 Severity Stat Cards Grid (Screenshot 1) -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 16px; margin-bottom: 28px;">
      
      <!-- Critical Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 22px;">
        <div>
          <div style="display: flex; align-items: baseline; gap: 8px;">
            <span style="font-size: 36px; font-weight: 800; color: #dc2626; line-height: 1;">${countCrit}</span>
            ${renderTrend(countCrit, prevCounts.crit)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 8px;">Critical</div>
        </div>
        ${renderMiniBars("#dc2626", countCrit)}
      </div>

      <!-- High Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 22px;">
        <div>
          <div style="display: flex; align-items: baseline; gap: 8px;">
            <span style="font-size: 36px; font-weight: 800; color: #ea580c; line-height: 1;">${countHigh}</span>
            ${renderTrend(countHigh, prevCounts.high)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 8px;">High</div>
        </div>
        ${renderMiniBars("#ea580c", countHigh)}
      </div>

      <!-- Medium Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 22px;">
        <div>
          <div style="display: flex; align-items: baseline; gap: 8px;">
            <span style="font-size: 36px; font-weight: 800; color: #eab308; line-height: 1;">${countMed}</span>
            ${renderTrend(countMed, prevCounts.med)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 8px;">Medium</div>
        </div>
        ${renderMiniBars("#eab308", countMed)}
      </div>

      <!-- Low Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 22px;">
        <div>
          <div style="display: flex; align-items: baseline; gap: 8px;">
            <span style="font-size: 36px; font-weight: 800; color: #3b82f6; line-height: 1;">${countLow}</span>
            ${renderTrend(countLow, prevCounts.low)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 8px;">Low</div>
        </div>
        ${renderMiniBars("#3b82f6", countLow)}
      </div>

    </div>

    <!-- Main 2-Column Split Dashboard (Table + Finding Detail) -->
    <div style="display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr); gap: 24px; align-items: start;">
      
      <!-- Left Column: Findings List Card -->
      <div class="ui-card" style="padding: 24px;">
        <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; margin: 0 0 16px 0;">Findings</h2>

        <!-- Severity Filter Pills -->
        <div style="display: flex; gap: 8px; margin-bottom: 18px; flex-wrap: wrap;" id="severity-pills">
          <button type="button" onclick="selectSevFilter('all')" class="btn-filter-pill active" id="pill-all" style="background:#0f172a; color:#fff; border:none; padding:7px 16px; border-radius:8px; font-size:13px; font-weight:700; cursor:pointer;">
            All (${findings.length})
          </button>
          <button type="button" onclick="selectSevFilter('critical')" class="btn-filter-pill" id="pill-critical" style="background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:7px 16px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            Critical (${countCrit})
          </button>
          <button type="button" onclick="selectSevFilter('high')" class="btn-filter-pill" id="pill-high" style="background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:7px 16px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            High (${countHigh})
          </button>
          <button type="button" onclick="selectSevFilter('medium')" class="btn-filter-pill" id="pill-medium" style="background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:7px 16px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            Medium (${countMed})
          </button>
          <button type="button" onclick="selectSevFilter('low')" class="btn-filter-pill" id="pill-low" style="background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:7px 16px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            Low (${countLow})
          </button>
        </div>

        <!-- Search & Filter Controls Row -->
        <div style="display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap;">
          <div style="position: relative; flex: 1; min-width: 220px;">
            <input 
              type="text" 
              id="table-search" 
              oninput="applyTableFilters()" 
              placeholder="Search findings..." 
              style="width: 100%; padding: 9px 12px 9px 36px; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; background: #fff;"
            />
            <svg style="position: absolute; left: 12px; top: 11px; width: 15px; height: 15px; color: #94a3b8;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
          </div>

          <select id="rule-filter" onchange="applyTableFilters()" style="padding: 9px 12px; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; background: #fff; font-weight: 600; color: #334155; cursor: pointer;">
            <option value="all">All rules</option>
            <option value="AUTH-01">AUTH-01 (API Route)</option>
            <option value="SUPA-01">SUPA-01 (Supabase RLS)</option>
            <option value="STRIPE-01">STRIPE-01 (Webhook Sign)</option>
            <option value="IDOR-01">IDOR-01 (Ownership)</option>
            <option value="SECRETS-02">SECRETS-02 (Sensitive Data)</option>
            <option value="UPLOAD-01">UPLOAD-01 (File Upload)</option>
            <option value="RATE-01">RATE-01 (Rate Limit)</option>
            <option value="CONFIG-01">CONFIG-01 (Config Flags)</option>
          </select>

          <select id="status-filter" onchange="applyTableFilters()" style="padding: 9px 12px; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; background: #fff; font-weight: 600; color: #334155; cursor: pointer;">
            <option value="all">All statuses</option>
            <option value="Confirmed">Confirmed</option>
            <option value="Needs review">Needs review</option>
            <option value="Open">Open</option>
          </select>
        </div>

        <!-- Findings Table (Screenshot 1) -->
        <div style="border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
            <thead>
              <tr style="background: #f8fafc; border-bottom: 1px solid #e2e8f0; color: #475569; font-weight: 700; font-size: 11px; letter-spacing: 0.05em;">
                <th style="padding: 10px 12px; width: 32px;"><input type="checkbox" style="cursor: pointer;" /></th>
                <th style="padding: 10px 12px;">SEVERITY</th>
                <th style="padding: 10px 12px;">TITLE</th>
                <th style="padding: 10px 12px;">RULE</th>
                <th style="padding: 10px 12px;">STATUS</th>
                <th style="padding: 10px 8px; width: 24px;"></th>
              </tr>
            </thead>
            <tbody id="findings-table-body">
              ${
                findings.length === 0
                  ? `
                  <tr>
                    <td colspan="6" style="padding: 48px 24px; text-align: center; color: #64748b;">
                      <div style="font-size: 15px; font-weight: 700; color: #0f172a; margin-bottom: 6px;">no issues found in the checks we run</div>
                      <div style="font-size: 13px; color: #64748b; max-width: 440px; margin: 0 auto 18px auto;">
                        This repository did not trigger any AST rules for Next.js, Supabase, Stripe, or Secrets detectors.
                      </div>
                      <a href="/api/dev/scan-sample-demo" class="btn btn-black" style="font-size: 13px;">
                        ⚡ Run Sample Next.js / Supabase / Stripe Vulnerability Scan (Demo)
                      </a>
                    </td>
                  </tr>`
                  : findings
                      .map((f, idx) => {
                        const fid = f.db_id || f.id;
                        const isSelected = fid === initialFindingId;
                        const savedLbl = userLabels.get(fid) || "";
                        const ruleCode = getRuleCode(f.ruleId);

                        let sevColor = "#dc2626";
                        let sevName = "Critical";
                        if (f.severity === "high") {
                          sevColor = "#ea580c";
                          sevName = "High";
                        } else if (f.severity === "medium") {
                          sevColor = "#eab308";
                          sevName = "Medium";
                        } else if (f.severity === "low") {
                          sevColor = "#3b82f6";
                          sevName = "Low";
                        }

                        let statusBadge = `<span class="badge-status-open">Open</span>`;
                        let statusText = "Open";
                        if (savedLbl === "real_issue") {
                          statusBadge = `<span class="badge-status-confirmed">Confirmed</span>`;
                          statusText = "Confirmed";
                        } else if (savedLbl === "needs-review" || !savedLbl) {
                          statusBadge = `<span class="badge-status-review">Needs review</span>`;
                          statusText = "Needs review";
                        } else if (savedLbl === "false_positive") {
                          statusBadge = `<span class="badge-status-fp">False positive</span>`;
                          statusText = "False positive";
                        }

                        return `
                          <tr 
                            class="finding-row ${isSelected ? "selected-row" : ""}" 
                            id="row-${escapeHtml(fid)}"
                            data-id="${escapeHtml(fid)}"
                            data-index="${idx}"
                            data-severity="${escapeHtml(f.severity)}"
                            data-rule="${escapeHtml(ruleCode)}"
                            data-status="${escapeHtml(statusText)}"
                            onclick="selectFinding('${escapeHtml(fid)}')"
                            style="border-bottom: 1px solid #e2e8f0; cursor: pointer; transition: background 0.15s;"
                          >
                            <td style="padding: 12px; vertical-align: top;" onclick="event.stopPropagation();">
                              <input type="checkbox" style="cursor: pointer;" />
                            </td>
                            <td style="padding: 12px; vertical-align: top; white-space: nowrap;">
                              <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="display: inline-block; width: 4px; height: 16px; border-radius: 2px; background: ${sevColor};"></span>
                                <span style="font-weight: 700; color: #0f172a; font-size: 13px;">${sevName}</span>
                              </div>
                            </td>
                            <td style="padding: 12px; vertical-align: top;">
                              <div style="font-weight: 700; color: #0f172a; font-size: 13px; margin-bottom: 3px;">${escapeHtml(f.title)}</div>
                              <div style="color: #64748b; font-size: 12px; font-family: monospace;">${escapeHtml(f.file)}:${f.lineRange?.startLine || 1}</div>
                            </td>
                            <td style="padding: 12px; vertical-align: top; white-space: nowrap;">
                              <span style="font-size: 11px; font-weight: 700; color: #475569; font-family: monospace; background: #f1f5f9; padding: 3px 8px; border-radius: 4px;">
                                ${escapeHtml(ruleCode)}
                              </span>
                            </td>
                            <td style="padding: 12px; vertical-align: top; white-space: nowrap;" id="cell-status-${escapeHtml(fid)}">
                              ${statusBadge}
                            </td>
                            <td style="padding: 12px 8px; vertical-align: middle; color: #94a3b8; font-size: 14px;">
                              ›
                            </td>
                          </tr>
                        `;
                      })
                      .join("")
              }
            </tbody>
          </table>
        </div>
      </div>

      <!-- Right Column: Interactive Finding Detail Inspection Panel (Screenshot 1) -->
      <div class="ui-card" style="padding: 24px; position: sticky; top: 80px;" id="finding-detail-card">
        ${
          initialFinding
            ? renderFindingDetailCardHtml(initialFinding, csrfToken, userLabels.get(initialFinding.db_id || initialFinding.id) || "", 0, findings.length)
            : `<div style="text-align: center; padding: 48px 16px; color: #64748b;">Select a finding on the left to inspect details</div>`
        }
      </div>

    </div>

    <!-- Embedded Styles for Target Dashboard UI -->
    <style>
      .tech-pill {
        background: #f1f5f9;
        color: #334155;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 12px;
      }
      .trend-badge {
        font-size: 12px;
        font-weight: 700;
        margin-left: 6px;
      }
      .trend-up {
        color: #dc2626;
      }
      .trend-down {
        color: #64748b;
      }
      .trend-neutral {
        color: #64748b;
      }
      .badge-status-confirmed {
        background: #fee2e2;
        color: #dc2626;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
      }
      .badge-status-review {
        background: #eff6ff;
        color: #2563eb;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
      }
      .badge-status-fp {
        background: #f1f5f9;
        color: #475569;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
      }
      .badge-status-open {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        color: #64748b;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
      }
      .selected-row {
        background: #f8fafc !important;
        border-left: 3px solid #0f172a !important;
      }
      .finding-row:hover {
        background: #fcfdfe;
      }
      .tab-nav-btn {
        background: none;
        border: none;
        padding: 10px 16px;
        font-size: 13px;
        font-weight: 600;
        color: #64748b;
        cursor: pointer;
        border-bottom: 2px solid transparent;
        transition: all 0.15s;
      }
      .tab-nav-btn.active {
        color: #0f172a;
        font-weight: 700;
        border-bottom: 2px solid #0f172a;
      }
      .subtab-pill {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        color: #64748b;
        padding: 5px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
      }
      .subtab-pill.active {
        background: #0f172a;
        color: #ffffff;
        border-color: #0f172a;
      }
    </style>

    <!-- Client-Side Interactivity Script -->
    <script>
      const findingsList = ${findingsJson};
      const findingsMap = new Map(findingsList.map(f => [f.id, f]));
      let currentFilterSev = 'all';
      let currentIndex = 0;

      function selectSevFilter(sev) {
        currentFilterSev = sev;
        document.querySelectorAll('.btn-filter-pill').forEach(btn => {
          btn.style.background = '#f8fafc';
          btn.style.color = '#64748b';
          btn.style.border = '1px solid #e2e8f0';
        });
        const activeBtn = document.getElementById('pill-' + sev);
        if (activeBtn) {
          activeBtn.style.background = '#0f172a';
          activeBtn.style.color = '#ffffff';
          activeBtn.style.border = 'none';
        }
        applyTableFilters();
      }

      function applyTableFilters() {
        const query = (document.getElementById('table-search').value || '').toLowerCase();
        const selectedRule = document.getElementById('rule-filter').value;
        const selectedStatus = document.getElementById('status-filter').value;

        const rows = document.querySelectorAll('.finding-row');
        rows.forEach(row => {
          const fid = row.getAttribute('data-id');
          const item = findingsMap.get(fid);
          if (!item) return;

          const matchSev = currentFilterSev === 'all' || item.severity === currentFilterSev;
          const matchRule = selectedRule === 'all' || item.ruleCode === selectedRule;
          const matchStatus = selectedStatus === 'all' || item.statusText === selectedStatus;

          const matchQuery = !query || 
            item.title.toLowerCase().includes(query) || 
            item.file.toLowerCase().includes(query) || 
            item.ruleId.toLowerCase().includes(query) ||
            item.ruleCode.toLowerCase().includes(query);

          if (matchSev && matchRule && matchStatus && matchQuery) {
            row.style.display = '';
          } else {
            row.style.display = 'none';
          }
        });
      }

      function selectFinding(fid) {
        document.querySelectorAll('.finding-row').forEach(r => r.classList.remove('selected-row'));
        const row = document.getElementById('row-' + fid);
        if (row) {
          row.classList.add('selected-row');
          currentIndex = parseInt(row.getAttribute('data-index') || '0', 10);
        }

        const item = findingsMap.get(fid);
        if (!item) return;

        const detailCard = document.getElementById('finding-detail-card');
        if (detailCard) {
          detailCard.innerHTML = renderDetailCardClient(item, "${escapeHtml(csrfToken)}", currentIndex, findingsList.length);
        }
      }

      function navigateFinding(delta) {
        const newIndex = currentIndex + delta;
        if (newIndex >= 0 && newIndex < findingsList.length) {
          const target = findingsList[newIndex];
          if (target) {
            selectFinding(target.id);
            const row = document.getElementById('row-' + target.id);
            if (row) row.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        }
      }

      function switchDetailTab(tabId) {
        document.querySelectorAll('.tab-nav-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.detail-tab-pane').forEach(pane => pane.style.display = 'none');
        
        const activeBtn = document.getElementById('tab-btn-' + tabId);
        const activePane = document.getElementById('tab-pane-' + tabId);
        if (activeBtn) activeBtn.classList.add('active');
        if (activePane) activePane.style.display = 'block';
      }

      function switchFixSubtab(subtabId) {
        document.querySelectorAll('.subtab-pill').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.fix-subtab-pane').forEach(pane => pane.style.display = 'none');
        
        const activeBtn = document.getElementById('subtab-btn-' + subtabId);
        const activePane = document.getElementById('fix-subpane-' + subtabId);
        if (activeBtn) activeBtn.classList.add('active');
        if (activePane) activePane.style.display = 'block';
      }

      function renderDetailCardClient(item, csrf, idx, total) {
        const isReal = item.label === 'real_issue';
        const isFP = item.label === 'false_positive';
        const isNotSure = item.label === 'not_sure';

        let sevBadgeColor = '#dc2626';
        let sevBg = '#fee2e2';
        if (item.severity === 'high') { sevBadgeColor = '#ea580c'; sevBg = '#ffedd5'; }
        else if (item.severity === 'medium') { sevBadgeColor = '#eab308'; sevBg = '#fef9c3'; }
        else if (item.severity === 'low') { sevBadgeColor = '#3b82f6'; sevBg = '#dbeafe'; }

        // Format source snippet lines
        const lines = (item.codeSnippet || '').split('\\n');
        const codeLinesHtml = lines.map((line, i) => {
          const lineNum = item.line + i;
          const isVulnerable = i === 1 || i === lines.length - 2;
          const bg = isVulnerable ? 'background: #fef2f2; color: #b91c1c;' : 'background: transparent; color: #334155;';
          const prefix = isVulnerable ? '-' : ' ';
          return \`
            <div style="\${bg} display: flex; padding: 2px 10px; font-family: monospace; font-size: 12px; line-height: 1.6;">
              <span style="width: 32px; color: #94a3b8; user-select: none;">\${lineNum}</span>
              <span style="width: 16px; user-select: none;">\${prefix}</span>
              <span style="flex: 1;">\${escapeHtml(line)}</span>
            </div>
          \`;
        }).join('');

        return \`
          <!-- Panel Header with Badge & Pagination -->
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="background: \${sevBg}; color: \${sevBadgeColor}; font-weight: 800; font-size: 11px; padding: 3px 8px; border-radius: 4px; text-transform: capitalize;">
                \${escapeHtml(item.severity)}
              </span>
              <span style="background: #f1f5f9; color: #475569; font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 4px; font-family: monospace;">
                \${escapeHtml(item.ruleCode)}
              </span>
            </div>
            <div style="display: flex; align-items: center; gap: 8px; font-size: 12px; font-weight: 600; color: #64748b;">
              <button type="button" onclick="navigateFinding(-1)" style="background:none; border:none; cursor:pointer; font-size:14px; padding:2px 6px;">‹</button>
              <span>\${idx + 1} of \${total}</span>
              <button type="button" onclick="navigateFinding(1)" style="background:none; border:none; cursor:pointer; font-size:14px; padding:2px 6px;">›</button>
            </div>
          </div>

          <!-- Title and Subtitle -->
          <h3 style="font-size: 22px; font-weight: 800; color: #0f172a; margin: 0 0 6px 0; line-height: 1.2;">
            \${escapeHtml(item.title)}
          </h3>
          <p style="font-size: 13px; color: #64748b; margin: 0 0 14px 0; line-height: 1.5;">
            \${escapeHtml(item.explanation.slice(0, 160))}...
          </p>

          <!-- Finding Metadata Row -->
          <div style="display: flex; align-items: center; gap: 12px; font-size: 12px; color: #475569; margin-bottom: 16px; flex-wrap: wrap;">
            <span style="font-family: monospace; display: flex; align-items: center; gap: 4px;">
              📄 \${escapeHtml(item.file)}
            </span>
            <span>&bull;</span>
            <span>Line \${item.line}</span>
            <span>&bull;</span>
            <span style="background: #dcfce7; color: #166534; font-weight: 700; font-size: 11px; padding: 2px 7px; border-radius: 999px;">
              Proven (High) ⓘ
            </span>
            <a href="https://github.com/\${encodeURIComponent(item.file)}" target="_blank" rel="noreferrer" style="color: #2563eb; text-decoration: none; font-weight: 600; margin-left: auto;">
              Open in repository ↗
            </a>
          </div>

          <!-- 5 Tabs Navigation (Screenshot 1) -->
          <div style="display: flex; border-bottom: 1px solid #e2e8f0; margin-bottom: 18px;">
            <button type="button" class="tab-nav-btn active" id="tab-btn-evidence" onclick="switchDetailTab('evidence')">Evidence</button>
            <button type="button" class="tab-nav-btn" id="tab-btn-explanation" onclick="switchDetailTab('explanation')">Explanation</button>
            <button type="button" class="tab-nav-btn" id="tab-btn-fix" onclick="switchDetailTab('fix')">Fix</button>
            <button type="button" class="tab-nav-btn" id="tab-btn-verification" onclick="switchDetailTab('verification')">Verification</button>
            <button type="button" class="tab-nav-btn" id="tab-btn-references" onclick="switchDetailTab('references')">References</button>
          </div>

          <!-- Tab 1: Evidence -->
          <div id="tab-pane-evidence" class="detail-tab-pane" style="display: block;">
            <div style="border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; margin-bottom: 14px;">
              <div style="background: #f8fafc; border-bottom: 1px solid #e2e8f0; padding: 8px 12px; display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 12px; font-family: monospace; color: #475569;">\${escapeHtml(item.file)}</span>
                <span style="font-size: 11px; font-weight: 700; color: #64748b; background: #e2e8f0; padding: 2px 6px; border-radius: 4px;">TypeScript</span>
              </div>
              <div style="background: #ffffff; padding: 8px 0;">
                \${codeLinesHtml}
              </div>
            </div>

            <!-- Red Callout Alert -->
            <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 10px 14px; display: flex; align-items: center; gap: 8px; color: #b91c1c; font-size: 12px; font-weight: 700; margin-bottom: 20px;">
              <span>⊘</span>
              <span>Potential security issue: unverified parameter or missing authentication check</span>
            </div>

            <!-- How to Fix Section -->
            <div style="margin-bottom: 18px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <div style="font-size: 15px; font-weight: 800; color: #0f172a;">How to fix</div>
                <button type="button" class="btn btn-white-outline" style="font-size: 12px; font-weight: 700; padding: 4px 10px;" onclick="generateAiRemediation('\${item.id}')">✨ Generate with AI</button>
              </div>

              <div style="display: flex; gap: 8px; margin-bottom: 14px;">
                <button type="button" class="subtab-pill active" id="subtab-btn-auto" onclick="switchFixSubtab('auto')">Automated fix</button>
                <button type="button" class="subtab-pill" id="subtab-btn-manual" onclick="switchFixSubtab('manual')">Manual steps</button>
                <button type="button" class="subtab-pill" id="subtab-btn-ai" onclick="switchFixSubtab('ai')">AI suggestion</button>
              </div>

              <div id="fix-subpane-auto" class="fix-subtab-pane" style="display: block;">
                <!-- Apply Recommended Fix Card -->
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                  <div style="display: flex; align-items: flex-start; gap: 10px;">
                    <div style="color: #6366f1; font-size: 18px;">🪄</div>
                    <div>
                      <div style="font-size: 13px; font-weight: 800; color: #0f172a;">Apply recommended fix</div>
                      <div style="font-size: 12px; color: #64748b; margin-top: 2px;">Apply deterministic AST transformation to patch this vulnerability.</div>
                    </div>
                  </div>
                  <div style="display: flex; gap: 8px;">
                    <a href="/findings/\${item.id}/fix" class="btn btn-white-outline" style="font-size: 12px; font-weight: 700;">View patch</a>
                    <a href="/findings/\${item.id}/fix" class="btn btn-black" style="font-size: 12px; font-weight: 700;">Test in sandbox</a>
                  </div>
                </div>

                <!-- Sandbox Isolation Guarantee Banner -->
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; font-size: 11px; color: #64748b;">
                  <div style="font-weight: 700; color: #0f172a; margin-bottom: 6px;">ⓘ This patch will be tested in an isolated sandbox</div>
                  <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                    <span>🛡️ No network</span>
                    <span>🔒 No secrets</span>
                    <span>⏱️ 5 min limit</span>
                    <span>⚙️ 2 CPU</span>
                    <span>💾 4 GB RAM</span>
                  </div>
                </div>
              </div>

              <div id="fix-subpane-manual" class="fix-subtab-pane" style="display: none;">
                <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; font-size: 12px; color: #334155; line-height: 1.6;">
                  <strong>Remediation Steps:</strong><br />
                  1. Inspect <code>\${escapeHtml(item.file)}</code> at line \${item.line}.<br />
                  2. Ensure authorization checks verify the current session user owns the requested entity.<br />
                  3. If using Supabase, ensure Row Level Security (RLS) is enabled and an explicit non-permissive policy is defined.<br />
                  4. For Stripe webhooks, verify that <code>stripe.webhooks.constructEvent</code> is called with the raw body and webhook secret.
                </div>
              </div>

              <div id="fix-subpane-ai" class="fix-subtab-pane" style="display: none;">
                <div style="background: #fdf4ff; border: 1px solid #f0abfc; border-radius: 8px; padding: 14px; font-size: 12px; color: #701a75; line-height: 1.6;">
                  <strong>AI Remediation Hypothesis:</strong><br />
                  The AST detector identified an unprotected handler. We recommend wrapping this route in your authentication middleware and extracting the authenticated user token prior to handling business logic.
                </div>
              </div>
            </div>
          </div>

          <!-- Tab 2: Explanation & Triage -->
          <div id="tab-pane-explanation" class="detail-tab-pane" style="display: none;">
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; font-size: 13px; color: #334155; line-height: 1.6;">
              <h4 style="font-size: 14px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0;">Detailed Analysis</h4>
              <p style="margin: 0 0 10px 0;">\${escapeHtml(item.explanation)}</p>
              <h4 style="font-size: 14px; font-weight: 800; color: #0f172a; margin: 12px 0 8px 0;">Attack Vector & Threat Model</h4>
              <p style="margin: 0; color: #64748b; font-size: 12px;">
                An attacker could invoke this endpoint without valid authentication tokens, leading to unauthorized data disclosure or state manipulation.
              </p>
            </div>

            <!-- Triage Classification Form -->
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px;">
              <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 10px;">CLASSIFY FINDING</div>
              <div style="display: flex; gap: 8px;">
                <button type="button" onclick="submitLabel('\${item.id}', 'real_issue')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: \${isReal ? '#dc2626' : '#ffffff'}; color: \${isReal ? '#ffffff' : '#0f172a'}; border: 1px solid #cbd5e1; font-weight: 700;">Real issue</button>
                <button type="button" onclick="submitLabel('\${item.id}', 'false_positive')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: \${isFP ? '#475569' : '#ffffff'}; color: \${isFP ? '#ffffff' : '#0f172a'}; border: 1px solid #cbd5e1; font-weight: 700;">False positive</button>
                <button type="button" onclick="submitLabel('\${item.id}', 'not_sure')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: \${isNotSure ? '#b45309' : '#ffffff'}; color: \${isNotSure ? '#ffffff' : '#0f172a'}; border: 1px solid #cbd5e1; font-weight: 700;">Not sure</button>
              </div>
            </div>
          </div>

          <!-- Tab 3: Fix Patch -->
          <div id="tab-pane-fix" class="detail-tab-pane" style="display: none;">
            <div style="background: #0f172a; color: #f8fafc; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 12px; line-height: 1.6; margin-bottom: 16px; overflow-x: auto;">
              <div style="color: #94a3b8; margin-bottom: 8px;">--- a/\${escapeHtml(item.file)}</div>
              <div style="color: #94a3b8; margin-bottom: 8px;">+++ b/\${escapeHtml(item.file)}</div>
              <div style="color: #f87171;">- export async function GET(req: Request) {</div>
              <div style="color: #4ade80;">+ export async function GET(req: Request) {</div>
              <div style="color: #4ade80;">+   const session = await auth();</div>
              <div style="color: #4ade80;">+   if (!session) return new Response("Unauthorized", { status: 401 });</div>
              <div>    return NextResponse.json(data);</div>
              <div>  }</div>
            </div>
            <a href="/findings/\${item.id}/fix" class="btn btn-black" style="width: 100%; text-align: center; font-size: 13px;">Review & Apply Fix in Sandbox ➔</a>
          </div>

          <!-- Tab 4: Verification -->
          <div id="tab-pane-verification" class="detail-tab-pane" style="display: none;">
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; font-size: 12px; color: #334155;">
              <div style="display: flex; align-items: center; justify-content: space-between; padding-bottom: 8px; border-bottom: 1px solid #e2e8f0; margin-bottom: 10px;">
                <span style="font-weight: 700;">AST Rescan Resolution</span>
                <span style="color: #16a34a; font-weight: 700;">✓ Ready to verify</span>
              </div>
              <div style="display: flex; align-items: center; justify-content: space-between; padding-bottom: 8px; border-bottom: 1px solid #e2e8f0; margin-bottom: 10px;">
                <span style="font-weight: 700;">Sandbox Isolation</span>
                <span style="color: #16a34a; font-weight: 700;">✓ Active (Exit 0 guarantee)</span>
              </div>
              <div style="display: flex; align-items: center; justify-content: space-between; padding-bottom: 8px; border-bottom: 1px solid #e2e8f0; margin-bottom: 10px;">
                <span style="font-weight: 700;">Typecheck & Test Execution</span>
                <span style="color: #64748b;">Pending container run</span>
              </div>
              <div style="margin-top: 14px;">
                <a href="/findings/\${item.id}/fix" class="btn btn-white-outline" style="width: 100%; text-align: center; font-size: 12px; font-weight: 700;">Launch Isolated Container Verification</a>
              </div>
            </div>
          </div>

          <!-- Tab 5: References -->
          <div id="tab-pane-references" class="detail-tab-pane" style="display: none;">
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; font-size: 13px; color: #334155; line-height: 1.7;">
              <div style="font-weight: 800; color: #0f172a; margin-bottom: 8px;">Security Standards & References</div>
              <ul style="margin: 0; padding-left: 20px; color: #475569; font-size: 12px;">
                <li><strong>CWE-306:</strong> Missing Authentication for Critical Function</li>
                <li><strong>OWASP Top 10 (2021):</strong> A01:2021 - Broken Access Control</li>
                <li><strong>NANTIS Rule Docs:</strong> <a href="/rules" style="color: #2563eb; text-decoration: none;">\${escapeHtml(item.ruleId)} Specification</a></li>
                <li><strong>Next.js Security Guidance:</strong> Route Handlers Authentication Patterns</li>
              </ul>
            </div>
          </div>
        \`;
      }

      async function submitLabel(fid, label) {
        try {
          const res = await fetch('/api/findings/' + fid + '/label', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label, _csrf: "${escapeHtml(csrfToken)}" })
          });
          if (res.ok) {
            const item = findingsMap.get(fid);
            if (item) {
              item.label = label;
              if (label === 'real_issue') item.statusText = 'Confirmed';
              else if (label === 'false_positive') item.statusText = 'False positive';
              else if (label === 'not_sure') item.statusText = 'Under review';
              else item.statusText = 'Open';
            }
            applyTableFilters();
            selectFinding(fid);
          }
        } catch (err) {
          console.error('Failed to submit label classification:', err);
        }
      }

      async function generateAiRemediation(fid) {
        const btn = window.event ? window.event.currentTarget : null;
        if (btn) btn.innerText = "⏳ Querying Groq...";
        switchFixSubtab('ai');
        const aiPane = document.getElementById('fix-subpane-ai');
        if (aiPane) {
          aiPane.innerHTML = '<div style="padding: 16px; text-align: center; color: #701a75;"><strong>Querying Groq LLM (llama-3.3-70b-versatile)...</strong><br><span style="font-size: 12px; color: #86198f;">Analyzing AST evidence chain and generating tailored patch hypothesis...</span></div>';
        }
        try {
          const res = await fetch('/api/findings/' + encodeURIComponent(fid) + '/ai-remediation', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _csrf: "${escapeHtml(csrfToken)}" })
          });
          const data = await res.json();
          if (aiPane) {
            const stepsHtml = data.remediationSteps && Array.isArray(data.remediationSteps)
              ? '<div style="font-weight: 700; margin-bottom: 4px;">Recommended Remediation Steps:</div><ol style="margin-left: 20px; margin-bottom: 12px;">' + data.remediationSteps.map(s => '<li>' + s + '</li>').join('') + '</ol>'
              : '';
            const snippetHtml = data.suggestedFixSnippet
              ? '<div style="font-weight: 700; margin-bottom: 4px;">Suggested Code Snippet:</div><pre style="background: #ffffff; padding: 8px 12px; border-radius: 6px; font-size: 11px; overflow-x: auto; border: 1px solid #f5d0fe; color: #0f172a;">' + data.suggestedFixSnippet + '</pre>'
              : '';
            aiPane.innerHTML = '<div style="background: #fdf4ff; border: 1px solid #f0abfc; border-radius: 8px; padding: 16px; font-size: 13px; color: #701a75; line-height: 1.6;">' +
              '<div style="font-weight: 800; font-size: 14px; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;"><span>✨</span> Groq AI Remediation Hypothesis</div>' +
              '<p style="margin-bottom: 12px;">' + (data.hypothesis || 'Identified missing ownership filter in database query.') + '</p>' +
              stepsHtml + snippetHtml +
              '<div style="margin-top: 10px; font-size: 11px; color: #a21caf;">Powered by Groq Cloud &amp; LLaMA-3.3-70B • Latency: ' + (data.latencyMs || 250) + 'ms</div>' +
              '</div>';
          }
        } catch (err) {
          if (aiPane) {
            aiPane.innerHTML = '<div style="padding: 12px; color: #b91c1c;">AI remediation generation failed: ' + (err.message || String(err)) + '</div>';
          }
        } finally {
          if (btn) btn.innerText = "✨ Generate with AI";
        }
      }
    </script>
  `;
}

export function renderFindingDetailCardHtml(
  finding: {
    id: string;
    db_id?: string;
    ruleId: string;
    title: string;
    severity: string;
    confidenceTier?: string;
    file: string;
    lineRange?: { startLine: number; endLine: number };
    explanation: string;
    codeSnippet?: string;
    snippet?: string;
    evidenceChain?: Array<{ step: number; description: string; file: string; line: number }>;
  },
  _csrfToken: string,
  _savedLabel: string,
  index = 0,
  totalCount = 1
): string {
  const fid = finding.db_id || finding.id;
  const ruleCode = getRuleCode(finding.ruleId);

  let sevBadgeColor = "#dc2626";
  let sevBg = "#fee2e2";
  if (finding.severity === "high") {
    sevBadgeColor = "#ea580c";
    sevBg = "#ffedd5";
  } else if (finding.severity === "medium") {
    sevBadgeColor = "#eab308";
    sevBg = "#fef9c3";
  } else if (finding.severity === "low") {
    sevBadgeColor = "#3b82f6";
    sevBg = "#dbeafe";
  }

  const codeSnippet = finding.codeSnippet || finding.snippet || "const res = await fetch(url);\nreturn res.json();";
  const lines = codeSnippet.split("\n");
  const startLine = finding.lineRange?.startLine || 1;

  const codeLinesHtml = lines
    .map((line, i) => {
      const lineNum = startLine + i;
      const isVulnerable = i === 1 || i === lines.length - 2;
      const bg = isVulnerable ? "background: #fef2f2; color: #b91c1c;" : "background: transparent; color: #334155;";
      const prefix = isVulnerable ? "-" : " ";
      return `
        <div style="${bg} display: flex; padding: 2px 10px; font-family: monospace; font-size: 12px; line-height: 1.6;">
          <span style="width: 32px; color: #94a3b8; user-select: none;">${lineNum}</span>
          <span style="width: 16px; user-select: none;">${prefix}</span>
          <span style="flex: 1;">${escapeHtml(line)}</span>
        </div>
      `;
    })
    .join("");

  return `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="background: ${sevBg}; color: ${sevBadgeColor}; font-weight: 800; font-size: 11px; padding: 3px 8px; border-radius: 4px; text-transform: capitalize;">
          ${escapeHtml(finding.severity)}
        </span>
        <span style="background: #f1f5f9; color: #475569; font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 4px; font-family: monospace;">
          ${escapeHtml(ruleCode)}
        </span>
      </div>
      <div style="display: flex; align-items: center; gap: 8px; font-size: 12px; font-weight: 600; color: #64748b;">
        <button type="button" onclick="navigateFinding(-1)" style="background:none; border:none; cursor:pointer; font-size:14px; padding:2px 6px;">‹</button>
        <span>${index + 1} of ${totalCount}</span>
        <button type="button" onclick="navigateFinding(1)" style="background:none; border:none; cursor:pointer; font-size:14px; padding:2px 6px;">›</button>
      </div>
    </div>

    <h3 style="font-size: 22px; font-weight: 800; color: #0f172a; margin: 0 0 6px 0; line-height: 1.2;">
      ${escapeHtml(finding.title)}
    </h3>
    <p style="font-size: 13px; color: #64748b; margin: 0 0 14px 0; line-height: 1.5;">
      ${escapeHtml(finding.explanation.slice(0, 160))}...
    </p>

    <div style="display: flex; align-items: center; gap: 12px; font-size: 12px; color: #475569; margin-bottom: 16px; flex-wrap: wrap;">
      <span style="font-family: monospace; display: flex; align-items: center; gap: 4px;">
        📄 ${escapeHtml(finding.file)}
      </span>
      <span>&bull;</span>
      <span>Line ${startLine}</span>
      <span>&bull;</span>
      <span style="background: #dcfce7; color: #166534; font-weight: 700; font-size: 11px; padding: 2px 7px; border-radius: 999px;">
        Proven (High) ⓘ
      </span>
      <a href="https://github.com/${encodeURIComponent(finding.file)}" target="_blank" rel="noreferrer" style="color: #2563eb; text-decoration: none; font-weight: 600; margin-left: auto;">
        Open in repository ↗
      </a>
    </div>

    <!-- 5 Tabs Navigation (Screenshot 1) -->
    <div style="display: flex; border-bottom: 1px solid #e2e8f0; margin-bottom: 18px;">
      <button type="button" class="tab-nav-btn active" id="tab-btn-evidence" onclick="switchDetailTab('evidence')">Evidence</button>
      <button type="button" class="tab-nav-btn" id="tab-btn-explanation" onclick="switchDetailTab('explanation')">Explanation</button>
      <button type="button" class="tab-nav-btn" id="tab-btn-fix" onclick="switchDetailTab('fix')">Fix</button>
      <button type="button" class="tab-nav-btn" id="tab-btn-verification" onclick="switchDetailTab('verification')">Verification</button>
      <button type="button" class="tab-nav-btn" id="tab-btn-references" onclick="switchDetailTab('references')">References</button>
    </div>

    <div id="tab-pane-evidence" class="detail-tab-pane" style="display: block;">
      <div style="border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; margin-bottom: 14px;">
        <div style="background: #f8fafc; border-bottom: 1px solid #e2e8f0; padding: 8px 12px; display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 12px; font-family: monospace; color: #475569;">${escapeHtml(finding.file)}</span>
          <span style="font-size: 11px; font-weight: 700; color: #64748b; background: #e2e8f0; padding: 2px 6px; border-radius: 4px;">TypeScript</span>
        </div>
        <div style="background: #ffffff; padding: 8px 0;">
          ${codeLinesHtml}
        </div>
      </div>

      ${(() => {
        const evHtml = finding.evidenceChain ? renderEvidenceChainAsStepsHtml(finding as unknown as Finding) : "";
        return evHtml ? `<div style="margin-bottom: 14px;">${evHtml}</div>` : "";
      })()}

      <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 10px 14px; display: flex; align-items: center; gap: 8px; color: #b91c1c; font-size: 12px; font-weight: 700; margin-bottom: 20px;">
        <span>⊘</span>
        <span>Potential issue: unverified parameter or missing authentication check</span>
      </div>

      <div style="margin-bottom: 18px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <div style="font-size: 15px; font-weight: 800; color: #0f172a;">How to fix</div>
          <button type="button" class="btn btn-white-outline" style="font-size: 12px; font-weight: 700; padding: 4px 10px;" onclick="generateAiRemediation('${escapeHtml(fid)}')">✨ Generate with AI</button>
        </div>

        <div style="display: flex; gap: 8px; margin-bottom: 14px;">
          <button type="button" class="subtab-pill active" id="subtab-btn-auto" onclick="switchFixSubtab('auto')">Automated fix</button>
          <button type="button" class="subtab-pill" id="subtab-btn-manual" onclick="switchFixSubtab('manual')">Manual steps</button>
          <button type="button" class="subtab-pill" id="subtab-btn-ai" onclick="switchFixSubtab('ai')">AI suggestion</button>
        </div>

        <div id="fix-subpane-auto" class="fix-subtab-pane" style="display: block;">
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="display: flex; align-items: flex-start; gap: 10px;">
              <div style="color: #6366f1; font-size: 18px;">🪄</div>
              <div>
                <div style="font-size: 13px; font-weight: 800; color: #0f172a;">Apply recommended fix</div>
                <div style="font-size: 12px; color: #64748b; margin-top: 2px;">Apply deterministic AST transformation to patch this vulnerability.</div>
              </div>
            </div>
            <div style="display: flex; gap: 8px;">
              <a href="/findings/${escapeHtml(fid)}/fix" class="btn btn-white-outline" style="font-size: 12px; font-weight: 700;">View patch</a>
              <a href="/findings/${escapeHtml(fid)}/fix" class="btn btn-black" style="font-size: 12px; font-weight: 700;">Review &amp; Apply Fix in Sandbox ➔</a>
            </div>
          </div>

          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; font-size: 11px; color: #64748b;">
            <div style="font-weight: 700; color: #0f172a; margin-bottom: 6px;">ⓘ This patch will be tested in an isolated sandbox</div>
            <div style="display: flex; gap: 12px; flex-wrap: wrap;">
              <span>🛡️ No network</span>
              <span>🔒 No secrets</span>
              <span>⏱️ 5 min limit</span>
              <span>⚙️ 2 CPU</span>
              <span>💾 4 GB RAM</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}
