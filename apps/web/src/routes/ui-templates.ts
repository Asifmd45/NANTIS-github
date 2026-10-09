import { RequestContext } from "./api-routes.js";

/**
 * Escapes HTML characters to protect against XSS injection attacks.
 */
export function escapeHtml(str: unknown): string {
  if (str === null || str === undefined) return "";
  const s = String(str);
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * In-memory CSRF token store per session
 */
const csrfTokens = new Map<string, string>();

export function getOrCreateCsrfToken(userId: string): string {
  if (!csrfTokens.has(userId)) {
    const token = crypto.randomUUID();
    csrfTokens.set(userId, token);
  }
  return csrfTokens.get(userId)!;
}

export function validateCsrfToken(req: RequestContext, userId: string): boolean {
  if (!userId) return false;
  const expected = csrfTokens.get(userId);
  if (!expected) return false;

  let tokenFromReq = "";
  if (typeof req.body === "object" && req.body !== null && "_csrf" in req.body) {
    tokenFromReq = String((req.body as Record<string, unknown>)._csrf);
  } else if (typeof req.body === "string" && req.body.length > 0) {
    const params = new URLSearchParams(req.body);
    tokenFromReq = params.get("_csrf") || "";
  } else if (req.headers && req.headers["x-csrf-token"]) {
    tokenFromReq = req.headers["x-csrf-token"];
  }

  return tokenFromReq === expected;
}

export function getDefaultHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
  return {
    "Content-Type": "text/html; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';",
    ...extraHeaders,
  };
}

export const BASE_CSS = `
  :root {
    --bg-main: #f8fafc;
    --bg-surface: #ffffff;
    --border-color: #e2e8f0;
    --border-hover: #cbd5e1;
    --text-primary: #0f172a;
    --text-secondary: #475569;
    --text-muted: #64748b;
    --text-dim: #94a3b8;
    --accent-dark: #0f172a;
    --accent-dark-hover: #1e293b;
    
    --color-critical: #dc2626;
    --color-high: #ea580c;
    --color-medium: #d97706;
    --color-low: #2563eb;
    
    --tier-proven-bg: #f3e8ff;
    --tier-proven-text: #7e22ce;
    --tier-proven-border: #e9d5ff;
    
    --tier-likely-bg: #ffedd5;
    --tier-likely-text: #c2410c;
    --tier-likely-border: #fed7aa;
    
    --tier-review-bg: #fee2e2;
    --tier-review-text: #b91c1c;
    --tier-review-border: #fca5a5;
    
    --tier-hygiene-bg: #d1fae5;
    --tier-hygiene-text: #047857;
    --tier-hygiene-border: #a7f3d0;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    line-height: 1.5;
    min-height: 100vh;
    display: flex;
  }

  /* App Sidebar Layout */
  .app-sidebar {
    width: 240px;
    min-width: 240px;
    background: #ffffff;
    border-right: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: 28px 18px;
    position: sticky;
    top: 0;
    height: 100vh;
    z-index: 50;
  }

  .app-logo {
    display: block;
    text-decoration: none;
    margin-bottom: 32px;
    padding-left: 6px;
  }

  .app-logo-title {
    font-size: 24px;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.03em;
    line-height: 1.1;
    font-family: Inter, sans-serif;
  }

  .app-logo-tagline {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.12em;
    color: #64748b;
    text-transform: uppercase;
    margin-top: 4px;
  }

  .nav-menu {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 14px;
    border-radius: 8px;
    color: #64748b;
    text-decoration: none;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    transition: all 0.15s ease;
  }

  .nav-item svg {
    width: 18px;
    height: 18px;
    stroke: currentColor;
    stroke-width: 2;
    fill: none;
    flex-shrink: 0;
  }

  .nav-item:hover {
    background: #f8fafc;
    color: #0f172a;
  }

  .nav-item.active {
    background: #f1f5f9;
    color: #0f172a;
  }

  /* Plan Card at bottom of sidebar */
  .sidebar-plan-card {
    background: #ffffff;
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02);
  }

  .plan-card-title {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
    color: #64748b;
    text-transform: uppercase;
  }

  .plan-card-stat {
    font-size: 24px;
    font-weight: 800;
    color: #0f172a;
    margin-top: 4px;
    line-height: 1.2;
  }

  .plan-card-subtext {
    font-size: 12px;
    color: #64748b;
    margin-bottom: 12px;
  }

  .plan-progress-bar {
    height: 4px;
    background: #e2e8f0;
    border-radius: 999px;
    overflow: hidden;
    margin-bottom: 14px;
  }

  .plan-progress-fill {
    height: 100%;
    background: #0f172a;
    width: 20%;
  }

  .btn-upgrade-disabled {
    width: 100%;
    background: #0f172a;
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
    font-weight: 600;
    cursor: not-allowed;
    opacity: 0.6;
    text-align: center;
  }

  .sidebar-footer-links {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-left: 6px;
  }

  .sidebar-footer-links a {
    color: #64748b;
    text-decoration: none;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .sidebar-footer-links a:hover {
    color: #0f172a;
  }

  /* Main Wrapper */
  .main-wrapper {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  /* Top Header */
  .top-header {
    height: 64px;
    background: #ffffff;
    border-bottom: 1px solid var(--border-color);
    padding: 0 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .repo-selector {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #ffffff;
    border: 1px solid var(--border-color);
    padding: 6px 14px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    color: #0f172a;
    cursor: pointer;
  }

  .search-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    background: #f8fafc;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 8px 14px;
    width: 380px;
    font-size: 13px;
    color: #64748b;
  }

  .search-bar input {
    border: none;
    background: transparent;
    outline: none;
    font-size: 13px;
    color: #0f172a;
    width: 100%;
  }

  .search-shortcut {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 11px;
    font-weight: 600;
    color: #64748b;
  }

  .user-avatar-badge {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: #e2e8f0;
    color: #0f172a;
    font-weight: 700;
    font-size: 13px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }

  /* Dev Environment Banner */
  .top-dev-banner {
    background: #fffbebfb;
    border-bottom: 1px solid #fef3c7;
    color: #b45309;
    padding: 6px 32px;
    font-size: 12px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .content-container {
    padding: 32px;
    max-width: 1400px;
    margin: 0 auto;
    width: 100%;
  }

  /* Reusable Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 600;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    text-decoration: none;
    transition: all 0.15s ease;
  }

  .btn-black {
    background-color: #0f172a;
    color: #ffffff;
  }
  .btn-black:hover {
    background-color: #1e293b;
  }

  .btn-white-outline {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    color: #0f172a;
  }
  .btn-white-outline:hover {
    background-color: #f8fafc;
    border-color: #cbd5e1;
  }

  .btn-disabled {
    background-color: #e2e8f0;
    color: #94a3b8;
    cursor: not-allowed;
  }

  /* Chip Badges */
  .chip-tier {
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    text-transform: capitalize;
  }
  .chip-proven { background: var(--tier-proven-bg); color: var(--tier-proven-text); border: 1px solid var(--tier-proven-border); }
  .chip-likely { background: var(--tier-likely-bg); color: var(--tier-likely-text); border: 1px solid var(--tier-likely-border); }
  .chip-review { background: var(--tier-review-bg); color: var(--tier-review-text); border: 1px solid var(--tier-review-border); }
  .chip-hygiene { background: var(--tier-hygiene-bg); color: var(--tier-hygiene-text); border: 1px solid var(--tier-hygiene-border); }

  /* Utility Cards */
  .ui-card {
    background: #ffffff;
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02);
  }
`;

export function renderPageLayout(options: {
  title: string;
  userLogin?: string;
  csrfToken?: string;
  content: string;
  activeNav?: "dashboard" | "repositories" | "scans" | "findings" | "fixes" | "pull-requests" | "settings";
  repoName?: string;
  userRepos?: { id: string; name: string; full_name: string }[];
  scansCount?: number;
}): string {
  const {
    title,
    userLogin,
    content,
    activeNav = "scans",
    repoName,
    userRepos = [],
    scansCount: _scansCount = 0,
  } = options;

  const displayRepo = repoName || (userRepos.length > 0 ? userRepos[0].full_name : "No repositories yet");
  const isNavActive = (name: string) => (activeNav === name ? "active" : "");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - NANTIS AST Review</title>
  <style>
    ${BASE_CSS}
  </style>
</head>
<body>

  <!-- Left Sidebar -->
  <aside class="app-sidebar">
    <div>
      <a href="/" class="app-logo">
        <div class="app-logo-title">NANTIS</div>
        <div class="app-logo-tagline">AUTOMATED AST REVIEW</div>
      </a>

      <nav class="nav-menu">
        <a href="/" class="nav-item ${isNavActive("dashboard")}">
          <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>
          Dashboard
        </a>
        <a href="/repos" class="nav-item ${isNavActive("repositories")}">
          <svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
          Repositories
        </a>
        <a href="/scans" class="nav-item ${isNavActive("scans")}">
          <svg viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          Scans
        </a>
        <a href="/findings" class="nav-item ${isNavActive("findings")}">
          <svg viewBox="0 0 24 24"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>
          Findings
        </a>
        <a href="/fixes" class="nav-item ${isNavActive("fixes")}">
          <svg viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
          Fixes
        </a>
        <a href="/pull-requests" class="nav-item ${isNavActive("pull-requests")}">
          <svg viewBox="0 0 24 24"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></svg>
          Pull Requests
        </a>
        <a href="/settings" class="nav-item ${isNavActive("settings")}">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
          Settings
        </a>
      </nav>
    </div>

    <!-- Bottom Sidebar Plan Card -->
    <div>
      <div class="sidebar-plan-card">
        <div class="plan-card-title">PRO PLAN</div>
        <div class="plan-card-stat">12 / 50</div>
        <div class="plan-card-subtext">scans this month</div>
        <div class="plan-progress-bar">
          <div class="plan-progress-fill" style="width: 24%;"></div>
        </div>
        <button type="button" class="btn-black" style="width: 100%; padding: 8px; font-size: 13px; font-weight: 600; border-radius: 8px; border: none; cursor: pointer;">Upgrade</button>
      </div>

      <div class="sidebar-footer-links">
        <a href="/rules">DOCS ↗</a>
        <a href="/privacy">SUPPORT ↗</a>
        <a href="/auth/logout">LOG OUT</a>
      </div>
    </div>
  </aside>

  <!-- Main Wrapper -->
  <div class="main-wrapper">
    
    <!-- Top Header Bar -->
    <header class="top-header">
      <div class="repo-selector" style="position: relative; cursor: pointer;" onclick="document.getElementById('repo-dropdown')?.classList.toggle('show')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
        <span id="header-repo-name" style="font-weight: 600;">${escapeHtml(displayRepo)}</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>

        <div id="repo-dropdown" style="display: none; position: absolute; top: 40px; left: 0; background: #fff; border: 1px solid var(--border-color); border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 260px; z-index: 100; padding: 6px 0;">
          <div style="padding: 6px 12px; font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Switch Repository</div>
          ${
            userRepos.map(r => `
              <a href="/repos" style="display: block; padding: 8px 12px; font-size: 13px; color: #0f172a; text-decoration: none;">${escapeHtml(r.full_name)}</a>
            `).join("")
          }
          <div style="border-top: 1px solid var(--border-color); margin: 4px 0;"></div>
          <a href="/repos" style="display: block; padding: 8px 12px; font-size: 13px; color: #2563eb; text-decoration: none;">+ Manage Repositories</a>
        </div>
      </div>

      <div class="search-bar">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input type="text" id="global-search-input" placeholder="Search findings, files, rules..." oninput="if(typeof applyTableFilters === 'function') { const s = document.getElementById('table-search'); if(s) { s.value = this.value; applyTableFilters(); } }" />
        <span class="search-shortcut">/</span>
      </div>

      <div style="display: flex; align-items: center; gap: 12px;">
        <div class="user-avatar-badge" title="${escapeHtml(userLogin || "User")}">
          ${escapeHtml((userLogin || "JD").slice(0, 2).toUpperCase())}
        </div>
      </div>
    </header>

    <!-- Main Page Content -->
    <main class="content-container">
      ${content}
    </main>

  </div>

  <script>
    document.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        const input = document.getElementById('global-search-input') || document.getElementById('table-search');
        if (input) input.focus();
      }
    });
    window.addEventListener('click', (e) => {
      const drop = document.getElementById('repo-dropdown');
      if (drop && !e.target.closest('.repo-selector')) {
        drop.style.display = 'none';
      }
    });
  </script>
</body>
</html>`;
}

