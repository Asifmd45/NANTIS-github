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

export async function renderRepositoriesPage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Authentication Required",
        content: `<h1>401 Authentication Required</h1><p>Please sign in to view repositories.</p>`,
      }),
    };
  }

  const session = decodeSession(token, env.SESSION_SECRET);
  if (!session || !session.userId) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Authentication Required",
        content: `<h1>401 Authentication Required</h1><p>Session invalid or expired.</p>`,
      }),
    };
  }

  const csrfToken = getOrCreateCsrfToken(session.userId);
  const snapshot = await db.getUserUnexpiredSnapshot(session.userId);
  const userInstallations = await db.getUserInstallations(session.userId);

  const chooseReposUrl =
    userInstallations.length > 0 && userInstallations[0].html_url
      ? userInstallations[0].html_url
      : `https://github.com/apps/${env.GITHUB_APP_SLUG}/installations/new`;

  // Fetch repos to list: snapshot repos first, fallback to user accessible repos if snapshot empty
  const accessibleFallback = snapshot.length === 0 ? await db.getUserAccessibleRepositories(session.userId) : [];
  const reposToList =
    snapshot.length > 0
      ? snapshot.map((s) => ({
          github_repo_id: s.github_repo_id,
          full_name: s.full_name,
          private: s.private,
          html_url: s.html_url || `https://github.com/${s.full_name}`,
          installation_id: s.installation_id,
        }))
      : accessibleFallback.map((r) => ({
          github_repo_id: r.github_repo_id,
          full_name: r.full_name,
          private: r.private,
          html_url: `https://github.com/${r.full_name}`,
          installation_id: Number(r.installation_id) || 1,
        }));

  // Fetch db repo rows for scan status if available
  const repoItems = await Promise.all(
    reposToList.map(async (r) => {
      const dbRepo = await db.getRepositoryByGithubId(r.github_repo_id);
      const scans = dbRepo ? await db.getScansForRepository(dbRepo.id) : [];
      const scanLinks = scans
        .map(
          (s) =>
            `<a href="/scans/${escapeHtml(s.id)}" class="btn btn-outline" style="padding: 2px 8px; font-size: 0.75rem;">${escapeHtml(
              s.status.toUpperCase()
            )} (${escapeHtml(s.commit_sha.slice(0, 7))})</a>`
        )
        .join(" ");

      const repoUrl = r.html_url || `https://github.com/${r.full_name}`;
      const instLink = userInstallations.find((i) => i.installation_id === r.installation_id)?.html_url || chooseReposUrl;

      return `
        <div class="ui-card repo-card-item" data-repo-name="${escapeHtml(r.full_name.toLowerCase())}" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding: 16px 20px;">
          <div>
            <h3 style="font-size: 1.1rem; font-weight: 700;">
              <a href="${escapeHtml(repoUrl)}" target="_blank" rel="noopener" style="color: inherit; text-decoration: none;">
                ${escapeHtml(r.full_name)} ↗
              </a>
              <span style="font-size: 0.75rem; font-weight: 600; padding: 2px 8px; border-radius: 9999px; background: #f1f5f9; color: #475569; margin-left: 8px;">
                ${r.private ? "private" : "public"}
              </span>
            </h3>
            <div style="margin-top: 4px; font-size: 0.8rem; color: #64748b;">
              <a href="${escapeHtml(instLink)}" target="_blank" rel="noopener" style="color: #2563eb; text-decoration: none;">Manage on GitHub ↗</a>
            </div>
            ${scanLinks ? `<div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-dim);">Scans: ${scanLinks}</div>` : `<div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-muted);">No scans run yet</div>`}
          </div>
          <div>
            <form action="/api/dev/scan-public-repo" method="POST" style="display: inline;">
              <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
              <input type="hidden" name="repoUrl" value="${escapeHtml(repoUrl)}" />
              <button type="button" data-repo-id="${escapeHtml(dbRepo ? dbRepo.id : String(r.github_repo_id))}" class="btn btn-black" style="padding: 6px 14px; font-size: 12px;">Scan</button>
            </form>
          </div>
        </div>
      `;
    })
  );

  const repoListHtml =
    reposToList.length === 0
      ? `<div style="text-align: center; padding: 40px 20px; background: #f8fafc; border: 1px dashed var(--border-color); border-radius: 8px; color: var(--text-muted); font-size: 14px;">
          <p style="margin-bottom: 16px;">No repository access snapshot found or snapshot has expired.</p>
          <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
            <a href="/" class="btn btn-black">Scan via URL (Home)</a>
            <a href="${escapeHtml(chooseReposUrl)}" target="_blank" rel="noopener" class="btn btn-outline">Choose repositories</a>
            <a href="/auth/login?refresh=true" class="btn btn-outline">Refresh</a>
          </div>
        </div>`
      : repoItems.join("\n");

  const content = `
    <div style="max-width: 900px; margin: 0 auto;">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; flex-wrap: wrap; gap: 16px;">
        <div>
          <h1 style="font-size: 1.8rem; font-weight: 800; margin-bottom: 4px;">
            Repositories
          </h1>
          <p style="color: var(--text-dim); font-size: 0.9rem; margin-bottom: 8px;">
            Signed in as <strong>${escapeHtml(session.githubLogin)}</strong>
            ${env.GITHUB_TOKEN ? '<span style="background: #ecfdf5; color: #047857; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; margin-left: 8px;">🔑 GITHUB_TOKEN Active</span>' : ""}
          </p>
          <p style="font-size: 0.85rem; color: var(--text-muted); max-width: 600px; line-height: 1.5;">
            NANTIS gets read-only access to only the repositories you choose, and you can change this anytime on GitHub.
          </p>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <a href="${escapeHtml(chooseReposUrl)}" target="_blank" rel="noopener" class="btn btn-outline" style="font-size: 0.85rem;">
            Choose repositories
          </a>
          <a href="/auth/login?refresh=true" class="btn btn-outline" style="font-size: 0.85rem;">
            Refresh
          </a>
          <a href="/auth/disconnect" class="btn btn-outline" style="font-size: 0.85rem; color: #dc2626; border-color: #fca5a5;">
            Disconnect GitHub
          </a>
        </div>
      </div>

      ${
        snapshot.length > 0
          ? `<div style="margin-bottom: 16px;">
              <input type="text" id="repo-search-input" placeholder="Search repositories..." onkeyup="
                var q = this.value.toLowerCase();
                var items = document.querySelectorAll('.repo-card-item');
                items.forEach(function(item) {
                  var name = item.getAttribute('data-repo-name') || '';
                  item.style.display = name.indexOf(q) !== -1 ? 'flex' : 'none';
                });
              " style="width: 100%; max-width: 320px; padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px;" />
            </div>`
          : ""
      }

      <!-- Sample Demo Repository Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding: 16px 20px; background: #ffffff; border-left: 4px solid #6366f1;">
        <div>
          <h3 style="font-size: 1.1rem; font-weight: 700;">
            e2e-nextjs-supabase-stripe (Sample Vulnerable Fixture)
            <span style="font-size: 0.75rem; font-weight: 600; padding: 2px 8px; border-radius: 9999px; background: #e0e7ff; color: #4338ca; margin-left: 8px;">
              Local Demo
            </span>
          </h3>
          <div style="margin-top: 4px; font-size: 0.8rem; color: #64748b;">
            Comprehensive AST security test fixture with Next.js, Supabase IDOR, and Stripe webhook patterns.
          </div>
        </div>
        <div>
          <a href="/api/dev/scan-sample-demo" class="btn btn-black" style="padding: 8px 16px; font-size: 12px; font-weight: 600;">
            Scan Demo Repo ➔
          </a>
        </div>
      </div>

      ${repoListHtml}
      <script>
        document.addEventListener('click', function(e) {
          var btn = e.target.closest('button[data-repo-id]');
          if (btn && btn.closest('form')) {
            btn.closest('form').submit();
          }
        });
      </script>
    </div>

  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Repositories",
      userLogin: session.githubLogin,
      csrfToken,
      content,
    }),
  };
}
