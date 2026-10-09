export interface GitHubPatRateLimit {
  limit: number;
  remaining: number;
  reset: number;
}

export interface GitHubPatDiagnostic {
  configured: boolean;
  authenticated: boolean;
  user?: string;
  userId?: number;
  avatarUrl?: string;
  scopes?: string[];
  tokenType?: "classic" | "fine-grained" | "none";
  rateLimit?: GitHubPatRateLimit;
  status?: number;
  error?: string;
  message?: string;
}

export interface GitHubRepoAccessResult {
  accessible: boolean;
  isPrivate?: boolean;
  defaultBranch?: string;
  fullName?: string;
  status?: number;
  error?: string;
}

/**
 * Validates a GitHub Personal Access Token (PAT) against the authenticated /user endpoint.
 * Returns diagnostic metadata (user, scopes, rate limits) without ever exposing the raw token.
 */
export async function validatePatConnection(
  token?: string,
  fetchFn: typeof fetch = fetch
): Promise<GitHubPatDiagnostic> {
  if (!token || token.trim() === "") {
    return {
      configured: false,
      authenticated: false,
      tokenType: "none",
      message: "No GITHUB_TOKEN configured. Local public repository scanning operates anonymously.",
    };
  }

  const cleanToken = token.trim();

  try {
    const res = await fetchFn("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${cleanToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "NANTIS-Security-App",
      },
    });

    const rateLimitHeader = res.headers.get("x-ratelimit-limit");
    const rateLimitRemaining = res.headers.get("x-ratelimit-remaining");
    const rateLimitReset = res.headers.get("x-ratelimit-reset");
    const scopesHeader = res.headers.get("x-oauth-scopes");

    const rateLimit: GitHubPatRateLimit | undefined = rateLimitHeader
      ? {
          limit: parseInt(rateLimitHeader, 10),
          remaining: parseInt(rateLimitRemaining || "0", 10),
          reset: parseInt(rateLimitReset || "0", 10),
        }
      : undefined;

    if (res.status === 401) {
      return {
        configured: true,
        authenticated: false,
        status: 401,
        rateLimit,
        error: "Authentication failed: GITHUB_TOKEN is invalid or has expired.",
      };
    }

    if (res.status === 403) {
      if (rateLimit && rateLimit.remaining === 0) {
        return {
          configured: true,
          authenticated: false,
          status: 403,
          rateLimit,
          error: "GitHub API rate limit exceeded for this token.",
        };
      }
      return {
        configured: true,
        authenticated: false,
        status: 403,
        rateLimit,
        error: "Access forbidden: Check that GITHUB_TOKEN has required permissions.",
      };
    }

    if (!res.ok) {
      return {
        configured: true,
        authenticated: false,
        status: res.status,
        rateLimit,
        error: `GitHub API returned unexpected status HTTP ${res.status}.`,
      };
    }

    const data = (await res.json()) as { login: string; id: number; avatar_url: string };
    const scopes = scopesHeader !== null
      ? scopesHeader.split(",").map((s) => s.trim()).filter(Boolean)
      : undefined;

    // Fine-grained PATs do not return x-oauth-scopes header
    const tokenType = scopesHeader !== null ? "classic" : "fine-grained";

    return {
      configured: true,
      authenticated: true,
      tokenType,
      user: data.login,
      userId: data.id,
      avatarUrl: data.avatar_url,
      scopes,
      rateLimit,
    };
  } catch (err: unknown) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    return {
      configured: true,
      authenticated: false,
      error: `Network error connecting to GitHub API: ${rawMsg}`,
    };
  }
}

/**
 * Checks if a specific repository is accessible via the GitHub REST API.
 * Accurately distinguishes 401, 403, 404, and rate limit errors.
 */
export async function checkRepoAccessWithPat(
  owner: string,
  repo: string,
  token?: string,
  fetchFn: typeof fetch = fetch
): Promise<GitHubRepoAccessResult> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "NANTIS-Security-App",
  };

  if (token && token.trim() !== "") {
    headers.Authorization = `Bearer ${token.trim()}`;
  }

  try {
    const res = await fetchFn(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {
      headers,
    });

    if (res.status === 200) {
      const data = (await res.json()) as {
        private: boolean;
        default_branch: string;
        full_name: string;
      };
      return {
        accessible: true,
        isPrivate: data.private,
        defaultBranch: data.default_branch,
        fullName: data.full_name,
        status: 200,
      };
    }

    if (res.status === 401) {
      return {
        accessible: false,
        status: 401,
        error: "Authentication failed: GITHUB_TOKEN is invalid or expired.",
      };
    }

    if (res.status === 403) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      if (remaining === "0") {
        return {
          accessible: false,
          status: 403,
          error: "GitHub API rate limit exceeded.",
        };
      }
      return {
        accessible: false,
        status: 403,
        error: "Access denied: GITHUB_TOKEN lacks permission to access this repository.",
      };
    }

    if (res.status === 404) {
      return {
        accessible: false,
        status: 404,
        error:
          "Repository not found or access denied (GitHub conceals private repositories from unauthorized requests).",
      };
    }

    return {
      accessible: false,
      status: res.status,
      error: `GitHub API returned HTTP ${res.status}.`,
    };
  } catch (err: unknown) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    return {
      accessible: false,
      error: `Network error reaching GitHub: ${rawMsg}`,
    };
  }
}
