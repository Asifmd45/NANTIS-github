export interface WebEnv {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  GITHUB_APP_ID: string;
  GITHUB_APP_SLUG?: string;
  GITHUB_APP_PRIVATE_KEY: string;
  GITHUB_WEBHOOK_SECRET: string;
  GITHUB_TOKEN?: string;
  SESSION_SECRET: string;
  DATABASE_URL: string;
  NODE_ENV: "development" | "production" | "test";
  USER_REPO_SNAPSHOT_TTL_MS?: number;
}

const REQUIRED_ENV_VARS: (keyof WebEnv)[] = [
  "GITHUB_CLIENT_ID",
  "GITHUB_CLIENT_SECRET",
  "GITHUB_APP_ID",
  "GITHUB_APP_SLUG",
  "GITHUB_APP_PRIVATE_KEY",
  "GITHUB_WEBHOOK_SECRET",
  "SESSION_SECRET",
];

export function validateWebEnv(env: Record<string, string | undefined> = process.env): WebEnv {
  const missing: string[] = [];
  const isProduction = env.NODE_ENV === "production";

  if (isProduction && (env.ALLOW_DEV_LOGIN === "true" || env.ENABLE_DEV_LOGIN === "true")) {
    const errorMsg = "[NANTIS Web Startup Error] Dev login is strictly prohibited in production mode.";
    console.error(errorMsg);
    throw new Error(errorMsg);
  }

  for (const key of REQUIRED_ENV_VARS) {
    if (!env[key] || env[key]!.trim() === "") {
      missing.push(key);
    }
  }

  if (missing.length > 0) {
    const errorMsg = `[NANTIS Web Startup Error] Missing required environment variable(s): ${missing.join(", ")}. Please configure them in your environment or .env file.`;
    console.error(errorMsg);
    throw new Error(errorMsg);
  }

  const ttlMs = parseInt(env.USER_REPO_SNAPSHOT_TTL_MS || "3600000", 10);

  return {
    GITHUB_CLIENT_ID: env.GITHUB_CLIENT_ID!,
    GITHUB_CLIENT_SECRET: env.GITHUB_CLIENT_SECRET!,
    GITHUB_APP_ID: env.GITHUB_APP_ID!,
    GITHUB_APP_SLUG: env.GITHUB_APP_SLUG!,
    GITHUB_APP_PRIVATE_KEY: env.GITHUB_APP_PRIVATE_KEY!,
    GITHUB_WEBHOOK_SECRET: env.GITHUB_WEBHOOK_SECRET!,
    GITHUB_TOKEN: env.GITHUB_TOKEN?.trim() || undefined,
    SESSION_SECRET: env.SESSION_SECRET!,
    DATABASE_URL: env.DATABASE_URL || "postgresql://localhost:5432/nantis_db",
    NODE_ENV: (env.NODE_ENV as WebEnv["NODE_ENV"]) || "development",
    USER_REPO_SNAPSHOT_TTL_MS: Number.isNaN(ttlMs) ? 3600000 : ttlMs,
  };
}
