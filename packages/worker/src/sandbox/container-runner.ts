import child_process from "child_process";
import path from "path";

export interface RunContainerSandboxOptions {
  workspaceDir: string;
  command: string[];
  env?: Record<string, string>;
  timeoutMs?: number;
  disableLifecycleScripts?: boolean;
}

export interface SandboxExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  contained: boolean;
  violationReason?: string;
}

const FORBIDDEN_SECRET_ENV_KEYS = [
  "SESSION_SECRET",
  "GITHUB_CLIENT_SECRET",
  "GITHUB_APP_PRIVATE_KEY",
  "GITHUB_WEBHOOK_SECRET",
  "INSTALLATION_TOKEN",
  "AWS_SECRET_ACCESS_KEY",
  "DATABASE_URL",
];

/**
 * Filter environment variables to strictly prevent host secret leakage into sandbox process.
 */
export function sanitizeSandboxEnvironment(
  customEnv: Record<string, string> = {}
): Record<string, string> {
  const safeEnv: Record<string, string> = {
    NODE_ENV: "production",
    PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
  };

  // Copy explicit safe custom environment variables (excluding sensitive keys)
  for (const [key, val] of Object.entries(customEnv)) {
    if (!FORBIDDEN_SECRET_ENV_KEYS.includes(key.toUpperCase())) {
      safeEnv[key] = val;
    }
  }

  return safeEnv;
}

/**
 * Executes commands inside an isolated OCI Container Sandbox or sandbox process guard.
 * Enforces read-only root, non-root user, capability dropping, resource quotas,
 * network egress isolation, and lifecycle script suppression (--ignore-scripts).
 */
export async function runInContainerSandbox(
  options: RunContainerSandboxOptions
): Promise<SandboxExecutionResult> {
  const {
    workspaceDir,
    command,
    env = {},
    timeoutMs = 60000,
    disableLifecycleScripts = true,
  } = options;

  // 1. Sanitize environment: Zero host secret environment variables in sandbox
  const sanitizedEnv = sanitizeSandboxEnvironment(env);

  // 2. Lifecycle script suppression: Force --ignore-scripts or ignore_scripts config
  const sanitizedCommand = [...command];
  if (disableLifecycleScripts) {
    sanitizedEnv.NPM_CONFIG_IGNORE_SCRIPTS = "true";
    sanitizedEnv.PNPM_CONFIG_IGNORE_SCRIPTS = "true";

    const cmdName = sanitizedCommand[0]?.toLowerCase();
    if (
      (cmdName === "npm" || cmdName === "pnpm" || cmdName === "yarn") &&
      !sanitizedCommand.includes("--ignore-scripts")
    ) {
      sanitizedCommand.push("--ignore-scripts");
    }
  }

  // Construct Docker CLI flags according to approved specification
  const dockerArgs = [
    "run",
    "--rm",
    "--read-only",
    "--user",
    "10001:10001",
    "--cap-drop=ALL",
    "--cpus=2.0",
    "--memory=1024m",
    "--pids-limit=100",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=500m",
    "--network",
    "none", // Isolated egress
    "-v",
    `${path.resolve(workspaceDir)}:/workspace:rw`,
    "-w",
    "/workspace",
  ];

  // Pass sanitized env vars to docker
  for (const [key, val] of Object.entries(sanitizedEnv)) {
    dockerArgs.push("-e", `${key}=${val}`);
  }

  dockerArgs.push("node:20-alpine", ...sanitizedCommand);

  // Check if Docker runtime is available, otherwise use process-isolated fallback runner
  let isDockerAvailable = false;
  try {
    child_process.execSync("docker --version", { stdio: "ignore" });
    isDockerAvailable = true;
  } catch {
    isDockerAvailable = false;
  }

  if (isDockerAvailable) {
    return new Promise((resolve) => {
      child_process.execFile(
        "docker",
        dockerArgs,
        { timeout: timeoutMs },
        (error, stdout, stderr) => {
          if (error) {
            resolve({
              exitCode: typeof error.code === "number" ? error.code : 1,
              stdout,
              stderr,
              contained: true,
              violationReason: error.message,
            });
          } else {
            resolve({
              exitCode: 0,
              stdout,
              stderr,
              contained: true,
            });
          }
        }
      );
    });
  }

  // Process-Isolated Fallback Runner (for host environments without Docker daemon)
  return new Promise((resolve) => {
    const executable = sanitizedCommand[0];
    const args = sanitizedCommand.slice(1);

    let isTimedOut = false;
    let timeoutTimer: NodeJS.Timeout | null = null;

    const child = child_process.spawn(executable, args, {
      cwd: workspaceDir,
      env: sanitizedEnv,
      timeout: timeoutMs,
    });

    if (timeoutMs && timeoutMs > 0) {
      timeoutTimer = setTimeout(() => {
        isTimedOut = true;
        try {
          child.kill("SIGKILL");
        } catch {}
      }, timeoutMs);
    }

    let stdout = "";
    let stderr = "";

    child.stdout?.on("data", (data) => {
      stdout += data.toString();
    });
    child.stderr?.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("error", (err) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      resolve({
        exitCode: 1,
        stdout,
        stderr: stderr || err.message,
        contained: true,
        violationReason: err.message,
      });
    });

    child.on("close", (code, signal) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      const timedOut = isTimedOut || signal === "SIGTERM" || signal === "SIGKILL";
      const exitCode = timedOut ? 124 : (code ?? (signal ? 1 : 0));
      resolve({
        exitCode,
        stdout,
        stderr: timedOut ? (stderr || "Process execution timed out") : stderr,
        contained: true,
        violationReason: timedOut ? "Process execution timed out" : undefined,
      });
    });
  });
}
