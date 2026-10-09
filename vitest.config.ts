import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**", "**/*.test.js", "**/*.test.d.ts"],
    testTimeout: 30000,
  },
});
