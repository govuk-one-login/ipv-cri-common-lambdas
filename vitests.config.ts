import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: ["lambdas/vitest.config.ts", "test-resources/vitest.config.ts"],
  },
});
