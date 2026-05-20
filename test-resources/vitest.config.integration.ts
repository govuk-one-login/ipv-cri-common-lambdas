import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["integration-tests/**/*.test.ts"],
  },
});
