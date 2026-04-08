import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        projects: [
            "audit-events-test-harness/lambdas/vitest.config.ts",
            "headless-core-stub/lambdas/*/vitest.config.ts",
            "headless-core-stub/utils/vitest.config.ts",
        ],
    },
});
