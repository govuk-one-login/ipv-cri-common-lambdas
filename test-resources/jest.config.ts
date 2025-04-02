import type { Config } from "jest";

export default {
    projects: [
        "audit-events-test-harness/lambdas/jest.config.ts",
        "headless-core-stub/lambdas/*/jest.config.ts",
        "headless-core-stub/utils/jest.config.ts",
        "integration-tests/jest.config.ts",
    ],
} satisfies Config;
