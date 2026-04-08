import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        globals: true,
        displayName: "headless-core-stub/lambdas/mock-jwks",
    },
});
