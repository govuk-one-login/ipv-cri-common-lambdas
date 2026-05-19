import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        clearMocks: true,
        include: ["tests/**/*.test.ts"],
        exclude: ["tests/unit/handlers/contract/*.test.ts"],
        coverage: {
            include: ["src/**/*"],
            reporter: ["lcov"],
        },
        env: {
            AUTHORIZATION_CODE_TTL: "100",
            AWS_STACK_NAME: "di-ipv-cri-oauth-common",
            ACCESS_TOKEN_TTL_IN_SECS: "100",
        },
    },
});
