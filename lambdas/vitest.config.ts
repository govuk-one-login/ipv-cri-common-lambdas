import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        setupFiles: "setEnvVars.js",
        clearMocks: true,
        include: ["tests/**/*.test.ts"],
        exclude: ["tests/unit/handlers/contract/*.test.ts"],
        coverage: {
            include: ["src/**/*"],
            reporter: ["lcov"],
        },
    },
});
