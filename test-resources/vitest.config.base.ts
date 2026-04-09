import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        clearMocks: true,
        roots: ["<rootDir>/src"],
        include: ["tests/**/*.test.ts"],
        coverage: {
            include: ["src/**/*"],
            reporter: ["lcov"],
        },
    },
});
