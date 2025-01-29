import type { Config } from "jest";

export default {
    preset: "ts-jest",
    clearMocks: true,
    modulePaths: ["<rootDir>/src"],
    collectCoverageFrom: ["<rootDir>/src/**/*"],
    testMatch: ["<rootDir>/tests/**/*.test.ts"],
    setupFiles: ["<rootDir>/setEnvVars.js"],
    coverageThreshold: {
        global: {
            statements: 93,
            branches: 94,
            functions: 95,
            lines: 94,
        },
        "./src/common/security/": {
            statements: 100,
            branches: 94,
            functions: 100,
            lines: 100,
        },
        "./src/services/security/": {
            statements: 100,
            branches: 100,
            functions: 100,
            lines: 100,
        },
    },
} satisfies Config;
