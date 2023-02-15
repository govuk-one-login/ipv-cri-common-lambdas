/*
 * For a detailed explanation regarding each configuration property and type check, visit:
 * https://jestjs.io/docs/configuration
 */

export default {
    transform: {
        "^.+\\.ts?$": "ts-jest",
    },
    clearMocks: true,
    collectCoverage: true,
    collectCoverageFrom: [
        'src/**/*.{js,ts}',
        '!**/tests/**',
        "!src/types/**"
    ],
    coverageDirectory: "coverage",
    coverageProvider: "v8",
    coveragePathIgnorePatterns: ["config.ts", "node_modules/"],
    testMatch: ["**/tests/**/*.test.ts"],
    preset: "ts-jest",
    testEnvironment: "node",
    setupFiles: ["<rootDir>/setEnvVars.js"]
};
