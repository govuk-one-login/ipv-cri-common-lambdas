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
    coverageThreshold: {
        global: {
            statements: 95,
            branches: 95,
            functions: 95,
            lines: 95,
        },
        './src/common/security/': {
            statements: 100,
            branches: 94,
            functions: 100,
            lines: 100
        },
        './src/services/security/': {
            statements: 100,
            branches: 100,
            functions: 100,
            lines: 100
        },
    },
    testMatch: ["**/tests/**/*.test.ts"],
    preset: "ts-jest",
    testEnvironment: "node",
    setupFiles: ["<rootDir>/setEnvVars.js"]
};
