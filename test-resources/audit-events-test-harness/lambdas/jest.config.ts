import type { Config } from "jest";
import baseConfig from "../../jest.config.base";

export default {
    ...baseConfig,
    displayName: "audits-events-test-harness/lambdas",
    setupFiles: ["<rootDir>/setEnvVars.js"],
} satisfies Config;
