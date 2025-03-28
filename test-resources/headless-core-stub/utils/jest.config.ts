import type { Config } from "jest";
import baseConfig from "../../jest.config.base";

export default {
    ...baseConfig,
    setupFiles: ["<rootDir>/setEnvVars.js"],
    displayName: "headless-core-stub/lambdas/callback",
} satisfies Config;
