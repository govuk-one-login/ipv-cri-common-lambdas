import type { Config } from "jest";
import baseConfig from "../jest.config.base";

export default {
    ...baseConfig,
    displayName: "integration-tests",
    testMatch: ["<rootDir>/**/*.test.ts"],
} satisfies Config;
