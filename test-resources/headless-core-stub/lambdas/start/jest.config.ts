import type { Config } from "jest";
import baseConfig from "../../../jest.config.base";

export default {
    ...baseConfig,
    displayName: "headless-core-stub/lambdas/start",
} satisfies Config;
