import type { Config } from "jest";
import baseConfig from "../../../jest.config.base";

export default {
    ...baseConfig,
    displayName: "headless-core-stub/lambdas/mock-jwks",
} satisfies Config;
