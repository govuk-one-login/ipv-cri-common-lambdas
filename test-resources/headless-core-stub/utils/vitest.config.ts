import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        env: {
            COMMON_STACK_NAME: "mock-common-prefix",
            TEST_RESOURCES_STACK_NAME: "mock-test-resources-prefix",
        },
    },
});
