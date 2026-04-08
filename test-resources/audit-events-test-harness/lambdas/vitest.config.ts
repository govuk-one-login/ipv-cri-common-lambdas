import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        globals: true,
        displayName: "audits-events-test-harness/lambdas",
        setupFiles: "setEnvVars.js",
    },
});
