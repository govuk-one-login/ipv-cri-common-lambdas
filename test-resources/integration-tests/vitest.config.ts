import { defineConfig } from "vitest/config";
import { resolve } from "path";

export default defineConfig({
    test: {
        globals: true,
        displayName: "integration-tests",
        root: resolve(__dirname),
        include: ["**/*.test.ts"],
    },
});
