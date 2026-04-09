import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: ["tests/unit/handlers/contract/*.test.ts"],
    },
});
