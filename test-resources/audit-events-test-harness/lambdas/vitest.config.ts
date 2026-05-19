import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        env: {
            REGION: "eu-west-2",
            EVENTS_TABLE_NAME: "audit-events-table",
        },
    },
});
