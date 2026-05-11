import assert from "node:assert/strict";
import { invokeApi } from "./apigw-fetch.ts";

interface CriExecutorFunctionInput {
    sessionId: string;
}

interface CriConfig {
    customClaims?: Record<string, unknown>;
    completeCri: (input: CriExecutorFunctionInput) => Promise<void>;
}

export const journeyConfig: Record<string, CriConfig> = {
    CHECK_HMRC_HAPPY: {
        completeCri: async function ({ sessionId }) {
            const response = await invokeApi("private", {
                method: "POST",
                path: "/check",
                headers: {
                    "session-id": sessionId,
                },
                jsonBody: {
                    nino: "AA000000B",
                },
            });

            assert(response.status === 200);
        },
    },
    ADDRESS_HAPPY: {
        completeCri: async function ({ sessionId }) {
            const response = await invokeApi("private", {
                method: "PUT",
                path: "/address",
                headers: { session_id: sessionId },
                jsonBody: [
                    {
                        uprn: 100000000000,
                        buildingNumber: "10",
                        streetName: "street",
                        addressLocality: "City",
                        postalCode: "SW1A 2AA",
                        addressCountry: "GB",
                        validFrom: "2000-01-01",
                    },
                ],
            });

            assert(response.status === 204);
        },
    },
};
