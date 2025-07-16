import { base64Encode } from "../../headless-core-stub/utils/src/base64/index";
import { DEFAULT_CLIENT_ID } from "../../headless-core-stub/utils/src/constants";
import { stackOutputs } from "../helpers/cloudformation";
import { signedFetch } from "../helpers/fetch";

describe("start endpoint happy path", () => {
    let testHarnessExecuteUrl: string;

    beforeAll(async () => {
        const { TestHarnessExecuteUrl } = await stackOutputs(process.env.STACK_NAME);
        testHarnessExecuteUrl = TestHarnessExecuteUrl;
    });

    it("returns 200 with non-empty response body for valid empty {} object request", async () => {
        const stubStartUrl = new URL("start", testHarnessExecuteUrl).href;
        const response = await signedFetch(stubStartUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({}),
        });

        const responseBody = await response.json();

        expect(response.status).toBe(200);
        expect(responseBody).toBeDefined();
        expect(Object.keys(responseBody).length).toBeGreaterThan(0);
    });

    it("returns 200 with non-empty response body for valid request overridden with shared claims", async () => {
        const aud = "https://api.review-k.dev.account.gov.uk";
        const stateOverride = base64Encode(
            JSON.stringify({
                aud,
                redirect_uri: new URL("callback", testHarnessExecuteUrl).href,
            }),
        );
        const sharedClaimsOverrides = {
            name: [
                {
                    nameParts: [
                        {
                            type: "GivenName",
                            value: "Test",
                        },
                        {
                            type: "FamilyName",
                            value: "Tester",
                        },
                    ],
                },
            ],
            birthDate: [{ value: "2000-02-02" }],
            address: [
                {
                    addressLocality: "LONDON",
                    buildingNumber: "1",
                    postalCode: "EE2 1AA",
                    streetName: "Test st",
                    validFrom: "2024-01-01",
                },
            ],
        };
        const stubStartUrl = new URL("start", testHarnessExecuteUrl).href;
        const response = await signedFetch(stubStartUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                aud,
                client_id: DEFAULT_CLIENT_ID,
                iss: testHarnessExecuteUrl,
                shared_claims: sharedClaimsOverrides,
                state: stateOverride,
            }),
        });

        const responseBody = await response.json();

        expect(response.status).toBe(200);
        expect(responseBody).toBeDefined();
        expect(Object.keys(responseBody).length).toBeGreaterThan(0);
    });
});
