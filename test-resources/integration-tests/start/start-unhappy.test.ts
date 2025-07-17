import { stackOutputs } from "../helpers/cloudformation";
import { signedFetch } from "../helpers/fetch";

describe("start endpoint unhappy path", () => {
    let testHarnessExecuteUrl;
    const aud = "https://test-aud";
    const iss = "https://test-issuer";
    const clientId = "ipv-core-stub-aws-headless";

    beforeAll(async () => {
        ({ TestHarnessExecuteUrl: testHarnessExecuteUrl } = await stackOutputs(process.env.STACK_NAME));
    });

    it("returns 500 where invalid client ID is provided", async () => {
        const response = await signedFetch(new URL("start", testHarnessExecuteUrl).href, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ aud, client_id: "no-ssm-params", iss }),
        });

        const { message } = await response.json();

        expect(message).toBe("Server error");
        expect(response.status).toBe(500);
    });

    it("returns 400 where invalid shared claims are provided", async () => {
        const sharedClaimsOverrides = {
            birthDate: "1965-07-08",
            name: "KENNETH DECERQUEIRA",
        };
        const response = await signedFetch(new URL("start", testHarnessExecuteUrl).href, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ aud, client_id: clientId, iss, shared_claims: sharedClaimsOverrides }),
        });

        const { message } = await response.json();

        expect(message).toBe(
            "Claims set failed validation: /shared_claims/birthDate - must be array, /shared_claims/name - must be array",
        );
        expect(response.status).toBe(400);
    });
});
