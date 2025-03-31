import { stackOutputs } from "../helpers/cloudformation";
import { signedFetch } from "../helpers/fetch";

describe("happy path core stub start endpoint", () => {
    let testHarnessExecuteUrl;
    const aud = "https://test-aud";
    const iss = "https://test-issuer";
    const clientId = "ipv-core-stub-aws-headless";

    beforeAll(async () => {
        ({ TestHarnessExecuteUrl: testHarnessExecuteUrl } = await stackOutputs(process.env.STACK_NAME));
    });

    it("returns 500 where invalid client ID is provided", async () => {
        const data = await signedFetch(`${testHarnessExecuteUrl}start`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ aud, client_id: "no-ssm-params", iss }),
        });

        const { message } = await data.json();

        expect(data.status).toEqual(500);
        expect(message).toEqual("Server error");
    });

    it("returns 400 where invalid shared claims are provided", async () => {
        const sharedClaimsOverrides = {
            birthDate: "1965-07-08",
            name: "KENNETH DECERQUEIRA",
        };
        const data = await signedFetch(`${testHarnessExecuteUrl}start`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ aud, client_id: clientId, iss, shared_claims: sharedClaimsOverrides }),
        });

        const { message } = await data.json();

        expect(data.status).toEqual(400);
        expect(message).toEqual(
            "Claims set failed validation: /shared_claims/birthDate - must be array, /shared_claims/name - must be array",
        );
    });
});
