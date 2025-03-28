import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { createSignedFetcher } from "aws-sigv4-fetch";
import { stackOutputs } from "../helpers/cloudformation";

const customCredentialsProvider = fromNodeProviderChain({
    timeout: 1000,
    maxRetries: 0,
});

const signedFetch = createSignedFetcher({
    region: "eu-west-2",
    service: "execute-api",
    credentials: customCredentialsProvider,
});

describe("core stub start endpoint", () => {
    let TestHarnessExecuteUrl;

    beforeAll(async () => {
        ({ TestHarnessExecuteUrl } = await stackOutputs(process.env.STACK_NAME));
    });
    it("returns 200 for a valid request", async () => {
        const response = await signedFetch(`${TestHarnessExecuteUrl}start`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ aud: "https://review-a.dev.account.gov.uk" }),
        });

        console.log("TestHarnessExecuteUrl", TestHarnessExecuteUrl);
        // console.log("response", response);
        expect(response.status).toBe(200);
    });
});
