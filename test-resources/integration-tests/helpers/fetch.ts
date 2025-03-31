import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { createSignedFetcher } from "aws-sigv4-fetch";

const customCredentialsProvider = fromNodeProviderChain({
    timeout: 1000,
    maxRetries: 0,
});

export const signedFetch = createSignedFetcher({
    region: "eu-west-2",
    service: "execute-api",
    credentials: customCredentialsProvider,
});
