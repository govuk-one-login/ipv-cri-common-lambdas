import { stackOutputs } from "../helpers/cloudformation";
import { signedFetch } from "../helpers/fetch";
import { kmsClient } from "../helpers/kms";
import { JweDecrypter } from "../helpers/jwe-decrypter";
import { JwtVerifierFactory, ClaimNames } from "../helpers/jwt-verifier";
import { getParametersValues } from "../../headless-core-stub/utils/src/parameter/get-parameters";

describe("happy path core stub start endpoint", () => {
    let authenticationAlg;
    let publicSigningJwkBase64;
    let testHarnessExecuteUrl;
    let jweDecrypter;

    const jwtVerifierFactory = new JwtVerifierFactory();
    const clientId = "ipv-core-stub-aws-headless";
    const aud = "https://test-aud";
    const iss = "https://test-issuer";

    beforeAll(async () => {
        const { TestHarnessExecuteUrl, CommonStackName } = await stackOutputs(process.env.STACK_NAME);
        testHarnessExecuteUrl = TestHarnessExecuteUrl;

        const { CriDecryptionKey1Id: decryptionKeyId } = await stackOutputs("core-infrastructure");

        ({ authenticationAlg, publicSigningJwkBase64 } = await getParametersValues([
            `/${CommonStackName}/clients/${clientId}/jwtAuthentication/authenticationAlg`,
            `/${CommonStackName}/clients/${clientId}/jwtAuthentication/publicSigningJwkBase64`,
        ]));

        jweDecrypter = new JweDecrypter(kmsClient, () => decryptionKeyId);
    });

    it("returns 200 with a valid JWT for a valid request", async () => {
        const data = await signedFetch(`${testHarnessExecuteUrl}start`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ aud, client_id: clientId, iss }),
        });

        const { client_id, request } = await data.json();

        const jwtBuffer = await jweDecrypter.decryptJwe(request);
        const jwtVerifier = jwtVerifierFactory.create(authenticationAlg, publicSigningJwkBase64);
        const payload = await jwtVerifier.verify(
            jwtBuffer,
            new Set([ClaimNames.EXPIRATION_TIME, ClaimNames.SUBJECT, ClaimNames.NOT_BEFORE, ClaimNames.STATE]),
            new Map([
                [ClaimNames.AUDIENCE, aud],
                [ClaimNames.ISSUER, iss],
            ]),
        );

        expect(data.status).toBe(200);
        expect(client_id).toBe(clientId);
        expect(payload?.iss).toEqual(iss);
        expect(payload?.aud).toEqual(aud);
        expect(payload?.shared_claims).toEqual({
            name: [
                {
                    nameParts: [
                        {
                            type: "GivenName",
                            value: "KENNETH",
                        },
                        {
                            type: "FamilyName",
                            value: "DECERQUEIRA",
                        },
                    ],
                },
            ],
            birthDate: [{ value: "1965-07-08" }],
            address: [
                {
                    addressLocality: "BATH",
                    buildingNumber: "8",
                    postalCode: "BA2 5AA",
                    streetName: "HADLEY ROAD",
                    validFrom: "2021-01-01",
                },
            ],
        });
    });

    it("returns overridden shared claims if provided", async () => {
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
        const data = await signedFetch(`${testHarnessExecuteUrl}start`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ aud, client_id: clientId, iss, shared_claims: sharedClaimsOverrides }),
        });

        const { client_id, request } = await data.json();

        const jwtBuffer = await jweDecrypter.decryptJwe(request);
        const jwtVerifier = jwtVerifierFactory.create(authenticationAlg, publicSigningJwkBase64);
        const payload = await jwtVerifier.verify(
            jwtBuffer,
            new Set([ClaimNames.EXPIRATION_TIME, ClaimNames.SUBJECT, ClaimNames.NOT_BEFORE, ClaimNames.STATE]),
            new Map([
                [ClaimNames.AUDIENCE, aud],
                [ClaimNames.ISSUER, iss],
            ]),
        );

        expect(data.status).toBe(200);
        expect(client_id).toBe(clientId);
        expect(payload?.iss).toEqual(iss);
        expect(payload?.aud).toEqual(aud);
        expect(payload?.shared_claims).toEqual(sharedClaimsOverrides);
    });
});
