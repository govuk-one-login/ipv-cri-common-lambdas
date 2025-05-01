import { Logger } from "@aws-lambda-powertools/logger";

import { base64Encode } from "../../headless-core-stub/utils/src/base64/index";
import { DEFAULT_CLIENT_ID } from "../../headless-core-stub/utils/src/constants";

import { getParametersValues } from "../../headless-core-stub/utils/src/parameter/get-parameters";

import { stackOutputs } from "../helpers/cloudformation";
import { JweDecrypter } from "../helpers/jwe-decrypter";
import { signedFetch } from "../helpers/fetch";
import { JwtVerifierFactory, ClaimNames } from "../helpers/jwt-verifier";
import { kmsClient } from "../helpers/kms";

describe("happy path core stub start endpoint", () => {
    let authenticationAlg: string;
    let jweDecrypter: JweDecrypter;
    let testHarnessExecuteUrl: string;
    const jwtVerifierFactory = new JwtVerifierFactory(new Logger());
    const aud = "https://test-aud";
    let iss: string;

    beforeAll(async () => {
        const { TestHarnessExecuteUrl, CommonStackName } = await stackOutputs(process.env.STACK_NAME);
        testHarnessExecuteUrl = TestHarnessExecuteUrl;
        iss = testHarnessExecuteUrl.replace(/\/+$/, "");
        const { CriDecryptionKey1Id: decryptionKeyId } = await stackOutputs("core-infrastructure");

        ({ authenticationAlg } = await getParametersValues([
            `/${CommonStackName}/clients/${DEFAULT_CLIENT_ID}/jwtAuthentication/authenticationAlg`,
        ]));

        jweDecrypter = new JweDecrypter(kmsClient, () => decryptionKeyId);
    });

    it("returns 200 with a valid JWT for a valid request", async () => {
        const defaultState = base64Encode(
            JSON.stringify({
                aud,
                redirect_uri: `https://test-resources.review-hc.dev.account.gov.uk/callback`,
            }),
        );
        const stubStartUrl = new URL("start", testHarnessExecuteUrl).href;
        const data = await signedFetch(stubStartUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ aud, client_id: DEFAULT_CLIENT_ID, iss }),
        });
        const { client_id, request } = await data.json();

        const jwtBuffer = await jweDecrypter.decryptJwe(request);
        const jwtVerifier = jwtVerifierFactory.create(authenticationAlg);
        const verifyResult = await jwtVerifier.verify(
            jwtBuffer,
            new Set([ClaimNames.EXPIRATION_TIME, ClaimNames.SUBJECT, ClaimNames.NOT_BEFORE, ClaimNames.STATE]),
            new Map([
                [ClaimNames.AUDIENCE, aud],
                [ClaimNames.ISSUER, iss],
            ]),
        );

        expect(data.status).toBe(200);
        expect(client_id).toBe(DEFAULT_CLIENT_ID);
        expect(verifyResult?.protectedHeader.alg).toEqual("ES256");
        expect(verifyResult?.protectedHeader.typ).toEqual("JWT");
        // ipv-core-stub-2-from-mkjwk.org hashed
        expect(verifyResult?.protectedHeader.kid).toEqual(
            "74c5b00d698a18178a738f5305ee67f9d50fc620f8be6b89d94638fa16a4c828",
        );
        expect(verifyResult?.payload.iss).toEqual(iss);
        expect(verifyResult?.payload.aud).toEqual(aud);
        expect(verifyResult?.payload.shared_claims).toEqual({
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
        expect(verifyResult?.payload.state).toEqual(defaultState);
    });

    it("returns overridden shared claims if provided", async () => {
        const stateOverride = base64Encode(
            JSON.stringify({
                aud: "https://review-hc.dev.account.gov.uk",
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
        const data = await signedFetch(stubStartUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                aud,
                client_id: DEFAULT_CLIENT_ID,
                iss,
                shared_claims: sharedClaimsOverrides,
                state: stateOverride,
            }),
        });

        const { client_id, request } = await data.json();

        const jwtBuffer = await jweDecrypter.decryptJwe(request);
        const jwtVerifier = jwtVerifierFactory.create(authenticationAlg);
        const verifyResult = await jwtVerifier.verify(
            jwtBuffer,
            new Set([ClaimNames.EXPIRATION_TIME, ClaimNames.SUBJECT, ClaimNames.NOT_BEFORE, ClaimNames.STATE]),
            new Map([
                [ClaimNames.AUDIENCE, aud],
                [ClaimNames.ISSUER, iss],
            ]),
        );

        expect(data.status).toBe(200);
        expect(client_id).toBe(DEFAULT_CLIENT_ID);
        expect(verifyResult?.protectedHeader.alg).toEqual("ES256");
        expect(verifyResult?.protectedHeader.typ).toEqual("JWT");
        // ipv-core-stub-2-from-mkjwk.org hashed
        expect(verifyResult?.protectedHeader.kid).toEqual(
            "74c5b00d698a18178a738f5305ee67f9d50fc620f8be6b89d94638fa16a4c828",
        );
        expect(verifyResult?.payload.iss).toEqual(iss);
        expect(verifyResult?.payload.aud).toEqual(aud);
        expect(verifyResult?.payload.shared_claims).toEqual(sharedClaimsOverrides);
        expect(verifyResult?.payload.state).toEqual(stateOverride);
    });
});
