import { JWK } from "jose";
import { base64Encode } from "../../src/base64";
import { generateJWKS } from "../../../lambdas/mock-jwks/src/services/cache-jwk";
import { ClientConfiguration } from "../../src/services/client-configuration";

describe("generateJWKS", () => {
    const samplePublicJWK: JWK = {
        kty: "EC",
        crv: "P-256",
        x: "x",
        y: "y",
        kid: "existing-kid",
    };

    beforeEach(() => {
        jest.spyOn(ClientConfiguration, "getConfig").mockImplementation(async () => ({
            publicSigningJwkBase64: base64Encode(JSON.stringify(samplePublicJWK)),
            privateSigningKey: JSON.stringify({
                kty: "EC",
                crv: "P-256",
                x: "x",
                y: "y",
                kid: "existing-kid",
            }),
        }));
    });

    afterEach(() => jest.clearAllMocks());

    it("generates JWKS with reused and fresh key, then caches the result", async () => {
        const { jwks, privateKeys } = await generateJWKS("test-client");

        expect(jwks.keys).toHaveLength(2);
        expect(privateKeys).toHaveLength(2);

        const [reusedPub, freshPub] = jwks.keys;

        expect(reusedPub.kid).toBe("2c40b2726052aa7f082eebfbe26f5f0751596d1ae2778a5b5bfd485a88747a29");

        expect(freshPub.kid).toBeDefined();

        for (const key of [...jwks.keys]) {
            expect(key).toMatchObject({
                kty: expect.any(String),
                alg: expect.any(String),
                use: expect.any(String),
            });
        }
    });

    it("returns cached keys on second call", async () => {
        const result1 = await generateJWKS("test-client");
        const result2 = await generateJWKS("test-client");

        expect(result1.jwks.keys.length).toBe(2);
        expect(result2.jwks).toEqual(result1.jwks);
    });
});
