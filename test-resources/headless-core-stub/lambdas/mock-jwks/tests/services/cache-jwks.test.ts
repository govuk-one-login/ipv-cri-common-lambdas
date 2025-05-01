import { generateJWKS } from "../../src/services/cache-jwk";
import * as ParameterHelper from "../../../../utils/src/parameter/get-parameters";

describe("generateJWKS", () => {
    beforeEach(() => {
        jest.spyOn(ParameterHelper, "getParametersValues").mockResolvedValueOnce({
            privateSigningKey: JSON.stringify({
                kty: "EC",
                crv: "P-256",
                x: "x",
                y: "y",
                kid: "ipv-core-stub-2-from-mkjwk.org",
            }),
        });
    });

    afterEach(() => jest.clearAllMocks());

    it("generates JWKS with reused and fresh key, then caches the result", async () => {
        const { jwks } = await generateJWKS();

        expect(jwks.keys).toHaveLength(2);

        const [reusedPub, freshPub] = jwks.keys;

        expect(reusedPub.kid).toBe("74c5b00d698a18178a738f5305ee67f9d50fc620f8be6b89d94638fa16a4c828");
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
        const result1 = await generateJWKS();
        const result2 = await generateJWKS();

        expect(result1.jwks.keys.length).toBe(2);
        expect(result2.jwks).toEqual(result1.jwks);
    });
});
