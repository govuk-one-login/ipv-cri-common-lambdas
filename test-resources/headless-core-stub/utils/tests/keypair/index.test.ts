import { getHashedKid } from "../../src/hashing";
import { getJwkKeyPair, GetJwkKeyPairOptions } from "../../src/keypair";

describe("getJwkKeyPair", () => {
    it("generates a valid key pair when no current keys are provided", async () => {
        const { publicKey, privateKey } = await getJwkKeyPair({
            kid: "my-generated-kid",
            alg: "ES256",
            use: "sig",
        });

        expect(publicKey).toMatchObject({
            alg: "ES256",
            use: "sig",
            kid: "my-generated-kid",
            kty: "EC",
        });
        expect(privateKey).toMatchObject({
            alg: "ES256",
            use: "sig",
            kid: "my-generated-kid",
            kty: "EC",
        });

        expect(typeof publicKey.x).toBe("string");
        expect(typeof publicKey.y).toBe("string");
        expect(typeof privateKey.d).toBe("string");
    });

    it("generates RSA keys when alg is RS256", async () => {
        const { publicKey, privateKey } = await getJwkKeyPair({
            kid: "rsa-kid",
            alg: "RS256",
            use: "enc",
        });

        expect(publicKey.kty).toBe("RSA");
        expect(publicKey.alg).toBe("RS256");
        expect(publicKey.use).toBe("enc");

        expect(privateKey.kty).toBe("RSA");
        expect(typeof privateKey.d).toBe("string");
    });

    it("reuses provided keys if they share the same kid", async () => {
        const firstPair = await getJwkKeyPair({
            kid: "shared-kid",
            alg: "ES256",
            use: "sig",
        });

        const { publicKey, privateKey } = await getJwkKeyPair({
            kid: "should-be-ignored",
            alg: "ES256",
            use: "sig",
            currentPublicKey: firstPair.publicKey,
            currentPrivateKey: firstPair.privateKey,
        });

        const expectedHashedKid = getHashedKid("shared-kid");

        expect(publicKey.kid).toBe("c049be65b48c236515956d63e5eb0656130d90c63d7e2a0f62117684b0b8cec8");
        expect(privateKey.kid).toBe(expectedHashedKid);
        expect(publicKey.alg).toBe("ES256");
        expect(privateKey.alg).toBe("ES256");
    });

    it("generates random UUID kid when none is provided", async () => {
        const { publicKey, privateKey } = await getJwkKeyPair({} as GetJwkKeyPairOptions);

        expect(typeof publicKey.kid).toBe("string");
        expect(publicKey.kid).toBe(publicKey.kid);
        expect(privateKey.kid).toBe(publicKey.kid);
    });
});
