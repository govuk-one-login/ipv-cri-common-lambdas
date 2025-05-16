import { clearCaches } from "@aws-lambda-powertools/parameters";
import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { mockClient } from "aws-sdk-client-mock";
import { generateKeyPairSync } from "crypto";
import { HeadlessCoreStubError } from "../../../../utils/src/errors/headless-core-stub-error";
import { encryptSignedJwt, getPublicEncryptionKey } from "../../src/services/signing-service";
import { TestData } from "../../../../utils/tests/test-data";
import { KeyLike } from "jose";

describe("signing-service", () => {
    const audience = "https://test-audience.com";
    describe("getPublicEncryptionKey - kms", () => {
        const mockKMSClient = mockClient(KMSClient);

        afterEach(() => {
            mockKMSClient.reset();
            clearCaches();
        });

        it("throws error with 500 if decryption key env variable not set", async () => {
            await expect(getPublicEncryptionKey(audience)).rejects.toThrow(
                new HeadlessCoreStubError("Decryption key ID not present", 500),
            );
        });

        it("throws error with 500 if kms key not retrieved", async () => {
            process.env.DECRYPTION_KEY_ID = "abc123";
            await expect(getPublicEncryptionKey(audience)).rejects.toThrow(
                new HeadlessCoreStubError("Unable to retrieve public encryption key", 500),
            );
        });

        it("retrieves public encryption key", async () => {
            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: "spki",
                    format: "der",
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "der",
                },
            });
            const keyBuffer = Buffer.from(publicKey);

            process.env.DECRYPTION_KEY_ID = "abc123";

            const mockKMSClient = mockClient(KMSClient);
            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: keyBuffer });

            const result = await getPublicEncryptionKey(audience);
            expect(result?.type).toEqual("public");
        });
    });

    describe("getPublicEncryptionKey - jwks uri", () => {
        let originalFetch: typeof global.fetch;

        beforeEach(() => {
            originalFetch = global.fetch;
        });

        afterEach(() => {
            global.fetch = originalFetch;
            clearCaches();
            delete process.env.DECRYPTION_KEY_ID;
        });

        it("retrieves public encryption key from JWKS endpoint", async () => {
            const mockJwks = {
                keys: [{ kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "dummy-n", kid: "dummy-kid" }],
            };
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED == "true";

            global.fetch = jest.fn().mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve(mockJwks),
            });

            const result = await getPublicEncryptionKey("https://test-audience.co.uk");

            expect(result).toBeDefined();
            expect(result?.type).toBe("public");
        });

        it("falls back to KMS if JWKS fetch fails", async () => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED == "false";

            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: "spki",
                    format: "der",
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "der",
                },
            });

            const keyBuffer = Buffer.from(publicKey);
            process.env.DECRYPTION_KEY_ID = "abc123";

            const mockKMSClient = mockClient(KMSClient);
            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: keyBuffer });

            const result = await getPublicEncryptionKey(audience);
            expect(result).toBeDefined();
            expect(result?.type).toBe("public");
        });
    });

    describe("encryptSignedJwt", () => {
        it("creates encrypted signed jwt", async () => {
            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: "spki",
                    format: "der",
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "der",
                },
            });
            const keyBuffer = Buffer.from(publicKey);

            process.env.DECRYPTION_KEY_ID = "abc123";

            const mockKMSClient = mockClient(KMSClient);
            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: keyBuffer });

            const publicEncryptionKey = await getPublicEncryptionKey(audience);

            const result = await encryptSignedJwt(TestData.jwt, publicEncryptionKey as KeyLike);
            expect(result).toMatch(
                /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
            );
        });
    });
});
