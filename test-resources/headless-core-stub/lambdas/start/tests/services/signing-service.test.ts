import { clearCaches } from "@aws-lambda-powertools/parameters";
import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { mockClient } from "aws-sdk-client-mock";
import { generateKeyPairSync } from "crypto";
import { HeadlessCoreStubError } from "../../src/errors/headless-core-stub-error";
import { encryptSignedJwt, getPublicEncryptionKey } from "../../src/services/signing-service";
import { TestData } from "../../../../utils/tests/test-data";

describe("crypto-service", () => {
    describe("getPublicEncryptionKey", () => {
        const mockKMSClient = mockClient(KMSClient);

        afterEach(() => {
            mockKMSClient.reset();
            clearCaches();
        });

        it("throws error with 500 if decryption key env variable not set", async () => {
            await expect(getPublicEncryptionKey()).rejects.toThrow(
                new HeadlessCoreStubError("Decryption key ID not present", 500),
            );
        });

        it("throws error with 500 if kms key not retrieved", async () => {
            process.env.DECRYPTION_KEY_ID = "abc123";
            await expect(getPublicEncryptionKey()).rejects.toThrow(
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

            const result = await getPublicEncryptionKey();
            expect(result.type).toEqual("public");
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

            const publicEncryptionKey = await getPublicEncryptionKey();

            const result = await encryptSignedJwt(TestData.jwt, publicEncryptionKey);
            expect(result).toMatch(
                /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
            );
        });
    });
});
