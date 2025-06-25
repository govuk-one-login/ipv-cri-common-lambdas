import { createDecipheriv } from "crypto";
import { KMSClient } from "@aws-sdk/client-kms";
import { JweDecrypter } from "../../../../src/services/security/jwe-decrypter";
import { logger, metrics } from "../../../../src/common/utils/power-tool";

jest.mock("../../../../src/common/utils/power-tool", () => ({
    logger: {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
    },
    metrics: {
        addMetric: jest.fn(),
    },
    tracer: {
        captureLambdaHandler: (handler: unknown) => handler,
    },
}));

jest.mock("crypto", () => ({
    createDecipheriv: jest.fn().mockReturnValue({
        setAuthTag: jest.fn(),
        setAAD: jest.fn(),
        update: jest.fn().mockReturnValue(Buffer.from("decrypted content")),
        final: jest.fn(),
    }),
}));

jest.mock("@aws-sdk/client-kms", () => ({
    KMSClient: jest.fn(() => ({
        send: jest.fn().mockResolvedValue({
            Plaintext: "decryptedContentEncKey",
        }),
    })),
    DecryptCommand: jest.fn(() => ({})),
    EncryptionAlgorithmSpec: {
        RSAES_OAEP_SHA_256: "RSAES_OAEP_SHA_256",
    },
}));

jest.mock("jose", () => ({
    base64url: {
        decode: jest.fn().mockReturnValue(new Uint8Array([1, 2, 3, 4])),
    },
}));

const decryptedContentEncKey = "decryptedContentEncKey";
const decodedIv = new Uint8Array([1, 2, 3, 4]);

describe("JweDecrypter", () => {
    let kmsClient: KMSClient;
    let jweDecrypter: JweDecrypter;
    const getEncryptionKeyId = jest.fn();
    const jweProtectedHeader = {
        alg: "RSA-OAEP",
        enc: "A256GCM",
        kid: "kid",
    };
    const compactJwe = `${jweProtectedHeader}.${"encryptedKey"}.${"iv"}.${"ciphertext"}.${"tag"}`;

    beforeEach(() => {
        kmsClient = new KMSClient({});
        jweDecrypter = new JweDecrypter(kmsClient, getEncryptionKeyId.mockReturnValueOnce("test-key-id"));
        jest.spyOn(JSON, "parse").mockReturnValueOnce(jweProtectedHeader);
        jest.clearAllMocks();
    });

    it("decrypts JWE", async () => {
        const result = await jweDecrypter.decryptJwe(compactJwe);

        expect(getEncryptionKeyId).toHaveBeenCalled();
        expect(createDecipheriv).toHaveBeenCalledWith("aes-256-gcm", decryptedContentEncKey, decodedIv, {
            authTagLength: 16,
        });
        expect(result).toEqual(Buffer.from("decrypted content"));
    });

    it("throws error when decrypts JWE fails", async () => {
        (createDecipheriv as jest.Mock).mockReturnValueOnce({
            setAAD: jest.fn(),
            update: jest.fn(),
            final: jest.fn(),
        });

        await expect(jweDecrypter.decryptJwe(compactJwe)).rejects.toMatchObject({
            statusCode: 403,
            message: expect.stringContaining("Invalid request - JWE decryption failed"),
        });
    });
    it("throws an error if number of JWE parts is not 5", async () => {
        await expect(jweDecrypter.decryptJwe("header.encrypted-key.iv.ciphertext")).rejects.toThrowError(
            "Invalid number of JWE parts encountered: 4",
        );
    });

    it("should throw an error on KmsClient send operation", async () => {
        const kmsClientMock = <jest.Mock>kmsClient.send;
        kmsClientMock.mockRejectedValue(new Error("Failed to decrypt CEK with any available alias or KMS Id"));

        await expect(jweDecrypter.decryptJwe(compactJwe)).rejects.toThrowError(
            "Failed to decrypt CEK with any available alias or KMS Id",
        );
    });

    describe("decryption using kms alias", () => {
        beforeEach(() => {
            delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION;
        });
        it("decrypts using an alias successfully", async () => {
            process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";

            const kmsClientMock = <jest.Mock>kmsClient.send;
            kmsClientMock.mockResolvedValueOnce({ Plaintext: new Uint8Array([1, 2, 3, 4]) });

            const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);
            const result = await decrypter.decryptJwe(compactJwe);

            expect(result).toBeInstanceOf(Buffer);
            expect(kmsClientMock).toHaveBeenCalledTimes(1);
            expect(logger.info).toHaveBeenCalledWith({
                message: "Key rotation enabled",
                status: "Successfully decrypted using Alias",
                alias: "alias/session_decryption_key_active_alias",
            });
        });

        it("decrypts using kms Id given key rotation flag is false", async () => {
            process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "false";

            const kmsClientMock = <jest.Mock>kmsClient.send;
            kmsClientMock.mockResolvedValueOnce({ Plaintext: new Uint8Array([1, 2, 3, 4]) });

            const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);
            const result = await decrypter.decryptJwe(compactJwe);

            expect(result).toBeInstanceOf(Buffer);
            expect(kmsClientMock).toHaveBeenCalledTimes(1);
            expect(result).toBeInstanceOf(Buffer);
            expect(logger.info).toHaveBeenCalledWith({ message: "Successfully decrypted using KMS Id" });
        });

        it("throws error if KMS decryption fails using KMS ID only", async () => {
            process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "false";
            const kmsClientMock = <jest.Mock>kmsClient.send;
            kmsClientMock.mockRejectedValueOnce(new Error("KMS decryption failed"));

            const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

            await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow(
                "Failed to decrypt CEK with any available alias or KMS Id",
            );
            expect(kmsClientMock).toHaveBeenCalledTimes(1);
        });

        it("fails to decrypt with some alias but succeeds decryption using an alias successfully", async () => {
            process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
            const kmsClientMock = <jest.Mock>kmsClient.send;
            const decodedIv = new Uint8Array([1, 2, 3, 4]);

            kmsClientMock
                .mockRejectedValueOnce(new Error("active alias failed"))
                .mockRejectedValueOnce(new Error("inactive alias failed"))
                .mockResolvedValueOnce({ Plaintext: decodedIv });

            const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);
            const result = await decrypter.decryptJwe(compactJwe);

            expect(result).toBeInstanceOf(Buffer);
            expect(kmsClientMock).toHaveBeenCalledTimes(3);
            expect(logger.info).toHaveBeenCalledWith({
                message: "Key rotation enabled",
                status: "Successfully decrypted using Alias",
                alias: "alias/session_decryption_key_previous_alias",
            });
        });

        it("uses KMS ID to after trying all aliases and failing", async () => {
            process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
            const kmsClientMock = <jest.Mock>kmsClient.send;
            const decodedIv = new Uint8Array([1, 2, 3, 4]);

            kmsClientMock
                .mockRejectedValueOnce(new Error("active alias failed"))
                .mockRejectedValueOnce(new Error("inactive alias failed"))
                .mockRejectedValueOnce(new Error("previous alias failed"))
                .mockResolvedValueOnce({ Plaintext: decodedIv });

            const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);
            const result = await decrypter.decryptJwe(compactJwe);

            expect(result).toBeInstanceOf(Buffer);
            expect(kmsClientMock).toHaveBeenCalledTimes(4);
            expect(logger.info).toHaveBeenCalledWith({
                message: "Key rotation enabled",
                status: "All aliases failed.",
            });
            expect(logger.info).toHaveBeenCalledWith({ message: "Successfully decrypted using KMS Id" });
        });

        it("throws if all decryption attempts fail", async () => {
            process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
            const kmsClientMock = <jest.Mock>kmsClient.send;

            kmsClientMock
                .mockRejectedValueOnce(new Error("active alias failed"))
                .mockRejectedValueOnce(new Error("inactive alias failed"))
                .mockRejectedValueOnce(new Error("previous alias failed"))
                .mockRejectedValueOnce(new Error("failed using KMS Id"));

            const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

            await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow(
                "Failed to decrypt CEK with any available alias or KMS Id",
            );

            expect(metrics.addMetric).toHaveBeenCalledWith("all_aliases_unavailable_for_decryption", "Count", 1);
            expect(logger.error).toHaveBeenCalledWith({
                message: "Key rotation enabled",
                alias: "alias/session_decryption_key_previous_alias",
                error: new Error("previous alias failed"),
            });
            expect(logger.error).toHaveBeenCalledWith({
                message: "Key rotation enabled",
                alias: "alias/session_decryption_key_inactive_alias",
                error: new Error("inactive alias failed"),
            });
            expect(logger.error).toHaveBeenCalledWith({
                message: "Key rotation enabled",
                alias: "alias/session_decryption_key_active_alias",
                error: new Error("active alias failed"),
            });
            expect(logger.error).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: "Failed to decrypt with KMS keyId",
                }),
            );
            expect(logger.info).toHaveBeenCalledWith({
                message: "Key rotation enabled",
                status: "All aliases failed.",
            });
        });
    });
});
