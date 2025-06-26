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
        kmsClientMock.mockRejectedValue(new Error("Failed to decrypt with legacy key"));

        await expect(jweDecrypter.decryptJwe(compactJwe)).rejects.toThrowError("Failed to decrypt with legacy key");
    });

    describe("session encrypted with legacy key", () => {
        beforeEach(() => {
            delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION;
            delete process.env.ENV_VAR_FEATURE_FLAG_LEGACY_KEY_FALLBACK;
        });
        describe("given key rotation flag is true", () => {
            describe("legacy fallback flag to true", () => {
                it("fails to decrypt with any alias initially, then the legacy key was successfully used for decryption", async () => {
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
                    process.env.ENV_VAR_FEATURE_FLAG_LEGACY_KEY_FALLBACK = "true";
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
                    expect(logger.info).toHaveBeenCalledWith({ message: "Decryption successful with legacy key" });
                });

                it("fails to decrypt with any alias initially, then the legacy key also failed at decryption", async () => {
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
                    process.env.ENV_VAR_FEATURE_FLAG_LEGACY_KEY_FALLBACK = "true";

                    const kmsClientMock = <jest.Mock>kmsClient.send;

                    kmsClientMock
                        .mockRejectedValueOnce(new Error("active alias failed"))
                        .mockRejectedValueOnce(new Error("inactive alias failed"))
                        .mockRejectedValueOnce(new Error("previous alias failed"))
                        .mockRejectedValueOnce(new Error("failed using KMS Id"));

                    const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

                    await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow("Failed to decrypt with legacy key");

                    expect(metrics.addMetric).toHaveBeenCalledWith(
                        "all_aliases_unavailable_for_decryption",
                        "Count",
                        1,
                    );
                    expect(logger.warn).toHaveBeenCalledWith({
                        message: "Key rotation enabled",
                        alias: "alias/session_decryption_key_previous_alias",
                        error: new Error("previous alias failed"),
                    });
                    expect(logger.warn).toHaveBeenCalledWith({
                        message: "Key rotation enabled",
                        alias: "alias/session_decryption_key_inactive_alias",
                        error: new Error("inactive alias failed"),
                    });
                    expect(logger.warn).toHaveBeenCalledWith({
                        message: "Key rotation enabled",
                        alias: "alias/session_decryption_key_active_alias",
                        error: new Error("active alias failed"),
                    });
                    expect(logger.error).toHaveBeenCalledWith(
                        expect.objectContaining({
                            message: "Legacy key decryption threw an exception",
                        }),
                    );
                    expect(logger.info).toHaveBeenCalledWith({
                        message: "Key rotation enabled",
                        status: "All aliases failed.",
                    });
                });
            });
            describe("legacy fallback flag to false", () => {
                it("fails when trying all aliases and legacy fallback disabled", async () => {
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
                    process.env.ENV_VAR_FEATURE_FLAG_LEGACY_KEY_FALLBACK = "false";

                    const kmsClientMock = <jest.Mock>kmsClient.send;
                    kmsClientMock
                        .mockRejectedValueOnce(new Error("active alias failed"))
                        .mockRejectedValueOnce(new Error("inactive alias failed"))
                        .mockRejectedValueOnce(new Error("previous alias failed"));

                    const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

                    await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow(
                        "Failed to decrypt with all available key aliases.",
                    );

                    expect(metrics.addMetric).toHaveBeenCalledWith(
                        "all_aliases_unavailable_for_decryption",
                        "Count",
                        1,
                    );
                });
            });
            it("decrypts successfully using active alias", async () => {
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

            it("fails to decrypt with the other aliases but succeeds decryption using the previous alias", async () => {
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
        });
        describe("given key rotation flag is false", () => {
            beforeEach(() => {
                delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION;
                delete process.env.ENV_VAR_FEATURE_FLAG_LEGACY_KEY_FALLBACK;
            });
            it("decrypts using legacy Kms key Id", async () => {
                process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "false";

                const kmsClientMock = <jest.Mock>kmsClient.send;
                kmsClientMock.mockResolvedValueOnce({ Plaintext: new Uint8Array([1, 2, 3, 4]) });

                const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);
                const result = await decrypter.decryptJwe(compactJwe);

                expect(result).toBeInstanceOf(Buffer);
                expect(kmsClientMock).toHaveBeenCalledTimes(1);
                expect(result).toBeInstanceOf(Buffer);
                expect(logger.info).toHaveBeenCalledWith({ message: "Decryption successful with legacy key" });
            });
            it("throws an error if legacy Key fails using Kms Id", async () => {
                process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "false";
                const kmsClientMock = <jest.Mock>kmsClient.send;
                kmsClientMock.mockRejectedValueOnce(new Error("KMS decryption failed"));

                const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

                await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow("Failed to decrypt with legacy key");
                expect(kmsClientMock).toHaveBeenCalledTimes(1);
            });
        });
    });
    describe("session encrypted with active key alias", () => {
        beforeEach(() => {
            delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION;
            delete process.env.ENV_VAR_FEATURE_FLAG_LEGACY_KEY_FALLBACK;
        });
        describe("given key rotation flag is true", () => {
            it("decrypts successfully using active alias", async () => {
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
        });
        describe("given key rotation flag is false", () => {
            beforeEach(() => {
                delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION;
                delete process.env.ENV_VAR_FEATURE_FLAG_LEGACY_KEY_FALLBACK;
            });
            it("decrypts fails using legacy Kms key Id", async () => {
                process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "false";
                const kmsClientMock = <jest.Mock>kmsClient.send;
                kmsClientMock.mockRejectedValueOnce(new Error("KMS decryption failed"));

                const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

                await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow("Failed to decrypt with legacy key");
                expect(kmsClientMock).toHaveBeenCalledTimes(1);
            });
        });
    });
});
