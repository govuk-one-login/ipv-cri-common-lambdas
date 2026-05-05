import { createDecipheriv } from "node:crypto";
import { KMSClient } from "@aws-sdk/client-kms";
import { JweDecrypter } from "../../../../src/services/security/jwe-decrypter";
import { logger } from "@govuk-one-login/cri-logger";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { Decipher } from "node:crypto";
import { captureMetric } from "@govuk-one-login/cri-metrics";

vi.mock("@govuk-one-login/cri-logger", () => ({
    logger: {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
    },
}));

vi.mock("@govuk-one-login/cri-metrics", () => ({
    metrics: {
        addDimension: vi.fn(),
        publishStoredMetrics: vi.fn(),
        logMetrics: vi.fn(),
    },
    captureMetric: vi.fn(),
}));

vi.mock("crypto", () => ({
    createDecipheriv: vi.fn().mockReturnValue({
        setAuthTag: vi.fn(),
        setAAD: vi.fn(),
        update: vi.fn().mockReturnValue(Buffer.from("decrypted content")),
        final: vi.fn(),
    }),
}));

vi.mock("@aws-sdk/client-kms", async (importOriginal) => ({
    ...(await importOriginal()),
    KMSClient: vi.fn(function () {
        return {
            send: vi.fn().mockResolvedValue({
                Plaintext: "decryptedContentEncKey",
            }),
        };
    }),
    EncryptionAlgorithmSpec: {
        RSAES_OAEP_SHA_256: "RSAES_OAEP_SHA_256",
    },
}));

vi.mock("jose", () => ({
    base64url: {
        decode: vi.fn().mockReturnValue(new Uint8Array([1, 2, 3, 4])),
    },
}));

const decryptedContentEncKey = "decryptedContentEncKey";
const decodedIv = new Uint8Array([1, 2, 3, 4]);

describe("JweDecrypter", () => {
    let kmsClient: KMSClient;
    let jweDecrypter: JweDecrypter;
    const getEncryptionKeyId = vi.fn();
    const jweProtectedHeader = {
        alg: "RSA-OAEP",
        enc: "A256GCM",
        kid: "kid",
    };
    const compactJwe = `${jweProtectedHeader}.${"encryptedKey"}.${"iv"}.${"ciphertext"}.${"tag"}`;

    beforeEach(() => {
        kmsClient = new KMSClient({});
        jweDecrypter = new JweDecrypter(kmsClient, getEncryptionKeyId.mockReturnValueOnce("test-key-id"));
        vi.spyOn(JSON, "parse").mockReturnValueOnce(jweProtectedHeader);
        vi.clearAllMocks();
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
        vi.mocked(createDecipheriv).mockReturnValueOnce({
            setAAD: vi.fn(),
            update: vi.fn(),
            final: vi.fn(),
        } as unknown as Decipher);

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
        const kmsClientMock = vi.mocked(kmsClient.send);
        kmsClientMock.mockRejectedValue(new Error("Failed to decrypt with legacy key"));

        await expect(jweDecrypter.decryptJwe(compactJwe)).rejects.toThrowError("Failed to decrypt with legacy key");
    });

    describe("session encrypted with legacy key", () => {
        beforeEach(() => {
            delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION;
            delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK;
        });
        describe("given key rotation flag is true", () => {
            describe("legacy fallback flag to true", () => {
                it("fails to decrypt with any alias initially, then the legacy key was successfully used for decryption", async () => {
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK = "true";
                    const kmsClientMock = vi.mocked(kmsClient.send);
                    const decodedIv = new Uint8Array([1, 2, 3, 4]);

                    kmsClientMock
                        .mockRejectedValueOnce(new Error("active alias failed"))
                        .mockRejectedValueOnce(new Error("inactive alias failed"))
                        .mockRejectedValueOnce(new Error("previous alias failed"))
                        .mockImplementationOnce(() => ({ Plaintext: decodedIv }));

                    const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);
                    const result = await decrypter.decryptJwe(compactJwe);

                    expect(result).toBeInstanceOf(Buffer);
                    expect(kmsClientMock).toHaveBeenCalledTimes(4);
                    expect(logger.info).toHaveBeenCalledWith({ message: "Decryption successful with legacy key" });
                });

                it("fails to decrypt with any alias initially, then the legacy key also failed at decryption", async () => {
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK = "true";

                    const kmsClientMock = vi.mocked(kmsClient.send);

                    kmsClientMock
                        .mockRejectedValueOnce(new Error("active alias failed"))
                        .mockRejectedValueOnce(new Error("inactive alias failed"))
                        .mockRejectedValueOnce(new Error("previous alias failed"))
                        .mockRejectedValueOnce(new Error("failed using KMS Id"));

                    const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

                    await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow("Failed to decrypt with legacy key");

                    expect(captureMetric).toHaveBeenCalledWith("all_aliases_unavailable_for_decryption");
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
                    expect(captureMetric).toHaveBeenCalledWith("all_aliases_unavailable_for_decryption");
                });
            });
            describe("legacy fallback flag to false", () => {
                it("fails when trying all aliases and legacy fallback disabled", async () => {
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";
                    process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK = "false";

                    const kmsClientMock = vi.mocked(kmsClient.send);
                    kmsClientMock
                        .mockRejectedValueOnce(new Error("active alias failed"))
                        .mockRejectedValueOnce(new Error("inactive alias failed"))
                        .mockRejectedValueOnce(new Error("previous alias failed"));

                    const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

                    await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow(
                        "Failed to decrypt with all available key aliases.",
                    );

                    expect(captureMetric).toHaveBeenCalledWith("all_aliases_unavailable_for_decryption");
                });
            });
            it("decrypts successfully using active alias", async () => {
                process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";

                const kmsClientMock = vi.mocked(kmsClient.send);
                kmsClientMock.mockImplementation(() => ({ Plaintext: new Uint8Array([1, 2, 3, 4]) }));

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
                const kmsClientMock = vi.mocked(kmsClient.send);
                const decodedIv = new Uint8Array([1, 2, 3, 4]);

                kmsClientMock
                    .mockRejectedValueOnce(new Error("active alias failed"))
                    .mockRejectedValueOnce(new Error("inactive alias failed"))
                    .mockImplementationOnce(() => ({ Plaintext: decodedIv }));

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
                delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK;
            });
            it("decrypts using legacy Kms key Id", async () => {
                process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "false";

                const kmsClientMock = vi.mocked(kmsClient.send);
                kmsClientMock.mockImplementation(() => ({ Plaintext: new Uint8Array([1, 2, 3, 4]) }));

                const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);
                const result = await decrypter.decryptJwe(compactJwe);

                expect(result).toBeInstanceOf(Buffer);
                expect(kmsClientMock).toHaveBeenCalledTimes(1);
                expect(result).toBeInstanceOf(Buffer);
                expect(logger.info).toHaveBeenCalledWith({ message: "Decryption successful with legacy key" });
            });
            it("throws an error if legacy Key fails using Kms Id", async () => {
                process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "false";
                const kmsClientMock = vi.mocked(kmsClient.send);
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
            delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK;
        });
        describe("given key rotation flag is true", () => {
            it("decrypts successfully using active alias", async () => {
                process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "true";

                const kmsClientMock = vi.mocked(kmsClient.send);
                kmsClientMock.mockImplementation(() => ({ Plaintext: new Uint8Array([1, 2, 3, 4]) }));

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
                delete process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK;
            });
            it("decrypts fails using legacy Kms key Id", async () => {
                process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION = "false";
                const kmsClientMock = vi.mocked(kmsClient.send);
                kmsClientMock.mockRejectedValueOnce(new Error("KMS decryption failed"));

                const decrypter = new JweDecrypter(kmsClient, getEncryptionKeyId);

                await expect(decrypter.decryptJwe(compactJwe)).rejects.toThrow("Failed to decrypt with legacy key");
                expect(kmsClientMock).toHaveBeenCalledTimes(1);
            });
        });
    });
});
