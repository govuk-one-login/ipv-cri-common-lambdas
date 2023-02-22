import { createDecipheriv } from "crypto";
import { KMSClient } from "@aws-sdk/client-kms";
import { JweDecrypter } from "../../../../src/services/security/jwe-decrypter";

jest.mock("crypto", () => ({
    createDecipheriv: jest.fn().mockReturnValueOnce({
        setAuthTag: jest.fn(),
        setAAD: jest.fn(),
        update: jest.fn().mockReturnValueOnce(Buffer.from("decrypted content")),
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
        const decoded_iv = new Uint8Array([1, 2, 3, 4]);
        const result = await jweDecrypter.decryptJwe(compactJwe);

        expect(getEncryptionKeyId).toHaveBeenCalled();
        expect(createDecipheriv).toHaveBeenCalledWith("aes-256-gcm", decryptedContentEncKey, decoded_iv, {
            authTagLength: 16,
        });
        expect(result).toEqual(Buffer.from("decrypted content"));
    });

    it("throws error when decrypts JWE fails", async () => {
        createDecipheriv("aes-256-gcm", decryptedContentEncKey, expect.any(Uint8Array), {});

        await expect(jweDecrypter.decryptJwe(compactJwe)).rejects.toThrowError(
            expect.objectContaining({
                statusCode: 403,
                message:
                    "Session Validation Error\", \"Invalid request - JWE decryption failed :TypeError: Cannot read properties of undefined (reading 'setAuthTag')",
            }),
        );
    });
    it("throws an error if number of JWE parts is not 5", async () => {
        await expect(jweDecrypter.decryptJwe("header.encrypted-key.iv.ciphertext")).rejects.toThrowError(
            "Invalid number of JWE parts encountered: 4",
        );
    });

    it("should throw an error on KmsClient send operation", async () => {
        const kmsClientMock = <jest.Mock>kmsClient.send;
        kmsClientMock.mockRejectedValue(new Error("Some KMS client error"));

        await expect(jweDecrypter.decryptJwe(compactJwe)).rejects.toThrowError("Some KMS client error");
    });
});
