import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { mockClient } from "aws-sdk-client-mock";
import { generateKeyPairSync } from "node:crypto";
import { HeadlessCoreStubError } from "../../../../utils/src/errors/headless-core-stub-error";
import {
    encryptSignedJwt,
    getPublicEncryptionKey,
    _resetCachedPublicKeyForTest,
} from "../../src/services/signing-service";
import { TestData } from "../../../../utils/tests/test-data";

import * as jose from "jose";
import { vi, describe, expect, it, beforeEach, afterEach } from "vitest";

vi.mock("jose", { spy: true });

describe("signing-service", () => {
    const audience = "https://test-audience.com";
    const mockKMSClient = mockClient(KMSClient);
    let originalFetch: typeof global.fetch;

    const resetEnvironment = () => {
        _resetCachedPublicKeyForTest();
        mockKMSClient.reset();
        vi.resetAllMocks();
        delete process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED;
        delete process.env.DECRYPTION_KEY_ID;
        global.fetch = originalFetch;
    };

    beforeEach(() => {
        originalFetch = global.fetch;
        vi.resetModules();
        _resetCachedPublicKeyForTest();
    });

    afterEach(() => {
        resetEnvironment();
    });

    describe("encryptSignedJwt", () => {
        it("creates encrypted signed jwt", async () => {
            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: { type: "spki", format: "der" },
                privateKeyEncoding: { type: "pkcs8", format: "der" },
            });

            const keyBuffer = Buffer.from(publicKey);
            process.env.DECRYPTION_KEY_ID = "abc123";

            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: keyBuffer });

            const publicEncryptionKey = await getPublicEncryptionKey(audience);
            const result = await encryptSignedJwt(TestData.jwt, publicEncryptionKey as jose.KeyLike);

            expect(result).toMatch(
                /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
            );
        });
    });

    describe("getPublicEncryptionKey - kms", () => {
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
                publicKeyEncoding: { type: "spki", format: "der" },
                privateKeyEncoding: { type: "pkcs8", format: "der" },
            });

            process.env.DECRYPTION_KEY_ID = "abc123";
            const keyBuffer = Buffer.from(publicKey);

            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: keyBuffer });

            const result = await getPublicEncryptionKey(audience);
            expect(result?.type).toEqual("public");
        });
    });

    describe("getPublicEncryptionKey - jwks uri", () => {
        beforeEach(() => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED = "true";
        });

        it("retrieves the last public encryption key from JWKS", async () => {
            const mockJwks = {
                keys: [
                    { kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "dummy-n", kid: "dummy-kid" },
                    { kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "dummy-n", kid: "dummy-kid_2" },
                ],
            };

            global.fetch = vi.fn().mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve(mockJwks),
            });

            const spyImportJWK = vi.spyOn(jose, "importJWK").mockImplementation(async (key: jose.JWK) => {
                expect(key?.kid).toBe("dummy-kid_2");
                return { type: "public" } as jose.KeyLike;
            });

            const result = await getPublicEncryptionKey(audience);
            expect(result?.type).toBe("public");
            expect(spyImportJWK).toHaveBeenCalledWith(expect.objectContaining({ kid: "dummy-kid_2" }), "RSA-OAEP-256");
        });

        it("retrieves public encryption key from JWKS endpoint", async () => {
            const mockJwks = {
                keys: [{ kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "dummy-n", kid: "dummy-kid" }],
            };

            global.fetch = vi.fn().mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve(mockJwks),
            });

            const result = await getPublicEncryptionKey(audience);
            expect(result).toBeDefined();
            expect(result?.type).toBe("public");
        });

        it("falls back to KMS if JWKS with enc isn't found", async () => {
            const mockJwks = {
                keys: [
                    {
                        kty: "EC",
                        use: "sig",
                        crv: "P-256",
                        kid: "74c5",
                        x: "x",
                        y: "y",
                        alg: "ES256",
                    },
                ],
            };

            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: { type: "spki", format: "der" },
                privateKeyEncoding: { type: "pkcs8", format: "der" },
            });

            global.fetch = vi.fn().mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve(mockJwks),
            });

            process.env.DECRYPTION_KEY_ID = "abc123";
            const keyBuffer = Buffer.from(publicKey);

            mockKMSClient
                .on(GetPublicKeyCommand, { KeyId: "abc123" })
                .resolvesOnce({ PublicKey: keyBuffer })
                .resolvesOnce({ PublicKey: keyBuffer });

            const result = await getPublicEncryptionKey(audience);
            expect(result?.type).toBe("public");
        });

        it("falls back to KMS if JWKS fetch fails", async () => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED = "false";

            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: { type: "spki", format: "der" },
                privateKeyEncoding: { type: "pkcs8", format: "der" },
            });

            const keyBuffer = Buffer.from(publicKey);
            process.env.DECRYPTION_KEY_ID = "abc123";

            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: keyBuffer });

            const result = await getPublicEncryptionKey(audience);
            expect(result?.type).toBe("public");
        });
    });

    describe("getPublicEncryptionKey caching behavior", () => {
        it("fetches key only once from JWKS when called multiple times", async () => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED = "true";

            const mockJwks = {
                keys: [{ kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "mocked-n", kid: "mocked-kid" }],
            };

            const fetchSpy = vi.fn().mockResolvedValue({
                headers: {
                    get: vi.fn().mockReturnValue("max-age=300"),
                },
                ok: true,
                json: () => Promise.resolve(mockJwks),
            });

            global.fetch = fetchSpy;
            const importSpy = vi.spyOn(jose, "importJWK").mockResolvedValue({ type: "public" } as jose.KeyLike);

            const key1 = await getPublicEncryptionKey(audience);
            const key2 = await getPublicEncryptionKey(audience);

            expect(key1).toEqual(key2);
            expect(fetchSpy).toHaveBeenCalledTimes(1);
            expect(importSpy).toHaveBeenCalledTimes(1);
        });

        it("refetches after cache reset", async () => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED = "true";

            const mockJwks = {
                keys: [{ kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "mocked-n", kid: "mocked-kid" }],
            };

            const fetchSpy = vi.fn().mockResolvedValue({
                ok: true,
                json: () => Promise.resolve(mockJwks),
            });

            global.fetch = fetchSpy;
            vi.spyOn(jose, "importJWK").mockResolvedValue({ type: "public" } as jose.KeyLike);

            await getPublicEncryptionKey(audience);
            _resetCachedPublicKeyForTest();
            await getPublicEncryptionKey(audience);

            expect(fetchSpy).toHaveBeenCalledTimes(2);
        });

        it("falls back to KMS if no JWKS encryption key is found", async () => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED = "true";
            process.env.DECRYPTION_KEY_ID = "abc123";

            const mockJwks = {
                keys: [{ kty: "RSA", e: "AQAB", use: "sig", alg: "RS256", n: "ignored" }],
            };

            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: { type: "spki", format: "der" },
                privateKeyEncoding: { type: "pkcs8", format: "der" },
            });

            const keyBuffer = Buffer.from(publicKey);

            global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(mockJwks) });
            mockKMSClient
                .on(GetPublicKeyCommand, { KeyId: "abc123" })
                .resolvesOnce({ PublicKey: keyBuffer })
                .resolvesOnce({ PublicKey: keyBuffer });

            const importSpy = vi.spyOn(jose, "importSPKI").mockResolvedValue({ type: "public" } as jose.KeyLike);

            const key1 = await getPublicEncryptionKey(audience);
            const key2 = await getPublicEncryptionKey(audience);

            expect(key1).toEqual(key2);
            expect(importSpy).toHaveBeenCalledTimes(2);
        });

        it("throws if KMS fails and cache is not set", async () => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED = "false";
            process.env.DECRYPTION_KEY_ID = "abc123";

            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolves({ PublicKey: undefined });

            await expect(getPublicEncryptionKey(audience)).rejects.toThrow("Unable to retrieve public encryption key");
        });

        it("refetches JWKS if cache has expired", async () => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED = "true";

            const mockJwks = {
                keys: [{ kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "mocked-n", kid: "mocked-kid" }],
            };

            const fetchSpy = vi
                .fn()
                .mockResolvedValueOnce({
                    headers: {
                        get: vi.fn().mockReturnValueOnce("max-age=300"),
                    },
                    ok: true,
                    json: () => Promise.resolve(mockJwks),
                })
                .mockResolvedValueOnce({
                    headers: {
                        get: vi.fn().mockReturnValueOnce("max-age=300"),
                    },
                    ok: true,
                    json: () => Promise.resolve(mockJwks),
                });

            global.fetch = fetchSpy;
            const importSpy = vi
                .spyOn(jose, "importJWK")
                .mockResolvedValueOnce({ type: "public" } as jose.KeyLike)
                .mockResolvedValueOnce({ type: "public" } as jose.KeyLike);

            const now = Date.now();
            const dateNowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

            await getPublicEncryptionKey(audience);

            const expiredTtl10MinutesLater = now + 1000 * 60 * 10;
            dateNowSpy.mockImplementation(() => expiredTtl10MinutesLater);

            await getPublicEncryptionKey(audience);

            expect(fetchSpy).toHaveBeenCalledTimes(2);
            expect(importSpy).toHaveBeenCalledTimes(2);
            dateNowSpy.mockRestore();
        });

        it("does not refetch if JWKS cache is still valid", async () => {
            process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED = "true";

            const mockJwks = {
                keys: [{ kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "mocked-n", kid: "mocked-kid" }],
            };

            const fetchSpy = vi.fn().mockResolvedValueOnce({
                headers: {
                    get: vi.fn().mockReturnValueOnce("max-age=300"),
                },
                ok: true,
                json: () => Promise.resolve(mockJwks),
            });

            global.fetch = fetchSpy;
            const importSpy = vi.spyOn(jose, "importJWK").mockResolvedValueOnce({ type: "public" } as jose.KeyLike);

            await getPublicEncryptionKey(audience);

            const fourMinuteWithinTtl = Date.now() + 1000 * 60 * 4;
            vi.spyOn(Date, "now").mockReturnValue(fourMinuteWithinTtl);

            await getPublicEncryptionKey(audience);

            expect(fetchSpy).toHaveBeenCalledTimes(1);
            expect(importSpy).toHaveBeenCalledTimes(1);
        });
    });
});
