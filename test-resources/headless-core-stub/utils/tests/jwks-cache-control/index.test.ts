import { JSONWebKeySet } from "jose";
import { describe, it, expect, vi, beforeEach } from "vitest";
import {
    clearJWKSCache,
    parseCacheControlMaxAge,
    isJWKSCacheValid,
    getCachedJWKS,
    fetchAndCacheJWKS,
} from "../../src/jwks-cache-control";

global.fetch = vi.fn();

const mockLogger = {
    info: vi.fn(),
};

const fakeJWKS: JSONWebKeySet = {
    keys: [
        {
            kty: "RSA",
            kid: "test-key-id",
            use: "enc",
            n: "some-modulus",
            e: "AQAB",
        },
    ],
};

const fetchMock = vi.mocked(fetch);
describe("JWKS Cache Control", () => {
    beforeEach(() => {
        clearJWKSCache();
        vi.clearAllMocks();
    });

    describe("parseCacheControlMaxAge", () => {
        it("parses valid max-age correctly", () => {
            const now = Date.now();
            const result = parseCacheControlMaxAge("public, max-age=60");

            expect(result).toBeGreaterThanOrEqual(now + 60000);
            expect(result).toBeLessThanOrEqual(now + 61000);
        });

        it("returns expiry in the past for invalid input", () => {
            const result = parseCacheControlMaxAge(undefined);

            expect(result).toBeLessThan(Date.now());
        });

        it("returns expiry in the past if max-age is not present", () => {
            const result = parseCacheControlMaxAge("no-cache");

            expect(result).toBeLessThan(Date.now());
        });
    });

    describe("JWKS cache operations", () => {
        it("initially has no valid cache", () => {
            expect(isJWKSCacheValid()).toBe(false);

            expect(getCachedJWKS()).toBeNull();
        });

        it("fetches and caches JWKS", async () => {
            const mockResponse = {
                ok: true,
                json: async () => fakeJWKS,
                headers: {
                    get: () => "max-age=60",
                },
            };

            fetchMock.mockResolvedValueOnce(mockResponse as unknown as Response);

            await fetchAndCacheJWKS(new URL("https://a-cri-endpoint.co.uk/.well-known/jwks.json"), mockLogger);

            expect(getCachedJWKS()).toEqual(fakeJWKS);
            expect(isJWKSCacheValid()).toBe(true);
            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringMatching(/JWKS cache has been updated/));
        });

        it("throws if fetch fails", async () => {
            fetchMock.mockResolvedValueOnce({
                ok: false,
                status: 500,
            } as Response);

            await expect(
                fetchAndCacheJWKS(new URL("https://a-cri-endpoint.co.uk/.well-known/jwks.json"), mockLogger),
            ).rejects.toThrow("Error received from the JWKS endpoint, status received: 500");
        });

        it("clears the cache", async () => {
            const mockResponse = {
                ok: true,
                json: async () => fakeJWKS,
                headers: {
                    get: () => "max-age=60",
                },
            };

            fetchMock.mockResolvedValueOnce(mockResponse as unknown as Response);
            await fetchAndCacheJWKS(new URL("https://example.com"), mockLogger);

            clearJWKSCache();

            expect(isJWKSCacheValid()).toBe(false);
            expect(getCachedJWKS()).toBeNull();
        });
    });
});
