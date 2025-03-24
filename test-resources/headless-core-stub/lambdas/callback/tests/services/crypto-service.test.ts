import { buildPrivateKeyJwtParams, msToSeconds, isJWK } from "../../src/services/crypto-service";
import { SignJWT, importJWK, importPKCS8 } from "jose";
import sigFormatter from "ecdsa-sig-formatter";
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import { PrivateJwtParams } from "../../src/services/types";

jest.mock("ecdsa-sig-formatter");
jest.mock("jose", () => ({
    SignJWT: jest.fn(),
    importJWK: jest.fn(),
    importPKCS8: jest.fn(),
}));

jest.mock("@aws-sdk/client-kms", () => ({
    KMSClient: jest.fn(),
    SignCommand: jest.fn(),
}));

const kmsClientMock = KMSClient as jest.Mock;
const sigFormatterMock = sigFormatter.derToJose as jest.Mock;
const importJWKMock = importJWK as jest.Mock;
const mockSignJWT = SignJWT as jest.Mock;
const importPKCS8Mock = importPKCS8 as jest.Mock;
const mockSignJWTMock = SignJWT as jest.Mock;

describe("Crypto Service", () => {
    describe("signJwt", () => {
        const authorizationCode = "an-authorization-code";
        const clientId = "headless-core-stub";
        const audience = "my-audience";
        const redirectUri = "https://test-resources.headless-core-stub.redirect/callback";
        const mockJwtPayload = { sub: clientId, clientId, aud: audience, exp: 9999999, jti: "mock-jti" };
        const mockHeader = { alg: "ES256", typ: "JWT" };
        const mockPrivateSigningKey = "mock-key";
        const mockPrivateSigningKeyId = "mock-key-id";
        const mockJWKKey = { kty: "EC", d: "mock-d", x: "mock-x", y: "mock-y", crv: "P-256" };

        beforeEach(() => jest.clearAllMocks());

        it("signs JWT using KMS", async () => {
            const kmsMock = { send: jest.fn().mockResolvedValueOnce({ Signature: "mock-signature" }) };
            kmsClientMock.mockImplementationOnce(() => kmsMock);
            sigFormatterMock.mockReturnValueOnce("mock-signature");

            const result = await buildPrivateKeyJwtParams(
                {
                    customClaims: mockJwtPayload,
                    authorizationCode,
                    redirectUrl: redirectUri,
                    privateSigningKeyId: mockPrivateSigningKeyId,
                },
                mockHeader,
            );

            expect(KMSClient).toHaveBeenCalledWith({ region: "eu-west-2" });
            expect(kmsMock.send).toHaveBeenCalledWith(expect.any(SignCommand));
            expect(sigFormatter.derToJose).toHaveBeenCalledWith("bW9jay1zaWduYXR1cmU=", "ES256");
            expect(result).toContain("client_assertion_type");
        });

        it("signs JWT using PKCS8 private key", async () => {
            const mockSigningKey = "mock-imported-key";
            const mockSignedJwt = "mock-signed-jwt";

            importPKCS8Mock.mockResolvedValueOnce(mockSigningKey);
            mockSignJWTMock.mockImplementationOnce(() => ({
                setProtectedHeader: jest.fn().mockReturnThis(),
                sign: jest.fn().mockResolvedValueOnce(mockSignedJwt),
            }));

            const result = await buildPrivateKeyJwtParams(
                {
                    authorizationCode,
                    customClaims: mockJwtPayload,
                    redirectUrl: redirectUri,
                    privateSigningKey: mockPrivateSigningKey,
                },
                mockHeader,
            );

            expect(importPKCS8).toHaveBeenCalledWith(expect.stringContaining(mockPrivateSigningKey), "ES256");
            expect(SignJWT).toHaveBeenCalled();
            expect(result).toContain("client_assertion_type");
        });

        it("signs JWT using JWK", async () => {
            const mockSigningKey = "mock-imported-key";
            const mockSignedJwt = "mock-signed-jwt";

            importJWKMock.mockResolvedValueOnce(mockSigningKey);

            mockSignJWT.mockImplementationOnce(() => ({
                setProtectedHeader: jest.fn().mockReturnThis(),
                sign: jest.fn().mockResolvedValueOnce(mockSignedJwt),
            }));

            const result = await buildPrivateKeyJwtParams(
                {
                    authorizationCode,
                    customClaims: mockJwtPayload,
                    redirectUrl: redirectUri,
                    privateSigningKey: mockJWKKey,
                },
                mockHeader,
            );

            expect(importJWK).toHaveBeenCalledWith(mockJWKKey, "ES256");
            expect(SignJWT).toHaveBeenCalled();
            expect(result).toContain("client_assertion_type");
        });

        it("throws an error if no signing key is provided", async () => {
            await expect(
                buildPrivateKeyJwtParams(
                    {
                        authorizationCode,
                        customClaims: mockJwtPayload,
                        redirectUrl: redirectUri,
                    } as unknown as PrivateJwtParams,
                    mockHeader,
                ),
            ).rejects.toThrow("No signing key provided!");
        });
    });

    describe("msToSeconds", () => {
        it("correctly convert milliseconds to seconds", () => {
            const result = msToSeconds(5000);

            expect(result).toBe(5);
        });
    });

    describe("isJWK", () => {
        it("returns true for valid JWK object", () => {
            expect(
                isJWK({
                    alg: "RS256",
                    crv: "P-256",
                    e: "AQAB",
                    kty: "RSA",
                }),
            ).toBe(true);
        });

        it("returns false for non-JWK string", () => {
            expect(isJWK("not-a-jwk")).toBe(false);
        });
    });
});
