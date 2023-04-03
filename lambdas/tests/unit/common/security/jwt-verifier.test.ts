import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerificationConfig } from "../../../../src/types/jwt-verification-config";
import { JwtVerifier, JwtVerifierFactory } from "../../../../src/common/security/jwt-verifier";
import * as jose from "jose";
import { importJWK, JWTHeaderParameters, jwtVerify } from "jose";
import { JwkKeyExportOptions } from "crypto";
jest.mock("jose", () => ({
    importJWK: jest.fn(),
    jwtVerify: jest.fn(),
}));

describe("jwt-verifier.ts", () => {
    let logger: Logger;
    describe("JwtVerifier", () => {
        let signingPublicJwk: jose.JWK;
        let jwtVerifierConfig: JwtVerificationConfig;
        let jwtVerifyOptions: JwkKeyExportOptions;

        beforeEach(() => {
            signingPublicJwk = {
                alg: "ES256",
                kty: "kty",
                use: "use",
                x: "x",
                y: "y",
            };
            jwtVerifierConfig = {
                publicSigningJwk: "publicSigningJwk",
                jwtSigningAlgorithm: "ES256",
            };
            jwtVerifyOptions = {
                algorithms: ["ES256"],
                audience: "some-audience",
                issuer: "some-issuer",
                subject: "some-subject",
            } as unknown as JwkKeyExportOptions;
        });

        describe("verify", () => {
            let publicKey: Uint8Array;
            let jwtVerifier: JwtVerifier;

            beforeEach(() => {
                logger = {
                    error: jest.fn(),
                } as unknown as Logger;
                publicKey = new Uint8Array([3, 101, 120, 26, 14, 184, 5, 99, 172, 149]);
                jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger as Logger);
            });

            afterEach(() => {
                jest.clearAllMocks();
            });

            it("should succeed with a JWT that has signing key in config but not in JWK", async () => {
                delete signingPublicJwk.alg;
                jwtVerifierConfig.jwtSigningAlgorithm = "ECDSA";
                const untypedJwtVerifyOptions = jwtVerifyOptions as unknown as { algorithms: Array<string> };
                untypedJwtVerifyOptions.algorithms = ["ECDSA"];

                const encodedJwt = Buffer.from("example.encoded.jwt");
                jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
                jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

                const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;
                const jwtVerifyMock = jwtVerify as jest.MockedFunction<typeof jwtVerify>;
                const mandatoryClaims = new Set(["iss", "sub"]);
                const expectedClaimValues = new Map([
                    ["iss", "some-issuer"],
                    ["sub", "some-subject"],
                    ["aud", "some-audience"],
                ]);
                const jwtPayload = {
                    iss: "some-issuer",
                    sub: "some-subject",
                    aud: "some-audience",
                };
                importJWKMock.mockResolvedValueOnce(publicKey);
                jwtVerifyMock.mockResolvedValueOnce({
                    payload: jwtPayload,
                    protectedHeader: {} as JWTHeaderParameters,
                } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

                const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                expect(payload).toEqual({
                    iss: "some-issuer",
                    sub: "some-subject",
                    aud: "some-audience",
                });
                expect(Buffer.from).toHaveBeenCalledWith("publicSigningJwk", "base64");
                expect(JSON.parse).toHaveBeenCalledWith("example.encoded.jwt");
                expect(importJWKMock).toBeCalledWith(signingPublicJwk, jwtVerifierConfig.jwtSigningAlgorithm);
                expect(jwtVerifyMock).toBeCalledWith(encodedJwt, publicKey, jwtVerifyOptions);
                expect(logger.error).not.toHaveBeenCalled();
            });

            it("should succeed with a JWT that has signing key and mandatory claims", async () => {
                const encodedJwt = Buffer.from("example.encoded.jwt");
                jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
                jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

                const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;
                const jwtVerifyMock = jwtVerify as jest.MockedFunction<typeof jwtVerify>;
                const mandatoryClaims = new Set(["iss", "sub"]);
                const expectedClaimValues = new Map([
                    ["iss", "some-issuer"],
                    ["sub", "some-subject"],
                    ["aud", "some-audience"],
                ]);
                const jwtPayload = {
                    iss: "some-issuer",
                    sub: "some-subject",
                    aud: "some-audience",
                };
                importJWKMock.mockResolvedValueOnce(publicKey);
                jwtVerifyMock.mockResolvedValueOnce({
                    payload: jwtPayload,
                    protectedHeader: {} as JWTHeaderParameters,
                } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

                const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                expect(payload).toEqual({
                    iss: "some-issuer",
                    sub: "some-subject",
                    aud: "some-audience",
                });
                expect(Buffer.from).toHaveBeenCalledWith("publicSigningJwk", "base64");
                expect(JSON.parse).toHaveBeenCalledWith("example.encoded.jwt");
                expect(importJWKMock).toBeCalledWith(signingPublicJwk, signingPublicJwk.alg);
                expect(jwtVerifyMock).toBeCalledWith(encodedJwt, publicKey, jwtVerifyOptions);
                expect(logger.error).not.toHaveBeenCalled();
            });
            it("should return null when mandatory claim is missing in JWT payload", async () => {
                const encodedJwt = Buffer.from("example.encoded.jwt");
                jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
                jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

                const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;
                const jwtVerifyMock = jwtVerify as jest.MockedFunction<typeof jwtVerify>;

                const mandatoryClaims = new Set(["iss", "sub"]);
                const expectedClaimValues = new Map([
                    ["iss", "some-issuer"],
                    ["sub", "some-subject"],
                    ["aud", "some-audience"],
                ]);
                const jwtPayload = {
                    iss: "some-issuer",
                    aud: "some-audience",
                };

                importJWKMock.mockResolvedValueOnce(publicKey);
                jwtVerifyMock.mockResolvedValueOnce({
                    payload: jwtPayload,
                    protectedHeader: {} as JWTHeaderParameters,
                } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

                const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                expect(payload).toBeNull();
                expect(logger.error).toHaveBeenCalledWith(
                    "JWT verification failed",
                    Error("Claims-set missing mandatory claim: sub"),
                );
            });

            it("should return null when it fails to import JWK", async () => {
                jest.spyOn(jose, "importJWK").mockRejectedValue(new Error("Failed to import JWK"));
                jest.spyOn(global.JSON, "parse").mockReturnValueOnce("some-parsed-value");
                const encodedJwt = Buffer.from("expect.jwt.value");

                const payload = await jwtVerifier.verify(
                    encodedJwt,
                    new Set(["iss"]),
                    new Map([["iss", "some-issuer"]]),
                );

                expect(payload).toBeNull();
                expect(logger.error).toHaveBeenCalledWith("JWT verification failed", Error("Failed to import JWK"));
            });

            it("should return null when it fails to verify JWT", async () => {
                jest.spyOn(jose, "jwtVerify").mockRejectedValue(new Error("JWT verification failed"));
                jest.spyOn(global.JSON, "parse").mockReturnValueOnce("some-parsed-value");
                const encodedJwt = Buffer.from("expect.jwt.value");
                const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;
                importJWKMock.mockResolvedValueOnce(publicKey);

                const payload = await jwtVerifier.verify(
                    encodedJwt,
                    new Set(["iss"]),
                    new Map([["iss", "some-issuer"]]),
                );

                expect(payload).toBeNull();
                expect(logger.error).toHaveBeenCalledWith("JWT verification failed", Error("JWT verification failed"));
            });
            it("should return null and log an error if JWT verification fails due to invalid public signing jwk", async () => {
                const encodedJwt = Buffer.from("exampleEncodedJwt");

                const payload = await jwtVerifier.verify(
                    encodedJwt,
                    new Set(["iss"]),
                    new Map([["iss", "some-issuer"]]),
                );

                expect(payload).toBeNull();
                expect(logger.error).toHaveBeenCalledWith(
                    "JWT verification failed",
                    Error("Unexpected token � in JSON at position 0"),
                );
            });
            it("should return null and log an error if one of JWT verification Options is invalid", async () => {
                const jwtVerifyOptions = {
                    algorithms: ["HS256"],
                    audience: "some-audience",
                    issuer: "some-issuer",
                    subject: "some-subject",
                } as unknown as JwkKeyExportOptions;
                const encodedJwt = Buffer.from("example.encoded.jwt");
                jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
                jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

                const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;
                const jwtVerifyMock = jwtVerify as jest.MockedFunction<typeof jwtVerify>;

                const mandatoryClaims = new Set(["iss", "sub"]);
                const expectedClaimValues = new Map([
                    ["iss", "some-issuer"],
                    ["sub", "some-subject"],
                    ["aud", "some-audience"],
                ]);
                importJWKMock.mockResolvedValueOnce(publicKey);

                const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                expect(payload).toBeNull;
                expect(Buffer.from).toHaveBeenCalledWith("publicSigningJwk", "base64");
                expect(JSON.parse).toHaveBeenCalledWith("example.encoded.jwt");
                expect(importJWKMock).toBeCalledWith(signingPublicJwk, signingPublicJwk.alg);
                expect(jwtVerifyMock).not.toBeCalledWith(encodedJwt, publicKey, jwtVerifyOptions);
                expect(logger.error).toHaveBeenCalledWith("JWT verification failed", Error("JWT verification failed"));
            });
            it("should return null when mandatory claims is empty", async () => {
                const encodedJwt = Buffer.from("example.encoded.jwt");
                jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
                jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

                const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;
                const jwtVerifyMock = jwtVerify as jest.MockedFunction<typeof jwtVerify>;

                const mandatoryClaims = new Set([]);
                const expectedClaimValues = new Map([
                    ["iss", "some-issuer"],
                    ["sub", "some-subject"],
                    ["aud", "some-audience"],
                ]);
                const jwtPayload = {
                    iss: "some-issuer",
                    sub: "some-subject",
                    aud: "some-audience",
                };

                importJWKMock.mockResolvedValueOnce(publicKey);
                jwtVerifyMock.mockResolvedValueOnce({
                    payload: jwtPayload,
                    protectedHeader: {} as JWTHeaderParameters,
                } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

                const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                expect(payload).toBeNull;
                expect(Buffer.from).toHaveBeenCalledWith("publicSigningJwk", "base64");
                expect(JSON.parse).toHaveBeenCalledWith("example.encoded.jwt");
                expect(importJWKMock).toBeCalledWith(signingPublicJwk, signingPublicJwk.alg);
                expect(jwtVerifyMock).toBeCalledWith(encodedJwt, publicKey, jwtVerifyOptions);
                expect(logger.error).toHaveBeenCalledWith(
                    "JWT verification failed",
                    Error("No mandatory claims provided"),
                );
            });
            it("should return null when mandatory claims is undefined", async () => {
                const encodedJwt = Buffer.from("example.encoded.jwt");
                jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
                jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

                const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;
                const jwtVerifyMock = jwtVerify as jest.MockedFunction<typeof jwtVerify>;

                const expectedClaimValues = new Map([
                    ["iss", "some-issuer"],
                    ["sub", "some-subject"],
                    ["aud", "some-audience"],
                ]);
                const jwtPayload = {
                    iss: "some-issuer",
                    sub: "some-subject",
                    aud: "some-audience",
                };

                importJWKMock.mockResolvedValueOnce(publicKey);
                jwtVerifyMock.mockResolvedValueOnce({
                    payload: jwtPayload,
                    protectedHeader: {} as JWTHeaderParameters,
                } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

                const payload = await jwtVerifier.verify(
                    encodedJwt,
                    undefined as unknown as Set<string>,
                    expectedClaimValues,
                );

                expect(payload).toBeNull;
                expect(Buffer.from).toHaveBeenCalledWith("publicSigningJwk", "base64");
                expect(JSON.parse).toHaveBeenCalledWith("example.encoded.jwt");
                expect(importJWKMock).toBeCalledWith(signingPublicJwk, signingPublicJwk.alg);
                expect(jwtVerifyMock).toBeCalledWith(encodedJwt, publicKey, jwtVerifyOptions);
                expect(logger.error).toHaveBeenCalledWith(
                    "JWT verification failed",
                    Error("No mandatory claims provided"),
                );
            });
        });
    });

    describe("SessionRequestValidatorFactory", () => {
        let jwtVerifierFactory: JwtVerifierFactory;
        jest.mocked(JwtVerifier);
        jest.mocked(JwtVerifier);

        beforeEach(() => {
            jwtVerifierFactory = new JwtVerifierFactory(logger);
        });

        it("should create a session request validator", () => {
            const output = jwtVerifierFactory.create("test-signing-algo", "test-public-signing-key");
            expect(output).toBeInstanceOf(JwtVerifier);
        });
    });
});
