import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerificationConfig } from "../../../../src/types/jwt-verification-config";
import { JwtVerifier, JwtVerifierFactory } from "../../../../src/common/security/jwt-verifier";
import * as jose from "jose";
import { importJWK, JWTHeaderParameters, jwtVerify } from "jose";
import { JwkKeyExportOptions } from "crypto";

jest.mock("jose", () => ({
    importJWK: jest.fn(),
    jwtVerify: jest.fn(),
    createLocalJWKSet: jest.fn(),
}));

type JwkKeyExtendedExportOptions = JwkKeyExportOptions & {
    algorithms: string[];
    audience: string;
    issuer: string;
    subject: string;
};

describe("jwt-verifier.ts", () => {
    let logger: Logger;

    beforeEach(() => {
        logger = {
            error: jest.fn(),
            info: jest.fn(),
        } as unknown as Logger;
    });

    describe("JwtVerifier", () => {
        let jwtVerifier: JwtVerifier;

        describe("verify", () => {
            let jwtVerifierConfig: JwtVerificationConfig;
            let jwtVerifyOptions: JwkKeyExtendedExportOptions;

            beforeEach(() => {
                jwtVerifierConfig = {
                    publicSigningJwk: "publicSigningJwk",
                    jwtSigningAlgorithm: "ES256",
                    jwksEndpoint: "http://localhost",
                };
                jwtVerifyOptions = {
                    algorithms: ["ES256"],
                    audience: "some-audience",
                    issuer: "some-issuer",
                    subject: "some-subject",
                } as unknown as JwkKeyExtendedExportOptions;
            });

            describe("JWKS Endpoint", () => {
                const MOCK_JWKS = {
                    keys: [
                        { kty: "RSA", e: "AQAB", use: "enc", alg: "RS256", n: "dummy-n", kid: "dummy-kid" },
                        {
                            kty: "EC",
                            use: "sig",
                            crv: "P-256",
                            x: "dummy-x",
                            y: "dummy-y",
                            alg: "ES256",
                            kid: "dummy-kid",
                        },
                    ],
                };
                const MOCK_JWT = {
                    iss: "some-issuer",
                    sub: "some-subject",
                    aud: "some-audience",
                };
                const encodedJwt = Buffer.from("example.encoded.jwt");
                const mandatoryClaims = new Set(["iss", "sub"]);
                const expectedClaimValues = new Map([
                    ["iss", "some-issuer"],
                    ["sub", "some-subject"],
                    ["aud", "some-audience"],
                ]);
                const jwtVerifyMock = jwtVerify as jest.MockedFunction<typeof jwtVerify>;
                let verifyWithJwksParamSpy: jest.SpyInstance;

                beforeEach(() => {
                    global.fetch = jest.fn();
                    process.env.ENV_VAR_FEATURE_CONSUME_PUBLIC_JWK = "true";
                    jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger as Logger);
                    jwtVerifyMock.mockResolvedValue({
                        payload: MOCK_JWT,
                        protectedHeader: {} as JWTHeaderParameters,
                    } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);
                    // @ts-expect-error: Private function
                    verifyWithJwksParamSpy = jest.spyOn(jwtVerifier, "verifyWithJwksParam");
                });

                afterEach(() => {
                    jest.clearAllMocks();
                    jwtVerifier.clearJWKSCache();
                });

                it("should successfully verify JWT using JWKS endpoint", async () => {
                    (global.fetch as jest.Mock).mockResolvedValueOnce({
                        headers: {
                            get: jest.fn().mockReturnValueOnce("max-age=300"),
                        },
                        json: jest.fn().mockResolvedValueOnce(MOCK_JWKS),
                        status: 200,
                        ok: true,
                    });

                    const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payload).toEqual(MOCK_JWT);
                    expect(verifyWithJwksParamSpy).not.toHaveBeenCalled();
                    expect(logger.info).toHaveBeenCalledWith("Sucessfully verified JWT using Public JWKS Endpoint");
                });

                it("should successfully uses the cached JWKS when populated", async () => {
                    (global.fetch as jest.Mock).mockResolvedValue({
                        headers: {
                            get: jest.fn().mockReturnValue("max-age=300"),
                        },
                        json: jest.fn().mockResolvedValue(MOCK_JWKS),
                        status: 200,
                        ok: true,
                    });

                    const payloadOne = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);
                    expect(payloadOne).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(1);

                    const payloadTwo = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);
                    expect(payloadTwo).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(1);

                    jwtVerifier.clearJWKSCache();
                    const payloadThree = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);
                    expect(payloadThree).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(2);

                    expect(verifyWithJwksParamSpy).toHaveBeenCalledTimes(0);
                });

                it("should successfully verify JWT using JWKS endpoint when Cache-Control regex does not match", async () => {
                    (global.fetch as jest.Mock).mockResolvedValueOnce({
                        headers: {
                            get: jest.fn().mockReturnValueOnce("no-cache"),
                        },
                        json: jest.fn().mockResolvedValueOnce(MOCK_JWKS),
                        status: 200,
                        ok: true,
                    });

                    const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payload).toEqual(MOCK_JWT);
                    expect(verifyWithJwksParamSpy).toHaveBeenCalledTimes(0);
                });

                it("should successfully verify JWT using JWKS endpoint when Cache-Control header is not present", async () => {
                    (global.fetch as jest.Mock).mockResolvedValueOnce({
                        headers: {
                            get: jest.fn().mockReturnValueOnce(null),
                        },
                        json: jest.fn().mockResolvedValueOnce(MOCK_JWKS),
                        status: 200,
                        ok: true,
                    });

                    const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payload).toEqual(MOCK_JWT);
                    expect(verifyWithJwksParamSpy).toHaveBeenCalledTimes(0);
                });

                describe("JWKS Endpoint fail and fallback", () => {
                    it("should use fallback method when jwksEndpoint is not set", async () => {
                        jwtVerifier = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "" }, logger as Logger);

                        // @ts-expect-error: Private function
                        const fallbackSpy = jest.spyOn(jwtVerifier, "verifyWithJwksParam").mockImplementation(() => {
                            return {
                                iss: "some-issuer",
                                sub: "some-subject",
                                aud: "some-audience",
                            };
                        });
                        const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                        expect(fallbackSpy).toBeCalledTimes(1);
                        expect(fallbackSpy).toHaveBeenCalledWith(encodedJwt, mandatoryClaims, jwtVerifyOptions);
                        expect(payload).toEqual({
                            iss: "some-issuer",
                            sub: "some-subject",
                            aud: "some-audience",
                        });
                    });

                    it("should use fallback method when jwksEndpoint is not a valid url", async () => {
                        jwtVerifier = new JwtVerifier(
                            { ...jwtVerifierConfig, jwksEndpoint: "localhost" },
                            logger as Logger,
                        );

                        // @ts-expect-error: Private function
                        const fallbackSpy = jest.spyOn(jwtVerifier, "verifyWithJwksParam").mockImplementation(() => {
                            return {
                                iss: "some-issuer",
                                sub: "some-subject",
                                aud: "some-audience",
                            };
                        });
                        const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                        expect(fallbackSpy).toBeCalledTimes(1);
                        expect(fallbackSpy).toHaveBeenCalledWith(encodedJwt, mandatoryClaims, jwtVerifyOptions);
                        expect(payload).toEqual({
                            iss: "some-issuer",
                            sub: "some-subject",
                            aud: "some-audience",
                        });
                    });

                    it("should use fallback method if JWKS endpoint does not return 200", async () => {
                        (global.fetch as jest.Mock).mockResolvedValueOnce({
                            status: 400,
                            ok: false,
                        });

                        jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger as Logger);
                        // @ts-expect-error: Private function
                        const fallbackSpy = jest.spyOn(jwtVerifier, "verifyWithJwksParam").mockImplementation(() => {
                            return {
                                iss: "some-issuer",
                                sub: "some-subject",
                                aud: "some-audience",
                            };
                        });
                        const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                        expect(fallbackSpy).toBeCalledTimes(1);
                        expect(fallbackSpy).toHaveBeenCalledWith(encodedJwt, mandatoryClaims, jwtVerifyOptions);
                        expect(payload).toEqual({
                            iss: "some-issuer",
                            sub: "some-subject",
                            aud: "some-audience",
                        });
                    });

                    it("should fail if JWT does not have mandatory claims", async () => {
                        (global.fetch as jest.Mock).mockResolvedValueOnce({
                            headers: {
                                get: jest.fn().mockReturnValueOnce("max-age=300"),
                            },
                            json: jest.fn().mockResolvedValueOnce(MOCK_JWKS),
                            status: 200,
                            ok: true,
                        });

                        jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger as Logger);
                        // @ts-expect-error: Private function
                        const fallbackSpy = jest.spyOn(jwtVerifier, "verifyWithJwksParam").mockImplementation(() => {
                            return null;
                        });
                        const mandatoryClaimsFail = new Set(["iss", "sub", "abc"]);
                        const payload = await jwtVerifier.verify(encodedJwt, mandatoryClaimsFail, expectedClaimValues);

                        expect(fallbackSpy).toBeCalledTimes(1);
                        expect(fallbackSpy).toHaveBeenCalledWith(encodedJwt, mandatoryClaimsFail, jwtVerifyOptions);
                        expect(payload).toEqual(null);
                    });
                });
            });

            describe("JWKS Param", () => {
                let publicKey: Uint8Array;
                let signingPublicJwk: jose.JWK;

                beforeEach(() => {
                    logger = {
                        error: jest.fn(),
                        info: jest.fn(),
                    } as unknown as Logger;
                    publicKey = new Uint8Array([3, 101, 120, 26, 14, 184, 5, 99, 172, 149]);
                    process.env.ENV_VAR_FEATURE_CONSUME_PUBLIC_JWK = "false";
                    jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger as Logger);
                    signingPublicJwk = {
                        alg: "ES256",
                        kty: "kty",
                        use: "use",
                        x: "x",
                        y: "y",
                    };
                });

                afterEach(() => {
                    jest.clearAllMocks();
                });

                it("should succeed with a JWT that has signing key in config but not in JWK", async () => {
                    delete signingPublicJwk.alg;
                    jwtVerifierConfig.jwtSigningAlgorithm = "ECDSA";
                    jwtVerifyOptions.algorithms = ["ECDSA"];

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
                        "JWT verification failed with JWKS parameter",
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
                    expect(logger.error).toHaveBeenCalledWith(
                        "JWT verification failed with JWKS parameter",
                        Error("Failed to import JWK"),
                    );
                });

                it("should return null when it fails to verify JWT", async () => {
                    jest.spyOn(jose, "jwtVerify").mockRejectedValue(
                        new Error("JWT verification failed with JWKS parameter"),
                    );
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
                    expect(logger.error).toHaveBeenCalledWith(
                        "JWT verification failed with JWKS parameter",
                        Error("JWT verification failed with JWKS parameter"),
                    );
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
                        "JWT verification failed with JWKS parameter",
                        expect.objectContaining({ message: expect.stringMatching(/Unexpected token '?�'?/) }),
                    );
                });
                it("should return null and log an error if one of JWT verification Options is invalid", async () => {
                    const jwtVerifyOptions = {
                        algorithms: ["HS256"],
                        audience: "some-audience",
                        issuer: "some-issuer",
                        subject: "some-subject",
                    };

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
                    expect(logger.error).toHaveBeenCalledWith(
                        "JWT verification failed with JWKS parameter",
                        Error("JWT verification failed with JWKS parameter"),
                    );
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
                        "JWT verification failed with JWKS parameter",
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
                        "JWT verification failed with JWKS parameter",
                        Error("No mandatory claims provided"),
                    );
                });
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
            const output = jwtVerifierFactory.create(
                "test-signing-algo",
                "test-public-signing-key",
                "http://localhost",
            );
            expect(output).toBeInstanceOf(JwtVerifier);
        });
    });
});
