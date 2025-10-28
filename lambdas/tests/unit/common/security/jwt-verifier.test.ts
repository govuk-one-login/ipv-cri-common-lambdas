import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerificationConfig } from "../../../../src/types/jwt-verification-config";
import { JwtVerifier, JwtVerifierFactory } from "../../../../src/common/security/jwt-verifier";
import * as jose from "jose";
import { JWTHeaderParameters, jwtVerify } from "jose";

jest.mock("jose", () => ({
    importJWK: jest.fn(),
    jwtVerify: jest.fn(),
    createLocalJWKSet: jest.fn(),
}));

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

            beforeEach(() => {
                jwtVerifierConfig = {
                    publicSigningJwk: "publicSigningJwk",
                    jwtSigningAlgorithm: "ES256",
                    jwksEndpoint: "http://localhost",
                };
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

                beforeEach(() => {
                    global.fetch = jest.fn();
                    jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger as Logger);
                    jwtVerifyMock.mockResolvedValue({
                        payload: MOCK_JWT,
                        protectedHeader: {} as JWTHeaderParameters,
                    } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);
                });

                afterEach(() => {
                    jest.clearAllMocks();
                    jwtVerifier.clearJWKSCacheForAllEndpoints();
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
                    expect(logger.info).toHaveBeenCalledWith("Using JWKS endpoint: http://localhost");
                    expect(logger.info).toHaveBeenCalledWith("Fetching new JWKS from http://localhost...");
                    expect(logger.info).toHaveBeenCalledWith("Successfully verified JWT using Public JWKS Endpoint");
                });

                it("should successfully use the cached JWKS when populated", async () => {
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

                    jwtVerifier.clearJWKSCacheForAllEndpoints();
                    const payloadThree = await jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues);
                    expect(payloadThree).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(2);
                });

                it("should be able to cache separate JWKS for different endpoints simultaneously", async () => {
                    (global.fetch as jest.Mock).mockResolvedValue({
                        headers: {
                            get: jest.fn().mockReturnValue("max-age=300"),
                        },
                        json: jest.fn().mockResolvedValue(MOCK_JWKS),
                        status: 200,
                        ok: true,
                    });

                    const verifierOne = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointA" }, logger);
                    const payloadOne = await verifierOne.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadOne).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(1);

                    const verifierTwo = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointA" }, logger);
                    const payloadTwo = await verifierTwo.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadTwo).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(1);

                    const verifierThree = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointB" }, logger);
                    const payloadThree = await verifierThree.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadThree).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(2);

                    const verifierFour = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointA" }, logger);
                    const payloadFour = await verifierFour.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadFour).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(2);

                    const verifierFive = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointB" }, logger);
                    const payloadFive = await verifierFive.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadFive).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(2);
                });

                it("should be able to clear cached JWKS for single endpoints without affecting other caches", async () => {
                    (global.fetch as jest.Mock).mockResolvedValue({
                        headers: {
                            get: jest.fn().mockReturnValue("max-age=300"),
                        },
                        json: jest.fn().mockResolvedValue(MOCK_JWKS),
                        status: 200,
                        ok: true,
                    });

                    const verifierOne = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointA" }, logger);
                    const payloadOne = await verifierOne.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadOne).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(1);

                    const verifierTwo = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointB" }, logger);
                    const payloadTwo = await verifierTwo.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadTwo).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(2);

                    verifierTwo.clearJWKSCacheForCurrentEndpoint();

                    const verifierThree = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointA" }, logger);
                    const payloadThree = await verifierThree.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadThree).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(2);

                    const verifierFour = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointB" }, logger);
                    const payloadFour = await verifierFour.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadFour).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(3);

                    const verifierFive = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "endpointB" }, logger);
                    const payloadFive = await verifierFive.verify(encodedJwt, mandatoryClaims, expectedClaimValues);

                    expect(payloadFive).toEqual(MOCK_JWT);
                    expect(global.fetch).toHaveBeenCalledTimes(3);
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
                });

                describe("JWKS Endpoint fail", () => {
                    it("should throw when jwksEndpoint is not set", async () => {
                        jwtVerifier = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "" }, logger as Logger);

                        await expect(
                            jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues),
                        ).rejects.toThrowError(
                            'Unable to retrieve jwksEndpoint SSM param from JWT verifier config! Got: ""',
                        );
                    });

                    it("should throw when jwksEndpoint is not a valid url", async () => {
                        jwtVerifier = new JwtVerifier(
                            { ...jwtVerifierConfig, jwksEndpoint: "localhost" },
                            logger as Logger,
                        );

                        await expect(
                            jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues),
                        ).rejects.toThrowError("Cannot read properties of undefined (reading 'ok')");
                    });

                    it("should throw if JWKS endpoint does not return 200", async () => {
                        (global.fetch as jest.Mock).mockResolvedValueOnce({
                            status: 400,
                            ok: false,
                        });

                        await expect(
                            jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues),
                        ).rejects.toThrowError("Error received from the JWKS endpoint, status received: 400");
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

                        const mandatoryClaimsFail = new Set(["iss", "sub", "abc"]);

                        await expect(
                            jwtVerifier.verify(encodedJwt, mandatoryClaimsFail, expectedClaimValues),
                        ).rejects.toThrowError("Claims-set missing mandatory claim: abc");
                    });
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
