import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerifier, JwtVerifierFactory } from "../../../../src/common/security/jwt-verifier";
import { JwtVerificationConfig } from "../../../../src/types/jwt-verification-config";
import * as jose from "jose";
import { importJWK, JWTHeaderParameters, jwtVerify } from "jose";

jest.mock("jose", () => ({
    importJWK: jest.fn(),
    jwtVerify: jest.fn(),
    createLocalJWKSet: jest.fn(),
}));

describe("jwt-verifier", () => {
    let logger: Logger;
    let jwtVerifier: JwtVerifier;
    let jwtVerifierConfig: JwtVerificationConfig;

    let publicKey: Uint8Array;
    let signingPublicJwk: jose.JWK;

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

        logger = {
            error: jest.fn(),
            info: jest.fn(),
        } as unknown as Logger;

        publicKey = new Uint8Array([3, 101, 120, 26, 14, 184, 5, 99, 172, 149]);

        jwtVerifierConfig = {
            publicSigningJwk: "publicSigningJwk",
            jwtSigningAlgorithm: "ES256",
            jwksEndpoint: "http://localhost",
        };

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
        jwtVerifier.clearJWKSCacheForAllEndpoints();
        jest.clearAllMocks();
    });

    it("should succeed with a JWT that has signing key and mandatory claims", async () => {
        const encodedJwt = Buffer.from("example.encoded.jwt");

        (global.fetch as jest.Mock).mockResolvedValueOnce({
            headers: {
                get: jest.fn().mockReturnValue("max-age=300"),
            },
            json: jest.fn().mockResolvedValueOnce(encodedJwt),
            status: 200,
            ok: true,
        });

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
    });

    it("should throw an error when mandatory claim is missing in JWT payload", async () => {
        const encodedJwt = Buffer.from("example.encoded.jwt");

        (global.fetch as jest.Mock).mockResolvedValueOnce({
            headers: {
                get: jest.fn().mockReturnValue("max-age=300"),
            },
            json: jest.fn().mockResolvedValueOnce(encodedJwt),
            status: 200,
            ok: true,
        });

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

        await expect(jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues)).rejects.toThrowError(
            "Claims-set missing mandatory claim: sub",
        );
        expect(logger.error).toHaveBeenCalledWith(
            "JWT verification failed with JWKS Endpoint",
            Error("Claims-set missing mandatory claim: sub"),
        );
    });

    it("should throw an error when it fails to import JWK", async () => {
        jest.spyOn(jose, "importJWK").mockRejectedValue(new Error("Failed to import JWK"));
        jest.spyOn(global.JSON, "parse").mockReturnValueOnce("some-parsed-value");
        const encodedJwt = Buffer.from("expect.jwt.value");

        (global.fetch as jest.Mock).mockResolvedValueOnce({
            headers: {
                get: jest.fn().mockReturnValue("max-age=300"),
            },
            json: jest.fn().mockResolvedValueOnce(encodedJwt),
            status: 200,
            ok: true,
        });

        await expect(
            jwtVerifier.verify(encodedJwt, new Set(["iss"]), new Map([["iss", "some-issuer"]])),
        ).rejects.toThrowError();
    });

    it("should throw an error when it fails to verify JWT", async () => {
        jest.spyOn(jose, "jwtVerify").mockRejectedValue(new Error("JWT verification failed with JWKS Endpoint"));
        jest.spyOn(global.JSON, "parse").mockReturnValueOnce("some-parsed-value");
        const encodedJwt = Buffer.from("expect.jwt.value");
        const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;
        importJWKMock.mockResolvedValueOnce(publicKey);

        (global.fetch as jest.Mock).mockResolvedValueOnce({
            headers: {
                get: jest.fn().mockReturnValue("max-age=300"),
            },
            json: jest.fn().mockResolvedValueOnce(encodedJwt),
            status: 200,
            ok: true,
        });

        await expect(
            jwtVerifier.verify(encodedJwt, new Set(["iss"]), new Map([["iss", "some-issuer"]])),
        ).rejects.toThrowError("JWT verification failed with JWKS Endpoint");
        expect(logger.error).toHaveBeenCalledWith(
            "JWT verification failed with JWKS Endpoint",
            Error("JWT verification failed with JWKS Endpoint"),
        );
    });

    it("should throw and log an error if JWT verification fails due to invalid public signing jwk", async () => {
        const encodedJwt = Buffer.from("exampleEncodedJwt");

        (global.fetch as jest.Mock).mockResolvedValueOnce({
            headers: {
                get: jest.fn().mockReturnValue("max-age=300"),
            },
            json: jest.fn().mockResolvedValueOnce(encodedJwt),
            status: 200,
            ok: true,
        });

        await expect(
            jwtVerifier.verify(encodedJwt, new Set(["iss"]), new Map([["iss", "some-issuer"]])),
        ).rejects.toThrowError();

        expect(logger.error).toHaveBeenCalledWith(
            expect.stringContaining("JWT verification failed with JWKS Endpoint"),
            expect.any(Error),
        );
    });

    it("should thrown and log an error if one of JWT verification Options is invalid", async () => {
        const encodedJwt = Buffer.from("example.encoded.jwt");

        (global.fetch as jest.Mock).mockResolvedValueOnce({
            headers: {
                get: jest.fn().mockReturnValue("max-age=300"),
            },
            json: jest.fn().mockResolvedValueOnce(encodedJwt),
            status: 200,
            ok: true,
        });

        jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
        jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

        const importJWKMock = importJWK as jest.MockedFunction<typeof importJWK>;

        const mandatoryClaims = new Set(["iss", "sub"]);
        const expectedClaimValues = new Map([
            ["iss", "some-issuer"],
            ["sub", "some-subject"],
            ["aud", "some-audience"],
        ]);
        importJWKMock.mockResolvedValueOnce(publicKey);

        await expect(jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues)).rejects.toThrowError();

        expect(logger.error).toHaveBeenCalledWith(
            expect.stringContaining("JWT verification failed with JWKS Endpoint"),
            expect.any(Error),
        );
    });

    it("should throw an error when mandatory claims is empty", async () => {
        const encodedJwt = Buffer.from("example.encoded.jwt");
        jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
        jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

        (global.fetch as jest.Mock).mockResolvedValueOnce({
            headers: {
                get: jest.fn().mockReturnValue("max-age=300"),
            },
            json: jest.fn().mockResolvedValueOnce(encodedJwt),
            status: 200,
            ok: true,
        });

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

        await expect(jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues)).rejects.toThrowError();

        expect(logger.error).toHaveBeenCalledWith(
            "JWT verification failed with JWKS Endpoint",
            Error("No mandatory claims provided"),
        );
    });

    it("should throw an error when mandatory claims is undefined", async () => {
        const encodedJwt = Buffer.from("example.encoded.jwt");
        jest.spyOn(global.Buffer, "from").mockReturnValueOnce(encodedJwt);
        jest.spyOn(global.JSON, "parse").mockReturnValueOnce(signingPublicJwk);

        (global.fetch as jest.Mock).mockResolvedValueOnce({
            headers: {
                get: jest.fn().mockReturnValue("max-age=300"),
            },
            json: jest.fn().mockResolvedValueOnce(encodedJwt),
            status: 200,
            ok: true,
        });

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

        await expect(
            jwtVerifier.verify(encodedJwt, undefined as unknown as Set<string>, expectedClaimValues),
        ).rejects.toThrowError();

        expect(logger.error).toHaveBeenCalledWith(
            "JWT verification failed with JWKS Endpoint",
            Error("No mandatory claims provided"),
        );
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

        jwtVerifyMock.mockResolvedValue({
            payload: MOCK_JWT,
            protectedHeader: {} as JWTHeaderParameters,
        } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

        const jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger);
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

        jwtVerifyMock.mockResolvedValue({
            payload: MOCK_JWT,
            protectedHeader: {} as JWTHeaderParameters,
        } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

        const jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger);

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

        jwtVerifyMock.mockResolvedValue({
            payload: MOCK_JWT,
            protectedHeader: {} as JWTHeaderParameters,
        } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

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

        jwtVerifyMock.mockResolvedValue({
            payload: MOCK_JWT,
            protectedHeader: {} as JWTHeaderParameters,
        } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

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

        jwtVerifyMock.mockResolvedValue({
            payload: MOCK_JWT,
            protectedHeader: {} as JWTHeaderParameters,
        } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

        const jwtVerifier = new JwtVerifier(jwtVerifierConfig, logger);

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

    it("should throw when jwksEndpoint is not set", async () => {
        jwtVerifyMock.mockResolvedValue({
            payload: MOCK_JWT,
            protectedHeader: {} as JWTHeaderParameters,
        } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

        const jwtVerifier = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "" }, logger as Logger);

        await expect(jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues)).rejects.toThrowError(
            'Unable to retrieve jwksEndpoint SSM param from JWT verifier config! Got: ""',
        );
    });

    it("should throw when jwksEndpoint is not a valid url", async () => {
        const jwtVerifier = new JwtVerifier({ ...jwtVerifierConfig, jwksEndpoint: "localhost" }, logger as Logger);

        await expect(jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues)).rejects.toThrowError(
            "Cannot read properties of undefined (reading 'ok')",
        );
    });

    it("should throw if JWKS endpoint does not return 200", async () => {
        (global.fetch as jest.Mock).mockResolvedValueOnce({
            status: 400,
            ok: false,
        });

        jwtVerifyMock.mockResolvedValue({
            payload: MOCK_JWT,
            protectedHeader: {} as JWTHeaderParameters,
        } as unknown as Promise<jose.JWTVerifyResult & jose.ResolvedKey>);

        await expect(jwtVerifier.verify(encodedJwt, mandatoryClaims, expectedClaimValues)).rejects.toThrowError(
            "Error received from the JWKS endpoint, status received: 400",
        );
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

        await expect(jwtVerifier.verify(encodedJwt, mandatoryClaimsFail, expectedClaimValues)).rejects.toThrowError(
            "Claims-set missing mandatory claim: abc",
        );
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
