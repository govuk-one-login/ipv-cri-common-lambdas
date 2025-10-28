import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerifier } from "../../../../src/common/security/jwt-verifier";
import * as jose from "jose";
import { importJWK, JWTHeaderParameters, jwtVerify } from "jose";
import { JwtVerificationConfig } from "../../../../src/types/jwt-verification-config";

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

    beforeEach(() => {
        jest.clearAllMocks();

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

        global.fetch = jest.fn();
    });

    afterEach(() => {
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
});
