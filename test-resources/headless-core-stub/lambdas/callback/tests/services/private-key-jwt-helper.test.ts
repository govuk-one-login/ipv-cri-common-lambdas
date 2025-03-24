import { generatePrivateJwtParams } from "../../src/services/private-key-jwt-helper";
import * as CryptoService from "../../src/services/crypto-service";
import * as Uuid from "uuid";
import { JWTPayload } from "jose";

jest.mock("../../src/services/crypto-service");
jest.mock("uuid");
describe("generatePrivateJwtParams", () => {
    const clientId = "mock-client-id";
    const authorizationCode = "mock-auth-code";
    const redirectUrl = "https://mock-redirect-url.com";
    const privateJwtKey = "mock-private-key";
    const audience = "mock-audience";

    const mockCustomClaims: JWTPayload = {
        iss: clientId,
        sub: clientId,
        aud: audience,
        exp: 12345678,
        jti: "mock-jti",
    };

    beforeEach(() => {
        jest.spyOn(CryptoService, "msToSeconds").mockImplementation((ms) => Math.floor(ms / 1000));
        jest.spyOn(Uuid, "v4").mockReturnValueOnce(mockCustomClaims.jti as string);
    });
    afterEach(() => jest.clearAllMocks());

    it("generates custom claims and call buildPrivateKeyJwtParams with the correct parameters", async () => {
        const mockJwt = "mock-jwt";
        jest.spyOn(CryptoService, "buildPrivateKeyJwtParams").mockResolvedValueOnce(mockJwt);

        const expectedCustomClaims: JWTPayload = {
            ...mockCustomClaims,
            exp: CryptoService.msToSeconds(Date.now() + 5 * 60 * 1000),
        };

        const result = await generatePrivateJwtParams(
            clientId,
            authorizationCode,
            redirectUrl,
            privateJwtKey,
            audience,
        );

        expect(Uuid.v4).toHaveBeenCalled();
        expect(CryptoService.msToSeconds).toHaveBeenCalledWith(expect.any(Number));
        expect(CryptoService.buildPrivateKeyJwtParams).toHaveBeenCalledWith({
            customClaims: expectedCustomClaims,
            authorizationCode: authorizationCode,
            redirectUrl: redirectUrl,
            privateSigningKey: privateJwtKey,
        });
        expect(result).toBe(mockJwt);
    });

    it("handles errors thrown by buildPrivateKeyJwtParams", async () => {
        jest.spyOn(CryptoService, "buildPrivateKeyJwtParams").mockRejectedValueOnce(new Error("Mock error"));

        await expect(
            generatePrivateJwtParams(clientId, authorizationCode, redirectUrl, privateJwtKey, audience),
        ).rejects.toThrow(new Error("Mock error"));

        expect(Uuid.v4).toHaveBeenCalled();
        expect(CryptoService.msToSeconds).toHaveBeenCalledWith(expect.any(Number));
        expect(CryptoService.buildPrivateKeyJwtParams).toHaveBeenCalled();
    });

    it("correctly formats the expiration time using msToSeconds", async () => {
        const mockExpirationMs = Date.now() + 5 * 60 * 1000;
        const expectedExpirationSeconds = Math.floor(mockExpirationMs / 1000);

        await generatePrivateJwtParams(clientId, authorizationCode, redirectUrl, privateJwtKey, audience);

        expect(CryptoService.msToSeconds).toHaveBeenCalledWith(mockExpirationMs);
        expect(CryptoService.msToSeconds).toHaveReturnedWith(expectedExpirationSeconds);
    });
});
