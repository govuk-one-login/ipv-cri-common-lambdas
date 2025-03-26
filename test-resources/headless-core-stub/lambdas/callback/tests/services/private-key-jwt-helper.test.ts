import { generatePrivateJwtParams } from "../../src/services/private-key-jwt-helper";
import { generateKeyPair, exportJWK, JWK } from "jose";

jest.useFakeTimers().setSystemTime(new Date("2025-03-26T12:00:00Z"));

describe("generatePrivateJwtParams", () => {
    let privateJwtKey: JWK;
    const clientId: string = "mock-client-id";
    const authorizationCode: string = "mock-auth-code";
    const redirectUrl: string = "https://mock-redirect-url.com";
    const audience: string = "mock-audience";
    const jwtHeader = { alg: "ES256", typ: "JWT" };

    beforeAll(async () => {
        const { privateKey } = await generateKeyPair("ES256");
        privateJwtKey = await exportJWK(privateKey);
    });

    it("generates JWT with correct claims and headers", async () => {
        const result = await generatePrivateJwtParams(
            clientId,
            authorizationCode,
            redirectUrl,
            privateJwtKey,
            audience,
            jwtHeader,
        );

        const params = new URLSearchParams(result);
        const jwt = params.get("client_assertion");
        expect(jwt).toBeTruthy();

        const [headerBase64, payloadBase64] = jwt!.split(".");
        const decodedHeader = JSON.parse(Buffer.from(headerBase64, "base64url").toString());
        const decodedPayload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString());

        expect(decodedHeader).toEqual(jwtHeader);

        expect(decodedPayload.iss).toBe(clientId);
        expect(decodedPayload.sub).toBe(clientId);
        expect(decodedPayload.aud).toBe(audience);
        expect(decodedPayload.exp).toBe(Math.round(Date.now() / 1000) + 5 * 60);
        expect(decodedPayload.jti).toBeTruthy();
    });

    it("defaults to standard JWT header if not provided", async () => {
        const result = await generatePrivateJwtParams(
            clientId,
            authorizationCode,
            redirectUrl,
            privateJwtKey,
            audience,
        );

        const params = new URLSearchParams(result);
        const jwt = params.get("client_assertion");
        expect(jwt).toBeTruthy();

        const [headerBase64, payloadBase64] = jwt!.split(".");
        const decodedHeader = JSON.parse(Buffer.from(headerBase64, "base64url").toString());
        const decodedPayload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString());

        expect(decodedHeader).toEqual(jwtHeader);

        expect(decodedPayload.jti).toBeTruthy();
    });

    it("generates different JWTs for different authorization codes", async () => {
        const result1 = await generatePrivateJwtParams(clientId, "auth-code-1", redirectUrl, privateJwtKey, audience);
        const result2 = await generatePrivateJwtParams(clientId, "auth-code-2", redirectUrl, privateJwtKey, audience);

        expect(result1).not.toEqual(result2);
    });

    it("generates a JWT with a valid expiration claim (5 minutes)", async () => {
        const result = await generatePrivateJwtParams(
            clientId,
            authorizationCode,
            redirectUrl,
            privateJwtKey,
            audience,
        );

        const params = new URLSearchParams(result);
        const jwt = params.get("client_assertion");

        const payloadBase64 = jwt!.split(".")[1];
        const decodedPayload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString());

        const expectedExp = Math.round(Date.now() / 1000) + 5 * 60;
        expect(decodedPayload.exp).toBe(expectedExp);
        expect(decodedPayload.jti).toBeTruthy();
    });
});
