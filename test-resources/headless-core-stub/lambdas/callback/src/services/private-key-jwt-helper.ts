import { importJWK, JWK, JWTHeaderParameters, JWTPayload, SignJWT } from "jose";
import { v4 as uuidv4 } from "uuid";
export const generatePrivateJwtParams = async (
    clientId: string,
    authorizationCode: string,
    redirectUrl: string,
    privateJwtKey: JWK,
    audience: string,
    jwtHeader: JWTHeaderParameters = { alg: "ES256", typ: "JWT" },
): Promise<string> => {
    const signingClaims: JWTPayload = {
        iss: clientId,
        sub: clientId,
        aud: audience,
        exp: msToSeconds(Date.now() + 5 * 60 * 1000),
        jti: uuidv4(),
    };

    const signedJwt = await new SignJWT(signingClaims)
        .setProtectedHeader(jwtHeader)
        .sign(await importJWK(privateJwtKey, "ES256"));

    return new URLSearchParams([
        ["client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
        ["code", authorizationCode],
        ["grant_type", "authorization_code"],
        ["redirect_uri", redirectUrl],
        ["client_assertion", signedJwt],
    ]).toString();
};
const msToSeconds = (ms: number) => Math.round(ms / 1000);
