import { JWK, JWTPayload } from "jose";
import { v4 as uuidv4 } from "uuid";
import { signJwt } from "../../../../utils/src/crypto/signer";
import { getHashedKid } from "../../../../utils/src/hashing";

export const generatePrivateJwtParams = async (
    clientId: string,
    authorizationCode: string,
    redirectUrl: string,
    privateJwtKey: JWK,
    audience: string,
): Promise<string> => {
    const signingClaims: JWTPayload = {
        iss: clientId,
        sub: clientId,
        aud: audience,
        exp: msToSeconds(Date.now() + 5 * 60 * 1000),
        jti: uuidv4(),
    };

    const jwtHeader = {
        alg: "ES256",
        typ: "JWT",
        ...(privateJwtKey.kid && { kid: getHashedKid(privateJwtKey.kid) }),
    };

    const signedJwt = await signJwt(signingClaims, privateJwtKey, jwtHeader);

    return new URLSearchParams([
        ["client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
        ["code", authorizationCode],
        ["grant_type", "authorization_code"],
        ["redirect_uri", redirectUrl],
        ["client_assertion", signedJwt],
    ]).toString();
};
const msToSeconds = (ms: number) => Math.round(ms / 1000);
