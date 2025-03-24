import { JWTPayload } from "jose";
import { buildPrivateKeyJwtParams, msToSeconds } from "./crypto-service";
import { v4 as uuidv4 } from "uuid";
export const generatePrivateJwtParams = async (
    clientId: string,
    authorizationCode: string,
    redirectUrl: string,
    privateJwtKey: string,
    audience: string,
): Promise<string> => {
    const customClaims: JWTPayload = {
        iss: clientId,
        sub: clientId,
        aud: audience,
        exp: msToSeconds(Date.now() + 5 * 60 * 1000),
        jti: uuidv4(),
    };

    return buildPrivateKeyJwtParams({
        customClaims,
        authorizationCode,
        redirectUrl,
        privateSigningKey: privateJwtKey,
    });
};
