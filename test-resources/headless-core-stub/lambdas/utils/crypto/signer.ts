import { importJWK, JWK, JWTHeaderParameters, JWTPayload, SignJWT } from "jose";

export const signJwt = async (
    jwtPayload: JWTPayload,
    privateSigningKey: JWK,
    jwtHeader: JWTHeaderParameters = { alg: "ES256", typ: "JWT" },
) => {
    return await new SignJWT(jwtPayload)
        .setProtectedHeader(jwtHeader)
        .sign(await importJWK(privateSigningKey, "ES256"));
};
