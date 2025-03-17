import sigFormatter from "ecdsa-sig-formatter";
import { importJWK, importPKCS8, JWK, JWTHeaderParameters, JWTPayload, SignJWT } from "jose";
import { BaseParams, PrivateJwtParams } from "./types";
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";

export const msToSeconds = (ms: number) => Math.round(ms / 1000);

export const isJWK = (key: string | JWK): boolean => typeof key === "object" && key !== null;

const signJwt = async (
    jwtPayload: JWTPayload,
    params: BaseParams,
    jwtHeader: JWTHeaderParameters = { alg: "ES256", typ: "JWT" },
) => {
    let signedJwt: string;
    if ("privateSigningKeyId" in params && params.privateSigningKeyId) {
        signedJwt = await signJwtViaKms(jwtHeader, jwtPayload, params.privateSigningKeyId);
    } else if ("privateSigningKey" in params && params.privateSigningKey && !isJWK(params.privateSigningKey)) {
        const signingKey = await importPKCS8(
            `-----BEGIN PRIVATE KEY-----\n${params.privateSigningKey}\n-----END PRIVATE KEY-----`, // pragma: allowlist secret
            "ES256",
        );
        signedJwt = await new SignJWT(jwtPayload).setProtectedHeader(jwtHeader).sign(signingKey);
    } else if ("privateSigningKey" in params && params.privateSigningKey && isJWK(params.privateSigningKey)) {
        const signingKey = await importJWK(params.privateSigningKey as JWK, "ES256");
        signedJwt = await new SignJWT(jwtPayload).setProtectedHeader(jwtHeader).sign(signingKey);
    } else {
        throw new Error("No signing key provided!");
    }
    return signedJwt;
};

const signJwtViaKms = async (header: JWTHeaderParameters, payload: JWTPayload, keyId: string) => {
    const kmsClient = new KMSClient({ region: "eu-west-2" });
    const jwtParts = {
        header: Buffer.from(JSON.stringify(header)).toString("base64url"),
        payload: Buffer.from(JSON.stringify(payload)).toString("base64url"),
        signature: "",
    };
    const message = Buffer.from(jwtParts.header + "." + jwtParts.payload);
    const signCommand = new SignCommand({
        Message: message,
        MessageType: "RAW",
        KeyId: keyId,
        SigningAlgorithm: "ECDSA_SHA_256",
    });
    const response = await kmsClient.send(signCommand);
    if (!response.Signature) {
        throw new Error(`Failed to sign JWT with KMS key ${keyId}`);
    }
    jwtParts.signature = sigFormatter.derToJose(Buffer.from(response.Signature).toString("base64"), "ES256");
    return jwtParts.header + "." + jwtParts.payload + "." + jwtParts.signature;
};

export const buildPrivateKeyJwtParams = async (params: PrivateJwtParams, headers?: JWTHeaderParameters) => {
    const signedJwt = await signJwt(params.customClaims as JWTPayload, params, headers);

    return new URLSearchParams([
        ["client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
        ["code", params.authorizationCode],
        ["grant_type", "authorization_code"],
        ["redirect_uri", params.redirectUrl],
        ["client_assertion", signedJwt],
    ]).toString();
};
