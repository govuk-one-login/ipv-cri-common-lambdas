import { v4 as uuidv4 } from "uuid";
import sigFormatter from "ecdsa-sig-formatter";
import { CompactEncrypt, importJWK, importPKCS8, JWK, JWTHeaderParameters, JWTPayload, SignJWT } from "jose";
import { BaseParams, JarAuthorizationParams, PrivateJwtParams } from "./types";
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";

const publicKeyToJwk = async (publicKey: string) => {
    const decoded = Buffer.from(publicKey, "base64").toString();
    const keyObject = JSON.parse(decoded);
    return await importJWK(keyObject, "RSA256");
};

const buildQueryString = (queryParams: Record<string, string>) => {
    return Object.entries(queryParams)
        .map((pair) => pair.map(encodeURIComponent).join("="))
        .join("&");
};

export const msToSeconds = (ms: number) => Math.round(ms / 1000);

const buildBaseJwtPayload = (params: BaseParams) => {
    const baseJwtPayload: JWTPayload = {
        iss: params.issuer,
        iat: msToSeconds(new Date().getTime()),
        nbf: msToSeconds(new Date().getTime()),
        exp: msToSeconds(new Date().getTime() + 5 * 60 * 1000),
    };

    return baseJwtPayload;
};

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

export const buildSignedJwt = async (params: BaseParams) => {
    const jwtPayload = { ...buildBaseJwtPayload(params), ...params.customClaims };
    const signedJwt = await signJwt(jwtPayload, params);
    return signedJwt;
};

export const buildJarAuthorizationRequest = async (params: JarAuthorizationParams) => {
    const jwtPayload: JWTPayload = {
        ...buildBaseJwtPayload(params),
        client_id: params.clientId,
        redirect_uri: params.redirectUrl,
        response_type: "code",
        state: uuidv4(),
        govuk_signin_journey_id: uuidv4(),
        sub: uuidv4(),
        aud: params.audience,
        ...params.customClaims,
    };

    const signedJwt = await signJwt(jwtPayload, params);

    const encryptionKeyJwk = await publicKeyToJwk(params.publicEncryptionKey);
    const encryptedSignedJwt = await new CompactEncrypt(new TextEncoder().encode(signedJwt))
        .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
        .encrypt(encryptionKeyJwk);

    return {
        client_id: params.clientId,
        request: encryptedSignedJwt,
    };
};

export const buildJarAuthorizationUrl = async (params: JarAuthorizationParams) => {
    return `${params.authorizationEndpoint}?${buildQueryString(await buildJarAuthorizationRequest(params))}`;
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
