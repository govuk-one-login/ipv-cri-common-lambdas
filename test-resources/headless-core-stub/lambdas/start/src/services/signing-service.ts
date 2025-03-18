import { JSONValue } from "@aws-lambda-powertools/commons/types";
import { Logger } from "@aws-lambda-powertools/logger";
import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { CompactEncrypt, importJWK, importSPKI, JWK, JWTHeaderParameters, JWTPayload, KeyLike, SignJWT } from "jose";
import { HeadlessCoreStubError } from "../errors/headless-core-stub-error";
import { getJsonSSMParameter } from "./ssm-service";

const logger = new Logger();
const kmsClient = new KMSClient({ region: "eu-west-2" });

const PRIVATE_SIGNING_KEY_SSM_NAME = "/test-resources/ipv-core-stub-aws-headless/privateSigningKey";

let cachedPublicKey: KeyLike | undefined;

export const getPrivateSigningKey = async () => {
    const signingKey: JSONValue = await getJsonSSMParameter(PRIVATE_SIGNING_KEY_SSM_NAME);
    return signingKey as JWK;
};

export const signJwt = async (
    jwtPayload: JWTPayload,
    privateSigningKey: JWK,
    jwtHeader: JWTHeaderParameters = { alg: "ES256", typ: "JWT" },
) => {
    return await new SignJWT(jwtPayload)
        .setProtectedHeader(jwtHeader)
        .sign(await importJWK(privateSigningKey, "ES256"));
};

export const getPublicEncryptionKey = async () => {
    if (cachedPublicKey) {
        return cachedPublicKey;
    }

    const decryptionKeyId = process.env.DECRYPTION_KEY_ID;
    if (!decryptionKeyId) {
        throw new HeadlessCoreStubError("Decryption key ID not present", 500);
    }

    const data = await kmsClient.send(new GetPublicKeyCommand({ KeyId: decryptionKeyId }));
    if (!data?.PublicKey) {
        throw new HeadlessCoreStubError("Unable to retrieve public encryption key", 500);
    }

    const base64PublicKey = Buffer.from(data.PublicKey).toString("base64");
    const header = "-----BEGIN PUBLIC KEY-----";
    const footer = "-----END PUBLIC KEY-----";
    const value = base64PublicKey.match(/.{1,64}/g)?.join("\n");
    const publicKeyPem = `${header}\n${value}\n${footer}`;

    logger.error(publicKeyPem);

    cachedPublicKey = await importSPKI(publicKeyPem, "RS256");
    return cachedPublicKey;
};

export const encryptSignedJwt = (signedJwt: string, publicEncryptionKey: KeyLike) => {
    return new CompactEncrypt(new TextEncoder().encode(signedJwt))
        .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
        .encrypt(publicEncryptionKey);
};
