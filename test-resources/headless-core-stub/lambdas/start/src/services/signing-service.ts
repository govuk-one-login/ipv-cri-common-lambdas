import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { CompactEncrypt, importJWK, importSPKI, JSONWebKeySet, JWK, KeyLike } from "jose";
import { HeadlessCoreStubError } from "../../../../utils/src/errors/headless-core-stub-error";
import { formatAudience } from "../../../../utils/src/audience-formatter";
import { Logger } from "@aws-lambda-powertools/logger";

const kmsClient = new KMSClient({ region: "eu-west-2" });
export const logger = new Logger();

let cachedPublicKey: KeyLike | undefined;

export const getPublicEncryptionKey = async (audience: string) => {
    if (cachedPublicKey) {
        return cachedPublicKey;
    }

    if (process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED === "true") {
        await getPublicEncryptionKeyJwksUri(audience);
    }

    if (!cachedPublicKey) {
        logger.info({ message: "using KMS to retrieve encryption key" });
        await getPublicEncryptionKeyFromKms();
    }

    return cachedPublicKey;
};

export const encryptSignedJwt = (signedJwt: string, publicEncryptionKey: KeyLike) => {
    return new CompactEncrypt(new TextEncoder().encode(signedJwt))
        .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
        .encrypt(publicEncryptionKey);
};

export function _resetCachedPublicKeyForTest() {
    cachedPublicKey = undefined;
}

async function getPublicEncryptionKeyJwksUri(audience: string) {
    const audienceApi = formatAudience(audience);
    const criEncryptionJwksEndpoint = new URL("/.well-known/jwks.json", audienceApi).href;

    logger.info({ message: "Attempting to use CRI hosted public encryption jwks endpoint", criEncryptionJwksEndpoint });

    const data = await fetch(criEncryptionJwksEndpoint, {
        method: "GET",
        headers: { Accept: "application/json" },
    });

    if (!data.ok) {
        throw new Error(`Failed to fetch JWKS: ${data.status} ${data.statusText}`);
    }

    const jwks = (await data.json()) as JSONWebKeySet;

    if (!jwks.keys || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
        throw new Error(`Invalid or empty JWKS response from ${criEncryptionJwksEndpoint}`);
    }
    logger.info({ message: "Successfully retrieved public encryption jwks endpoint", ...jwks });

    const encryptionKey = jwks.keys
        .slice()
        .reverse()
        .find((k) => k.use === "enc") as JWK;

    cachedPublicKey = encryptionKey && ((await importJWK(encryptionKey, "RSA-OAEP-256")) as KeyLike);
}

async function getPublicEncryptionKeyFromKms() {
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

    cachedPublicKey = await importSPKI(publicKeyPem, "RS256");
}
