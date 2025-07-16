import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { CompactEncrypt, importJWK, importSPKI, JWK, KeyLike } from "jose";
import {
    clearJWKSCache,
    fetchAndCacheJWKS,
    getCachedJWKS,
    isJWKSCacheValid,
} from "../../../../utils/src/jwks-cache-control";
import { HeadlessCoreStubError } from "../../../../utils/src/errors/headless-core-stub-error";
import { formatAudience } from "../../../../utils/src/audience-formatter";
import { Logger } from "@aws-lambda-powertools/logger";

const kmsClient = new KMSClient({ region: "eu-west-2" });
export const logger = new Logger();

let cachedPublicKey: KeyLike | undefined;

export const getPublicEncryptionKey = async (audience: string) => {
    if (isJWKSCacheValid()) {
        logger.info({ message: "Using Cached JWKS Key" });

        return cachedPublicKey;
    }

    if (process.env.KEY_ROTATION_FEATURE_FLAG_ENABLED === "true") {
        await setCachedPublicEncryptionKeyFromJwks(audience);
    }

    if (!getCachedJWKS()) {
        logger.info({ message: "using KMS to retrieve encryption key" });
        await setPublicEncryptionKeyFromKms();
    }

    return cachedPublicKey;
};

export const encryptSignedJwt = (signedJwt: string, publicEncryptionKey: KeyLike) => {
    return new CompactEncrypt(new TextEncoder().encode(signedJwt))
        .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
        .encrypt(publicEncryptionKey);
};

export function _resetCachedPublicKeyForTest() {
    clearJWKSCache();
}

async function setCachedPublicEncryptionKeyFromJwks(audience: string) {
    const audienceApi = formatAudience(audience);
    const criEncryptionJwksEndpoint = new URL(".well-known/jwks.json", audienceApi);

    logger.info({ message: "Attempting to use CRI hosted public encryption jwks endpoint", criEncryptionJwksEndpoint });

    if (isJWKSCacheValid()) {
        logger.info({ message: "Using locally cached JWKs", criEncryptionJwksEndpoint, ...getCachedJWKS() });
    } else {
        logger.info({ message: "JWKS cache expired or missing; fetching new JWKS..." });
        await fetchAndCacheJWKS(criEncryptionJwksEndpoint, logger);
    }

    const jwks = getCachedJWKS();

    if (!jwks?.keys || !Array.isArray(jwks?.keys) || jwks?.keys?.length === 0) {
        clearJWKSCache();
        logger.error({ message: "Invalid or empty JWKS response", criEncryptionJwksEndpoint });
        return;
    }
    logger.info({ message: "Successfully retrieved public encryption jwks endpoint", ...jwks });

    const encryptionKey = jwks.keys
        .slice()
        .reverse()
        .find((k) => k.use === "enc") as JWK;

    if (!encryptionKey) {
        logger.error(`No encryption key (use: "enc") found in JWKS from ${criEncryptionJwksEndpoint}`);
        clearJWKSCache();
        return;
    }

    logger.info({ message: "Retrieved encryption key from JWKS", ...encryptionKey });
    cachedPublicKey = encryptionKey && ((await importJWK(encryptionKey, "RSA-OAEP-256")) as KeyLike);
}

async function setPublicEncryptionKeyFromKms() {
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
