import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { CompactEncrypt, importSPKI, KeyLike } from "jose";
import { HeadlessCoreStubError } from "../../../../utils/src/errors/headless-core-stub-error";

const kmsClient = new KMSClient({ region: "eu-west-2" });

let cachedPublicKey: KeyLike | undefined;

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

    cachedPublicKey = await importSPKI(publicKeyPem, "RS256");
    return cachedPublicKey;
};

export const encryptSignedJwt = (signedJwt: string, publicEncryptionKey: KeyLike) => {
    return new CompactEncrypt(new TextEncoder().encode(signedJwt))
        .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
        .encrypt(publicEncryptionKey);
};
