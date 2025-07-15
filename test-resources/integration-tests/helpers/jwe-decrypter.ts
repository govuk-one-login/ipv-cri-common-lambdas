/* eslint-disable no-console */
import { base64url } from "jose";
import { CipherGCMTypes, createDecipheriv, KeyObject } from "crypto";
import { DecryptCommand, EncryptionAlgorithmSpec, KMSClient } from "@aws-sdk/client-kms";
const DecryptionKeyAliases = [
    "session_decryption_key_active_alias",
    "session_decryption_key_inactive_alias",
    "session_decryption_key_previous_alias",
] as const;

const ALL_ALIASES_UNAVAILABLE = "all_aliases_unavailable_for_decryption";

export class JweDecrypter {
    private kmsEncryptionKeyId: string | undefined;
    constructor(
        private readonly kmsClient: KMSClient,
        private readonly getEncryptionKeyId: () => string,
    ) {}

    public async decryptJwe(compactJwe: string): Promise<Buffer> {
        const { 0: jweProtectedHeader, 1: encryptedKey, 2: iv, 3: cipherText, 4: tag, length } = compactJwe.split(".");

        if (length !== 5) {
            throw new Error(`Invalid number of JWE parts encountered: ${length}`);
        }

        const decryptedContentEncKey = await this.fetchKey(encryptedKey);

        const buff = Buffer.from(jweProtectedHeader, "base64");
        const jweHeader = JSON.parse(buff.toString("utf8"));

        const protectedHeaderArray: Uint8Array = new TextEncoder().encode(jweProtectedHeader);

        try {
            return this.gcmDecrypt(
                jweHeader.enc,
                decryptedContentEncKey as Uint8Array,
                base64url.decode(cipherText),
                base64url.decode(iv),
                base64url.decode(tag),
                protectedHeaderArray,
            );
        } catch (error) {
            console.error("Error decrypting JWE", error);
            throw error;
        }
    }

    // TODO: check if we can import this from the jose package
    private gcmDecrypt(
        enc: string,
        cek: KeyObject | Uint8Array,
        cipherText: Uint8Array,
        iv: Uint8Array,
        tag: Uint8Array,
        aad: Uint8Array,
    ): Buffer {
        const keySize = parseInt(enc.slice(1, 4), 10);

        const algorithm = <CipherGCMTypes>`aes-${keySize}-gcm`;

        const decipher = createDecipheriv(algorithm, cek, iv, { authTagLength: 16 });
        decipher.setAuthTag(tag);
        if (aad.byteLength) {
            decipher.setAAD(aad, { plaintextLength: cipherText.length });
        }
        const plainText = decipher.update(cipherText);
        decipher.final();
        return plainText;
    }

    private async fetchKey(encryptedKey: string): Promise<Uint8Array | undefined> {
        const decodedEncryptedKey = base64url.decode(encryptedKey);
        if (process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION === "true") {
            return await this.fetchKeyUsingAlias(decodedEncryptedKey);
        }
        return await this.fetchKeyUsingKeyId(decodedEncryptedKey);
    }

    private async fetchKeyUsingAlias(encryptedEncKey: Uint8Array): Promise<Uint8Array | undefined> {
        console.log("Key rotation enabled. Attempting to decrypt with key aliases.");
        for (const aliasName of DecryptionKeyAliases) {
            const alias = `alias/${aliasName}`;
            try {
                const cek = await this.decryptKeyWithKms(encryptedEncKey, alias);
                console.log({ message: "Key rotation enabled", alias, status: "Successfully decrypted using Alias" });
                return cek;
            } catch (error: unknown) {
                console.warn({ message: "Key rotation enabled", alias, error });
            }
        }

        console.log(`add metrics for ${ALL_ALIASES_UNAVAILABLE}`);

        if (process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK === "true") {
            console.warn("Failed to decrypt with all available key aliases, falling back to legacy key.");
            return await this.fetchKeyUsingKeyId(encryptedEncKey);
        }
        throw new Error("Failed to decrypt with all available key aliases.");
    }

    private async fetchKeyUsingKeyId(encryptedContentEncKey: Uint8Array): Promise<Uint8Array | undefined> {
        if (!this.kmsEncryptionKeyId) {
            this.kmsEncryptionKeyId = this.getEncryptionKeyId();
        }
        const kmsDecryptionKeyId = this.kmsEncryptionKeyId;
        try {
            const cek = await this.decryptKeyWithKms(encryptedContentEncKey, kmsDecryptionKeyId);
            console.log({ message: "Decryption successful with legacy key" });
            return cek;
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : String(error);
            throw new Error(`Failed to decrypt with legacy key: ${message}`);
        }
    }

    private async decryptKeyWithKms(
        encryptedContentEncKey: Uint8Array,
        kmsKeyIdOrAlias: string,
    ): Promise<Uint8Array | undefined> {
        const decryptCommand = new DecryptCommand({
            CiphertextBlob: encryptedContentEncKey,
            KeyId: kmsKeyIdOrAlias,
            EncryptionAlgorithm: EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256,
        });
        const response = await this.kmsClient.send(decryptCommand);
        return response.Plaintext;
    }
}
