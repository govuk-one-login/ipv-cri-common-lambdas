import { base64url } from "jose";
import { CipherGCMTypes, createDecipheriv, KeyObject } from "crypto";
import { DecryptCommand, EncryptionAlgorithmSpec, KMSClient } from "@aws-sdk/client-kms";
import { JweDecrypterError } from "../../common/utils/errors";
import { logger, metrics } from "../../common/utils/power-tool";
import { MetricUnits } from "@aws-lambda-powertools/metrics";

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
        const { 0: jweProtectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag, length } = compactJwe.split(".");

        if (length !== 5) {
            throw new Error(`Invalid number of JWE parts encountered: ${length}`);
        }

        const decryptedContentEncKey = await this.getDecryptedCek(encryptedKey);

        const buff = Buffer.from(jweProtectedHeader, "base64");
        const jweHeader = JSON.parse(buff.toString("utf8"));

        const protectedHeaderArray: Uint8Array = new TextEncoder().encode(jweProtectedHeader);

        try {
            return this.gcmDecrypt(
                jweHeader.enc,
                decryptedContentEncKey as Uint8Array,
                base64url.decode(ciphertext),
                base64url.decode(iv),
                base64url.decode(tag),
                protectedHeaderArray,
            );
        } catch (error) {
            throw new JweDecrypterError(error as Error);
        }
    }

    // TODO: check if we can import this from the jose package
    private gcmDecrypt(
        enc: string,
        cek: KeyObject | Uint8Array,
        ciphertext: Uint8Array,
        iv: Uint8Array,
        tag: Uint8Array,
        aad: Uint8Array,
    ): Buffer {
        const keySize = parseInt(enc.slice(1, 4), 10);

        const algorithm = <CipherGCMTypes>`aes-${keySize}-gcm`;

        const decipher = createDecipheriv(algorithm, cek, iv, { authTagLength: 16 });
        decipher.setAuthTag(tag);
        if (aad.byteLength) {
            decipher.setAAD(aad, { plaintextLength: ciphertext.length });
        }
        const plainText = decipher.update(ciphertext);
        decipher.final();
        return plainText;
    }

    private async getDecryptedCek(encryptedKey: string): Promise<Uint8Array | undefined> {
        const ciphertextBlob = base64url.decode(encryptedKey);
        const isKeyRotationEnabled = process.env.ENV_VAR_FEATURE_FLAG_KEY_ROTATION === "true";

        if (isKeyRotationEnabled) {
            const decryptedWithAlias = await this.tryDecryptWithAliases(ciphertextBlob);
            if (decryptedWithAlias) {
                return decryptedWithAlias;
            }
            logger.info({ message: "Key rotation enabled", status: "All aliases failed." });
            metrics.addMetric(ALL_ALIASES_UNAVAILABLE, MetricUnits.Count, 1);
        }

        const decryptedWithKmsId = await this.tryDecryptWithKmsId(ciphertextBlob);

        if (decryptedWithKmsId) {
            return decryptedWithKmsId;
        }
        throw new Error("Failed to decrypt CEK with any available alias or KMS Id");
    }

    private async tryDecryptWithAliases(ciphertextBlob: Uint8Array): Promise<Uint8Array | undefined> {
        for (const alias of DecryptionKeyAliases) {
            const aliasName = `alias/${alias}`;
            try {
                const cek = await this.getKey(ciphertextBlob, aliasName);
                this.logSuccessfulAliasDecryption(aliasName);
                return cek;
            } catch (err: unknown) {
                this.logFailedAliasDecryption(aliasName, err as Error);
            }
        }
        return undefined;
    }

    private async tryDecryptWithKmsId(ciphertextBlob: Uint8Array): Promise<Uint8Array | undefined> {
        if (!this.kmsEncryptionKeyId) {
            this.kmsEncryptionKeyId = this.getEncryptionKeyId();
        }
        const kmsDecryptionKeyId = this.kmsEncryptionKeyId;
        try {
            const cek = await this.getKey(ciphertextBlob, kmsDecryptionKeyId);
            logger.info({ message: "Successfully decrypted using KMS Id" });
            return cek;
        } catch (error: unknown) {
            logger.error({
                message: "Failed to decrypt with KMS keyId",
                error,
            });
            return undefined;
        }
    }

    private async getKey(jweEncryptedKeyAsBytes: Uint8Array, keyId: string): Promise<Uint8Array | undefined> {
        const decryptCommand = new DecryptCommand({
            CiphertextBlob: jweEncryptedKeyAsBytes,
            KeyId: keyId,
            EncryptionAlgorithm: EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256,
        });
        const response = await this.kmsClient.send(decryptCommand);
        return response.Plaintext;
    }
    private readonly logSuccessfulAliasDecryption = (alias: string) =>
        logger.info({
            message: "Key rotation enabled",
            alias,
            status: "Successfully decrypted using Alias",
        });

    private readonly logFailedAliasDecryption = (alias: string, error: Error) =>
        logger.error({
            message: "Key rotation enabled",
            alias,
            error,
        });
}
