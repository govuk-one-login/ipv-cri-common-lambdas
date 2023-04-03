import { base64url } from "jose";
import { CipherGCMTypes, createDecipheriv, KeyObject } from "crypto";
import { DecryptCommand, EncryptionAlgorithmSpec, KMSClient } from "@aws-sdk/client-kms";
import { JweDecrypterError } from "../../common/utils/errors";

export class JweDecrypter {
    private kmsEncryptionKeyId: string | undefined;
    constructor(private readonly kmsClient: KMSClient, private readonly getEncryptionKeyId: () => string) {}

    public async decryptJwe(compactJwe: string): Promise<Buffer> {
        const { 0: jweProtectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag, length } = compactJwe.split(".");

        if (length !== 5) {
            throw new Error(`Invalid number of JWE parts encountered: ${length}`);
        }

        const decryptedContentEncKey = (await this.getKey(encryptedKey)) as Uint8Array;

        const buff = Buffer.from(jweProtectedHeader, "base64");
        const jweHeader = JSON.parse(buff.toString("utf8"));

        const protectedHeaderArray: Uint8Array = new TextEncoder().encode(jweProtectedHeader);

        try {
            return this.gcmDecrypt(
                jweHeader.enc,
                decryptedContentEncKey,
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

    private async getKey(encryptedKey: string): Promise<Uint8Array | undefined> {
        if (!this.kmsEncryptionKeyId) {
            this.kmsEncryptionKeyId = this.getEncryptionKeyId();
        }
        const kmsDecryptionKeyId = this.kmsEncryptionKeyId;
        const jweEncryptedKeyAsBytes = base64url.decode(encryptedKey);
        const decryptCommand = new DecryptCommand({
            CiphertextBlob: jweEncryptedKeyAsBytes,
            KeyId: kmsDecryptionKeyId,
            EncryptionAlgorithm: EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256,
        });
        const response = await this.kmsClient.send(decryptCommand);
        return response.Plaintext;
    }
}
