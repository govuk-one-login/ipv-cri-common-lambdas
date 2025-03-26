package uk.gov.di.ipv.cri.common.api.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Set;

import static software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;

class KMSRSADecrypter implements JWEDecrypter {
    private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWEAlgorithm.RSA_OAEP_256);
    private static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS =
            Set.of(EncryptionMethod.A256GCM);
    private static final Logger LOGGER = LogManager.getLogger();

    private static final String CLIENT_JAR_KMS_ENCRYPTION_KEY_ALIAS_PRIMARY =
            "dev_identity_signing_key"; //change the name to session_decryption_key_current
    private static final String CLIENT_JAR_KMS_ENCRYPTION_KEY_ALIAS_SECONDARY =
            "dev_identity_signing_key_previous"; //change the name to session_decryption_key_previous

    private final boolean keyRotationEnabled =
            Boolean.parseBoolean(System.getenv("ENV_VAR_FEATURE_FLAG_KEY_ROTATION"));
    private final JWEJCAContext jcaContext;
    private final KmsClient kmsClient;
    private final String keyId;

    KMSRSADecrypter(String keyId, KmsClient kmsClient) {
        this.keyId = keyId;
        this.kmsClient = kmsClient;
        this.jcaContext = new JWEJCAContext();
    }

    @Override
    public byte[] decrypt(
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag,
            byte[] aad)
            throws JOSEException {
        // Validate required JWE parts
        if (Objects.isNull(encryptedKey)) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (Objects.isNull(iv)) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (Objects.isNull(authTag)) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        JWEAlgorithm alg = header.getAlgorithm();

        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, supportedJWEAlgorithms()));
        }
        DecryptResponse decryptResponse = null;
        if (keyRotationEnabled) {
            System.out.println("KeyRotationEnabled!!!!!!!!");
            var encryptedKeyDecryptRequestPrimary =
                    DecryptRequest.builder()
                            .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                            .encryptionAlgorithm(RSAES_OAEP_SHA_256)
                            .keyId("alias/" + CLIENT_JAR_KMS_ENCRYPTION_KEY_ALIAS_PRIMARY)
                            .build();

            // During a key rotation we might receive JWTs encrypted with either the old or new key.
            boolean primaryKeyUnsuccessful = true;
            try {
                System.out.println("Policy added");
                System.out.println("PRIMARY KEY BLOCK:::::");
                decryptResponse = kmsClient.decrypt(encryptedKeyDecryptRequestPrimary);
                String encryptKeyID = decryptResponse.keyId();
                String hashedKeyId = createHashedKeyId(encryptKeyID);
                primaryKeyUnsuccessful = false;
            } catch (Exception e) {
                LOGGER.warn("Failed to decrypt with primary key. Trying secondary", e);
            }
            if (primaryKeyUnsuccessful) {

                var encryptedKeyDecryptRequestSecondary =
                        DecryptRequest.builder()
                                .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                                .encryptionAlgorithm(RSAES_OAEP_SHA_256)
                                .keyId("alias/" + CLIENT_JAR_KMS_ENCRYPTION_KEY_ALIAS_SECONDARY)
                                .build();

                try {
                    System.out.println("Policy added");
                    System.out.println("SECONDARY KEY BLOCK:::::");
                    decryptResponse = kmsClient.decrypt(encryptedKeyDecryptRequestSecondary);
                } catch (Exception e) {
                    LOGGER.error("Failed to decrypt with secondary key", e);
                    throw e;
                }
            }

        } else {
            System.out.println("KeyRotationEnabled Flag set to false");
            DecryptRequest decryptRequest =
                    DecryptRequest.builder()
                            .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
                            .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                            .keyId(this.keyId)
                            .build();
            decryptResponse = this.kmsClient.decrypt(decryptRequest);
        }

        SecretKey cek = new SecretKeySpec(decryptResponse.plaintext().asByteArray(), "AES");
        return ContentCryptoProvider.decrypt(
                header, null, encryptedKey, iv, cipherText, authTag, cek, getJCAContext());
    }

    private String createHashedKeyId(String keyId) throws NoSuchAlgorithmException {
        System.out.println("ENTER CREATE HASHED KEY ID METHOD");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(keyId.getBytes(StandardCharsets.UTF_8));
        return Hex.encodeHexString(hash);
    }

    // TODO: Helper method to compare hashed keyIDs - validation check
    //compare it with the hashed kid we received in the JWE header
    //fail if not matched
    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return SUPPORTED_ALGORITHMS;
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return SUPPORTED_ENCRYPTION_METHODS;
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return jcaContext;
    }
}
