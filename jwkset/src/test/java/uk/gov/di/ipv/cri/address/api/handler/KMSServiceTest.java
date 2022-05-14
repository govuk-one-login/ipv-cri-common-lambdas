package uk.gov.di.ipv.cri.address.api.handler;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

import java.security.PublicKey;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KMSServiceTest {

    @Mock private GetPublicKeyResponse publicKeyResponse;

    @Mock private KmsClient kmsClient;

    @Test
    void generateRSAJWKFromRSAPublicKey() throws JOSEException {
        String keyId = "a key id";
        GetPublicKeyRequest publicKeyRequest = GetPublicKeyRequest.builder().keyId(keyId).build();
        when(kmsClient.getPublicKey(publicKeyRequest)).thenReturn(publicKeyResponse);
        when(publicKeyResponse.publicKey())
                .thenReturn(SdkBytes.fromByteArray(generateRSAPublicKey().getEncoded()));
        when(publicKeyResponse.keyUsageAsString())
                .thenReturn(KeyUsageType.ENCRYPT_DECRYPT.toString());
        when(publicKeyResponse.keySpecAsString()).thenReturn("RSA");
        JWK jwk = new KMSService(kmsClient).getJWK(keyId);
        assertEquals(KeyType.RSA, jwk.getKeyType());
        assertEquals(keyId, jwk.getKeyID());
    }

    @Test
    void generateECJWKFromECPublicKey() throws JOSEException {
        String keyId = "a key id";
        GetPublicKeyRequest publicKeyRequest = GetPublicKeyRequest.builder().keyId(keyId).build();
        when(kmsClient.getPublicKey(publicKeyRequest)).thenReturn(publicKeyResponse);
        when(publicKeyResponse.publicKey())
                .thenReturn(SdkBytes.fromByteArray(generateECPublicKey().getEncoded()));
        when(publicKeyResponse.keyUsageAsString()).thenReturn(KeyUsageType.SIGN_VERIFY.toString());
        when(publicKeyResponse.keySpecAsString()).thenReturn("EC");
        JWK jwk = new KMSService(kmsClient).getJWK(keyId);
        assertEquals(KeyType.EC, jwk.getKeyType());
        assertEquals(keyId, jwk.getKeyID());
    }

    private PublicKey generateRSAPublicKey() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate()
                .toPublicKey();
    }

    public PublicKey generateECPublicKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate()
                .toPublicKey();
    }
}
