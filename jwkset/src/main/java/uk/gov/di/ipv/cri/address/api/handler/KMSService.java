package uk.gov.di.ipv.cri.address.api.handler;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class KMSService {

    private final KmsClient kmsClient;

    public KMSService() {
        this.kmsClient = KmsClient.builder().build();
    }

    public KMSService(KmsClient kmsClient) {
        this.kmsClient = kmsClient;
    }

    public List<String> getKeyIds() {
        ListKeysRequest listKeysRequest = ListKeysRequest.builder().build();
        ListKeysResponse result = kmsClient.listKeys(listKeysRequest);
        List<KeyListEntry> keyListEntries = new ArrayList<>(result.keys());
        while (result.nextMarker() != null) {
            listKeysRequest = ListKeysRequest.builder().marker(result.nextMarker()).build();
            result = kmsClient.listKeys(listKeysRequest);
            keyListEntries.addAll(result.keys());
        }
        return keyListEntries.stream().map(KeyListEntry::keyId).collect(Collectors.toList());
    }

    public Set<Tag> getTags(String keyId) {
        ListResourceTagsResponse listResourceTagsReponse =
                kmsClient.listResourceTags(ListResourceTagsRequest.builder().keyId(keyId).build());
        return new HashSet<>(listResourceTagsReponse.tags());
    }

    public KeyMetadata getMetadata(String keyId) {
        DescribeKeyResponse describeKeyReponse =
                kmsClient.describeKey(DescribeKeyRequest.builder().keyId(keyId).build());
        return describeKeyReponse.keyMetadata();
    }

    public JWK getJWK(String keyId) {
        GetPublicKeyResponse publicKeyResponse =
                kmsClient.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build());
        EncodedKeySpec publicKeySpec =
                new X509EncodedKeySpec(publicKeyResponse.publicKey().asByteArray());

        try {

            Algorithm algorithm = Algorithm.parse(publicKeySpec.getAlgorithm());
            String keyUsage = publicKeyResponse.keyUsageAsString();
            if (publicKeyResponse.keySpecAsString().startsWith("RSA")) {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
                return new RSAKey.Builder(publicKey)
                        .keyID(keyId)
                        .algorithm(algorithm)
                        .keyUse(KeyUse.parse(keyUsage))
                        .build();
            } else {
                KeyFactory keyFactory = KeyFactory.getInstance("EC");

                ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
                return new ECKey.Builder(Curve.P_256, publicKey)
                        .keyID(keyId)
                        .algorithm(algorithm)
                        .keyUse(KeyUse.parse(keyUsage))
                        .build();
            }
        } catch (ParseException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }
}
