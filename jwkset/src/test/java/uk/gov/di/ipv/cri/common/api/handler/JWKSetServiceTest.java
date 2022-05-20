package uk.gov.di.ipv.cri.common.api.handler;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.kms.model.KeyMetadata;
import software.amazon.awssdk.services.kms.model.Tag;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.common.api.handler.JWKSetService.ENV_VAR_NAME_CLOUDFORMATION_STACK;

@ExtendWith(MockitoExtension.class)
class JWKSetServiceTest {

    @Mock private EnvironmentService environmentService;

    @Mock private KMSService kmsService;

    @Mock private KeyMetadata keyMetadata;

    @Test
    void shouldMatchAKMSKeyByTagsAndEnabled() throws JOSEException {

        String keyId = "a kms key id";

        when(environmentService.getEnvironmentVariableOrThrow(ENV_VAR_NAME_CLOUDFORMATION_STACK))
                .thenReturn("a stack name");

        when(kmsService.getKeyIds()).thenReturn(List.of(keyId));
        Tag tag1 = Tag.builder().tagKey("jwkset").tagValue("true").build();
        Tag tag2 = Tag.builder().tagKey("awsStackName").tagValue("a stack name").build();

        when(kmsService.getTags(keyId)).thenReturn(Set.of(tag1, tag2));
        when(kmsService.getMetadata(keyId)).thenReturn(keyMetadata);
        when(keyMetadata.keyStateAsString()).thenReturn("Enabled");
        JWK jwk = createRSAJWK(keyId);
        when(kmsService.getJWK(keyId)).thenReturn(jwk);

        JWKSetService jwkSetService = new JWKSetService(kmsService, environmentService);
        List<JWK> jwks = jwkSetService.getJWKs();
        assertEquals(1, jwks.size());
        assertSame(jwks.get(0), jwk);
    }

    @ParameterizedTest
    @MethodSource("generateData")
    void name(boolean expectMatch, Set<Tag> tagsForPublish, Set<Tag> tagsOnKey) {
        when(kmsService.getTags("a key id")).thenReturn(tagsOnKey);
        boolean result =
                new JWKSetService(kmsService, null).matchOnTags("a key id", tagsForPublish);
        assertEquals(expectMatch, result);
    }

    private static Stream<Arguments> generateData() {
        return Stream.of(
                Arguments.of(
                        true,
                        toTags(Map.of("a", "b", "c", "d")),
                        toTags(Map.of("a", "b", "c", "d"))),
                Arguments.of(true, toTags(Map.of("a", "b")), toTags(Map.of("a", "b", "c", "d"))),
                Arguments.of(
                        false,
                        toTags(Map.of("a", "b", "c", "d")),
                        toTags(Map.of("a", "b", "c", "e"))),
                Arguments.of(false, toTags(Map.of("a", "b", "c", "d")), toTags(Map.of("a", "b"))));
    }

    private static Set<Tag> toTags(Map<String, String> input) {
        Set<Map.Entry<String, String>> entries = input.entrySet();
        return entries.stream()
                .map(e -> Tag.builder().tagKey(e.getKey()).tagValue(e.getValue()).build())
                .collect(toSet());
    }

    private JWK createRSAJWK(String keyId) throws JOSEException {
        RSAKey jwk =
                new RSAKeyGenerator(2048)
                        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                        .keyID(keyId) // give the key a unique ID
                        .generate();
        return jwk.toPublicJWK();
    }
}
