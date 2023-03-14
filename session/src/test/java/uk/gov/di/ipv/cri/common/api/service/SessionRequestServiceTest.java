package uk.gov.di.ipv.cri.common.api.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.api.domain.RawSessionRequest;
import uk.gov.di.ipv.cri.common.api.serializer.PIIRedactingDeserializer;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.SharedClaims;
import uk.gov.di.ipv.cri.common.library.exception.ClientConfigurationException;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.JWTVerifier;

import java.io.IOException;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SessionRequestServiceTest {

    @Mock private ConfigurationService mockConfigurationService;
    @Mock private JWTDecrypter mockJwtDecrypter;
    @Mock private JWTVerifier mockJwtVerifier;
    SessionRequestService sessionRequestService;
    private SharedClaims testSharedClaims;
    private ObjectMapper objectMapper;
    private final List<String> sensitiveFields = List.of("name", "birthDate", "address");

    private static final String SHARED_CLAIMS =
            "{\"@context\":[\"https:\\/\\/www.w3.org\\/2018\\/credentials\\/v1\",\"https:\\/\\/vocab.london.cloudapps.digital\\/contexts\\/identity-v1.jsonld\"],\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"KENNETH\"},{\"type\":\"FamilyName\",\"value\":\"DECERQUEIRA\"}]}],\"birthDate\":[{\"value\":\"1965-04-05\"}],\"address\":[{\"buildingNumber\":\"8\",\"streetName\":\"HADLEY ROAD\",\"postalCode\":\"BA2 5AA\",\"validFrom\":\"2021-01-01\"}]}";

    @BeforeEach
    void setUp() throws JsonProcessingException {
        SimpleModule redactionModule = new SimpleModule();
        this.objectMapper = new ObjectMapper();
        redactionModule.addDeserializer(
                SharedClaims.class,
                new PIIRedactingDeserializer<>(sensitiveFields, SharedClaims.class));
        this.objectMapper
                .registerModule(new JavaTimeModule())
                .registerModule(new Jdk8Module())
                .registerModule(redactionModule);
        sessionRequestService =
                new SessionRequestService(
                        objectMapper, mockJwtVerifier, mockConfigurationService, mockJwtDecrypter);
        testSharedClaims = objectMapper.readValue(SHARED_CLAIMS, SharedClaims.class);
    }

    @Test
    void shouldThrowValidationExceptionWhenSessionRequestIsInvalid() throws IOException {
        String requestBody = marshallToJSON(Map.of("not", "a-session-request"));

        SessionValidationException exception =
                assertThrows(
                        SessionValidationException.class,
                        () -> sessionRequestService.validateSessionRequest(requestBody));
        assertThat(exception.getMessage(), containsString("Could not parse request body"));
        verifyNoInteractions(mockConfigurationService);
    }

    @Test
    void shouldThrowValidationExceptionWhenRequestClientIdIsInvalid()
            throws ParseException, JOSEException {
        String invalidClientId = "invalid-client-id";
        JSONObject requestBody = new JSONObject();
        requestBody.put("client_id", invalidClientId);
        requestBody.put("request", "some.jwt.value");
        String testRequestBody = requestBody.toString();
        String configParameterPath = "/clients/" + invalidClientId + "/jwtAuthentication";
        SignedJWTBuilder signedJWTBuilder = new SignedJWTBuilder().setClientId(invalidClientId);
        SignedJWT signedJWT = signedJWTBuilder.build();
        RawSessionRequest rawSessionRequest = createRawSessionRequest(signedJWT);
        rawSessionRequest.setClientId(invalidClientId);

        when(mockJwtDecrypter.decrypt(any())).thenReturn(signedJWT);
        when(mockConfigurationService.getParametersForPath(configParameterPath))
                .thenReturn(Map.of());
        SessionValidationException exception =
                assertThrows(
                        SessionValidationException.class,
                        () -> sessionRequestService.validateSessionRequest(testRequestBody));
        assertThat(exception.getMessage(), containsString("no configuration for client id"));
        verify(mockConfigurationService).getParametersForPath(configParameterPath);
    }

    @Test
    void shouldThrowValidationExceptionWhenRedirectUriIsInvalid()
            throws ParseException, JOSEException {
        SignedJWTBuilder signedJWTBuilder =
                new SignedJWTBuilder().setRedirectUri("https://www.example.com/not-valid-callback");
        SignedJWT signedJWT = signedJWTBuilder.build();

        JSONObject requestBody = new JSONObject();
        requestBody.put("client_id", "ipv-core");
        requestBody.put("request", "some.jwt.value");
        String testRequestBody = requestBody.toString();

        when(mockJwtDecrypter.decrypt(any())).thenReturn(signedJWT);
        initMockConfigurationService(standardSSMConfigMap(signedJWTBuilder.getCertificate()));

        SessionValidationException exception =
                assertThrows(
                        SessionValidationException.class,
                        () -> sessionRequestService.validateSessionRequest(testRequestBody));
        assertThat(
                exception.getMessage(),
                containsString(
                        "redirect uri https://www.example.com/not-valid-callback does not match configuration uri https://www.example/com/callback"));
    }

    @Test
    void shouldThrowValidationExceptionWhenJWTIsInvalid() throws ParseException, JOSEException {

        JSONObject requestBody = new JSONObject();
        requestBody.put("client_id", "ipv-core");
        requestBody.put("request", "sharedClaimsJsonObject");
        String testRequestBody = requestBody.toString();

        when(mockJwtDecrypter.decrypt(any())).thenReturn(null);

        SessionValidationException exception =
                assertThrows(
                        SessionValidationException.class,
                        () -> sessionRequestService.validateSessionRequest(testRequestBody));
        assertThat(
                exception.getMessage(),
                containsString("could not parse request body to signed JWT"));
    }

    @Test
    void shouldFailOnInvalidDOBInClaimsWithoutRevealingPII() throws Exception {
        List<String> sensitiveFields = List.of("name", "birthDate", "address");
        SimpleModule redactionModule = new SimpleModule();
        redactionModule.addDeserializer(
                SharedClaims.class,
                new PIIRedactingDeserializer<>(sensitiveFields, SharedClaims.class));
        objectMapper.registerModule(new JavaTimeModule()).registerModule(redactionModule);
        sessionRequestService =
                new SessionRequestService(
                        objectMapper, mockJwtVerifier, mockConfigurationService, mockJwtDecrypter);

        JSONObject requestBody = new JSONObject();
        requestBody.put("client_id", "some-client-id");
        requestBody.put("request", "some.jwt.value");
        String request = requestBody.toString();
        String birthdaySharedClaim =
                "{\"@context\":[\"https:\\/\\/www.w3.org\\/2018\\/credentials\\/v1\",\"https:\\/\\/vocab.london.cloudapps.digital\\/contexts\\/identity-v1.jsonld\"],\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"KENNETH\"},{\"type\":\"FamilyName\",\"value\":\"DECERQUEIRA\"}]}],\"birthDate\":[{\"value\":\"1965-00-00\"}],\"address\":[{\"buildingNumber\":\"8\",\"streetName\":\"HADLEY ROAD\",\"postalCode\":\"BA2 5AA\",\"validFrom\":\"2021-01-01\"}]}";

        SignedJWT signedJWT =
                new SignedJWTBuilder()
                        .setPrivateKeyFile("signing_ec.pk8")
                        .setCertificateFile("signing_ec.crt.pem")
                        .setSigningAlgorithm(JWSAlgorithm.ES384)
                        .setSharedClaims(birthdaySharedClaim)
                        .build();

        when(mockJwtDecrypter.decrypt(requestBody.get("request").toString())).thenReturn(signedJWT);
        SessionValidationException exception =
                assertThrows(
                        SessionValidationException.class,
                        () -> sessionRequestService.validateSessionRequest(request));

        assertThat(exception.getCause().getMessage(), not(containsString(birthdaySharedClaim)));
        assertThat(
                exception.getCause().getMessage(),
                containsString(
                        "Error while deserializing object. Some PII fields were redacted. {\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://vocab.london.cloudapps.digital/contexts/identity-v1.jsonld\"],\"name\":\"******\",\"birthDate\":\"******\",\"address\":\"******\"}"));
        assertThat(exception.getMessage(), containsString("Could not parse request body"));
    }

    @Test
    void shouldValidateJWTSignedWithECKey()
            throws SessionValidationException, ClientConfigurationException,
                    java.text.ParseException, JOSEException, JsonProcessingException {
        JSONObject requestBody = new JSONObject();
        requestBody.put("client_id", "ipv-core");
        requestBody.put("request", "some.jwt.value");
        String testRequestBody = requestBody.toString();
        SignedJWTBuilder signedJWTBuilder =
                new SignedJWTBuilder()
                        .setPrivateKeyFile("signing_ec.pk8")
                        .setCertificateFile("signing_ec.crt.pem")
                        .setSigningAlgorithm(JWSAlgorithm.ES384)
                        .setIncludeSharedClaims(Boolean.TRUE);
        SignedJWT signedJWT = signedJWTBuilder.build();
        RawSessionRequest rawSessionRequest = createRawSessionRequest(signedJWT);

        when(mockJwtDecrypter.decrypt(any())).thenReturn(signedJWT);
        Map<String, String> configMap = standardSSMConfigMap(signedJWTBuilder.getCertificate());
        configMap.put("authenticationAlg", "ES384");
        initMockConfigurationService(configMap);

        SessionRequest result = sessionRequestService.validateSessionRequest(testRequestBody);

        makeSessionRequestFieldValueAssertions(
                result, rawSessionRequest, signedJWT.getJWTClaimsSet());
    }

    private void makeSessionRequestFieldValueAssertions(
            SessionRequest sessionRequest,
            RawSessionRequest rawSessionRequest,
            JWTClaimsSet jwtClaims)
            throws java.text.ParseException, JsonProcessingException {
        assertThat(sessionRequest.getAudience(), equalTo(jwtClaims.getAudience().get(0)));
        assertThat(sessionRequest.getIssuer(), equalTo(jwtClaims.getIssuer()));
        assertThat(sessionRequest.getSubject(), equalTo(jwtClaims.getSubject()));
        assertThat(
                objectMapper.writeValueAsString(sessionRequest.getSharedClaims()),
                equalTo(objectMapper.writeValueAsString(testSharedClaims)));
        assertThat(sessionRequest.getState(), equalTo(jwtClaims.getStringClaim("state")));
        assertThat(sessionRequest.getClientId(), equalTo(rawSessionRequest.getClientId()));
        assertThat(sessionRequest.getClientId(), equalTo(jwtClaims.getStringClaim("client_id")));
        assertThat(
                sessionRequest.getRedirectUri(),
                equalTo(URI.create(jwtClaims.getStringClaim("redirect_uri"))));
        assertThat(
                sessionRequest.getResponseType(),
                equalTo(jwtClaims.getStringClaim("response_type")));
        assertThat(
                sessionRequest.getPersistentSessionId(),
                equalTo(jwtClaims.getStringClaim("persistent_session_id")));
        assertThat(
                sessionRequest.getClientSessionId(),
                equalTo(jwtClaims.getStringClaim("govuk_signin_journey_id")));
    }

    private String marshallToJSON(Object sessionRequest) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(sessionRequest);
    }

    private RawSessionRequest createRawSessionRequest(SignedJWT signedJWT) {
        return createRawSessionRequest(signedJWT.serialize());
    }

    private RawSessionRequest createRawSessionRequest(String serialisedJWT) {
        RawSessionRequest rawSessionRequest = new RawSessionRequest();
        rawSessionRequest.setClientId("ipv-core");
        rawSessionRequest.setRequestJWT(serialisedJWT);
        return rawSessionRequest;
    }

    private Map<String, String> standardSSMConfigMap(Certificate certificate) {
        try {
            HashMap<String, String> map = new HashMap<>();
            map.put("redirectUri", "https://www.example/com/callback");
            map.put("authenticationAlg", "RS256");
            map.put("issuer", "ipv-core");
            map.put(
                    "publicCertificateToVerify",
                    Base64.getEncoder().encodeToString(certificate.getEncoded()));
            return map;
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private void initMockConfigurationService(Map<String, String> parameters) {
        when(mockConfigurationService.getParametersForPath("/clients/ipv-core/jwtAuthentication"))
                .thenReturn(parameters);
    }
}
