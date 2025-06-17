package uk.gov.di.ipv.cri.common.api.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.kms.KmsClient;
import uk.gov.di.ipv.cri.common.api.domain.RawSessionRequest;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.SharedClaims;
import uk.gov.di.ipv.cri.common.library.exception.ClientConfigurationException;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.persistence.item.EvidenceRequest;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.JWTVerifier;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.common.library.util.deserializers.PiiRedactingDeserializer;

import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class SessionRequestService {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final String SHARED_CLAIMS_NAME = "shared_claims";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String CLIENT_ID = "client_id";
    private static final String PERSISTENT_SESSION_ID = "persistent_session_id";
    private static final String CLIENT_SESSION_ID = "govuk_signin_journey_id";
    private static final String CONTEXT = "context";
    private static final String EVIDENCE_REQUESTED = "evidence_requested";

    private final ObjectMapper objectMapper;
    private final JWTVerifier jwtVerifier;
    private final JWTDecrypter jwtDecrypter;
    private final ConfigurationService configurationService;

    private final List<String> sensitiveFields = List.of("name", "birthDate", "address");

    @ExcludeFromGeneratedCoverageReport
    public SessionRequestService(
            ConfigurationService configurationService,
            KmsClient kmsClient,
            ObjectMapper objectMapper,
            EventProbe eventProbe) {
        this.configurationService = configurationService;
        this.objectMapper = objectMapper;
        this.objectMapper
                .registerModule(new JavaTimeModule())
                .registerModule(
                        new SimpleModule()
                                .addDeserializer(
                                        SharedClaims.class,
                                        new PiiRedactingDeserializer<>(
                                                sensitiveFields, SharedClaims.class)));
        this.jwtVerifier = new JWTVerifier();
        this.jwtDecrypter =
                new JWTDecrypter(
                        new KMSRSADecrypter(
                                this.configurationService.getKmsEncryptionKeyId(),
                                kmsClient,
                                eventProbe));
    }

    public SessionRequestService(
            ObjectMapper objectMapper,
            JWTVerifier jwtVerifier,
            ConfigurationService configurationService,
            JWTDecrypter jwtDecrypter) {
        this.objectMapper = objectMapper;
        this.jwtVerifier = jwtVerifier;
        this.configurationService = configurationService;
        this.jwtDecrypter = jwtDecrypter;
    }

    public SessionRequest validateSessionRequest(String requestBody)
            throws SessionValidationException, ClientConfigurationException {
        SessionRequest sessionRequest = parseSessionRequest(requestBody);

        Map<String, String> clientAuthenticationConfig =
                getClientAuthenticationConfig(sessionRequest.getClientId());

        verifyRequestUri(sessionRequest.getRedirectUri(), clientAuthenticationConfig);

        jwtVerifier.verifyAuthorizationJWT(
                clientAuthenticationConfig, sessionRequest.getSignedJWT());
        return sessionRequest;
    }

    private SessionRequest parseSessionRequest(String requestBody)
            throws SessionValidationException {
        try {
            RawSessionRequest rawSessionRequest =
                    this.objectMapper.readValue(requestBody, RawSessionRequest.class);
            SignedJWT requestJWT = decryptSessionRequest(rawSessionRequest.getRequestJWT());

            if (Objects.isNull(requestJWT)) {
                throw new SessionValidationException("could not parse request body to signed JWT");
            }

            JWTClaimsSet jwtClaims = requestJWT.getJWTClaimsSet();

            SessionRequest sessionRequest = new SessionRequest();
            sessionRequest.setAudience(jwtClaims.getAudience().get(0));
            sessionRequest.setClientId(rawSessionRequest.getClientId());
            sessionRequest.setJwtClientId(jwtClaims.getStringClaim(CLIENT_ID));
            sessionRequest.setExpirationTime(jwtClaims.getExpirationTime());
            sessionRequest.setIssuer(jwtClaims.getIssuer());
            sessionRequest.setNotBeforeTime(jwtClaims.getNotBeforeTime());
            sessionRequest.setRedirectUri(jwtClaims.getURIClaim(REDIRECT_URI));
            sessionRequest.setResponseType(jwtClaims.getStringClaim("response_type"));
            sessionRequest.setSignedJWT(requestJWT);
            sessionRequest.setState(jwtClaims.getStringClaim("state"));
            sessionRequest.setSubject(jwtClaims.getSubject());

            if (jwtClaims.getClaims().containsKey(PERSISTENT_SESSION_ID)) {
                sessionRequest.setPersistentSessionId(
                        jwtClaims.getStringClaim(PERSISTENT_SESSION_ID));
            }

            if (jwtClaims.getClaims().containsKey(CLIENT_SESSION_ID)) {
                sessionRequest.setClientSessionId(jwtClaims.getStringClaim(CLIENT_SESSION_ID));
            }

            if (jwtClaims.getClaims().containsKey(SHARED_CLAIMS_NAME)) {
                SharedClaims sharedClaims =
                        this.objectMapper.readValue(
                                objectMapper.writeValueAsString(
                                        jwtClaims.getClaim(SHARED_CLAIMS_NAME)),
                                SharedClaims.class);
                sessionRequest.setSharedClaims(sharedClaims);
            }

            if (jwtClaims.getClaims().containsKey(CONTEXT)) {
                sessionRequest.setContext(jwtClaims.getStringClaim(CONTEXT));
            }

            LOGGER.info("Checking EVIDENCE_REQUESTED");
            if (jwtClaims.getClaims().containsKey(EVIDENCE_REQUESTED)) {

                LOGGER.info("Got EVIDENCE_REQUESTED");

                EvidenceRequest evidenceRequest =
                        this.objectMapper.readValue(
                                objectMapper.writeValueAsString(
                                        jwtClaims.getClaim(EVIDENCE_REQUESTED)),
                                EvidenceRequest.class);
                sessionRequest.setEvidenceRequest(evidenceRequest);

                LOGGER.info("EVIDENCE_REQUESTED {}", evidenceRequest.getIdentityFraudScore());
            }

            return sessionRequest;
        } catch (ParseException | JsonProcessingException e) {
            throw new SessionValidationException("Could not parse request body", e);
        }
    }

    private SignedJWT decryptSessionRequest(String serialisedJWE)
            throws SessionValidationException {
        try {
            return jwtDecrypter.decrypt(serialisedJWE);
        } catch (ParseException e) {
            throw new SessionValidationException("Failed to parse request body", e);
        } catch (JOSEException e) {
            throw new SessionValidationException("Decryption failed", e);
        }
    }

    private void verifyRequestUri(URI requestRedirectUri, Map<String, String> clientConfig)
            throws SessionValidationException {
        URI configRedirectUri = URI.create(clientConfig.get("redirectUri"));
        if (requestRedirectUri == null || !requestRedirectUri.equals(configRedirectUri)) {
            throw new SessionValidationException(
                    "redirect uri "
                            + requestRedirectUri
                            + " does not match configuration uri "
                            + configRedirectUri);
        }
    }

    private Map<String, String> getClientAuthenticationConfig(String clientId)
            throws SessionValidationException {
        String path = String.format("/clients/%s/jwtAuthentication", clientId);
        Map<String, String> clientConfig = this.configurationService.getParametersForPath(path);
        if (clientConfig == null || clientConfig.isEmpty()) {
            throw new SessionValidationException(
                    String.format("no configuration for client id '%s'", clientId));
        }
        return clientConfig;
    }
}
