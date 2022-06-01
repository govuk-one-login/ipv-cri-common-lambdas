package uk.gov.di.ipv.cri.common.api.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import uk.gov.di.ipv.cri.common.api.domain.RawSessionRequest;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.exception.ClientConfigurationException;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.JWTVerifier;

import java.net.URI;
import java.util.Map;

public class SessionRequestService {
    private static final String SHARED_CLAIMS_NAME = "shared_claims";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String CLIENT_ID = "client_id";

    private final ObjectMapper objectMapper;
    private final JWTVerifier jwtVerifier;

    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public SessionRequestService() {
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        this.jwtVerifier = new JWTVerifier();
        this.configurationService = new ConfigurationService();
    }

    public SessionRequestService(
            ObjectMapper objectMapper,
            JWTVerifier jwtVerifier,
            ConfigurationService configurationService) {
        this.objectMapper = objectMapper;
        this.jwtVerifier = jwtVerifier;
        this.configurationService = configurationService;
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
            //            SignedJWT requestJWT =
            // decryptSessionRequest(rawSessionRequest.getRequestJWT());

            //            if (Objects.isNull(requestJWT)) {
            //                throw new SessionValidationException("could not parse request body to
            // signed JWT");
            //            }
            //
            //            JWTClaimsSet jwtClaims = requestJWT.getJWTClaimsSet();
            //
            //            SessionRequest sessionRequest = new SessionRequest();
            //            sessionRequest.setAudience(jwtClaims.getAudience().get(0));
            //            sessionRequest.setClientId(rawSessionRequest.getClientId());
            //            sessionRequest.setJwtClientId(jwtClaims.getStringClaim(CLIENT_ID));
            //            sessionRequest.setExpirationTime(jwtClaims.getExpirationTime());
            //            sessionRequest.setIssuer(jwtClaims.getIssuer());
            //            sessionRequest.setNotBeforeTime(jwtClaims.getNotBeforeTime());
            //            sessionRequest.setRedirectUri(jwtClaims.getURIClaim(REDIRECT_URI));
            //            sessionRequest.setResponseType(jwtClaims.getStringClaim("response_type"));
            //            sessionRequest.setSignedJWT(requestJWT);
            //            sessionRequest.setState(jwtClaims.getStringClaim("state"));
            //            sessionRequest.setSubject(jwtClaims.getSubject());

            //            if (jwtClaims.getClaims().containsKey(SHARED_CLAIMS_NAME)) {
            //                SharedClaims sharedClaims =
            //                        this.objectMapper.readValue(
            //                                jwtClaims.getClaim(SHARED_CLAIMS_NAME).toString(),
            //                                SharedClaims.class);
            //                sessionRequest.setSharedClaims(sharedClaims);
            //            }

            return new SessionRequest();
        } catch (JsonProcessingException e) {
            throw new SessionValidationException("Could not parse request body", e);
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
