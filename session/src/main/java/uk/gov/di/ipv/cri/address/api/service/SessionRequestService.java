package uk.gov.di.ipv.cri.address.api.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.cri.address.api.domain.RawSessionRequest;
import uk.gov.di.ipv.cri.address.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.address.library.exception.ClientConfigurationException;
import uk.gov.di.ipv.cri.address.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.address.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.address.library.service.JWTVerifier;

import java.net.URI;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

public class SessionRequestService {
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String CLIENT_ID = "client_id";

    private final ObjectMapper objectMapper;
    private final JWTVerifier jwtVerifier;
    private final JWTDecrypter jwtDecrypter;
    private final ConfigurationService configurationService;

    public SessionRequestService() {
        this.objectMapper = new ObjectMapper();
        this.jwtVerifier = new JWTVerifier();
        this.configurationService = new ConfigurationService();
        String encryptionKeyId = this.configurationService.getKmsEncryptionKeyId();
        this.jwtDecrypter = new JWTDecrypter(new KMSRSADecrypter(encryptionKeyId));
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

            return sessionRequest;
        } catch (JsonProcessingException | ParseException e) {
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
