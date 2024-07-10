package uk.gov.di.ipv.cri.common.api.service;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;

import java.net.URI;
import java.util.Map;

public class AuthorizationValidatorService {

    private final ConfigurationService configurationService;

    public AuthorizationValidatorService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public void validate(AuthenticationRequest authenticationRequest, SessionItem sessionItem)
            throws SessionValidationException {

        if (!sessionItem.getClientId().equals(authenticationRequest.getClientID().getValue())) {
            throw new SessionValidationException(
                    "client_id: "
                            + authenticationRequest.getClientID()
                            + " does not match configuration: "
                            + sessionItem.getClientId());
        }

        Map<String, String> clientAuthenticationConfig =
                getClientAuthenticationConfig(authenticationRequest.getClientID().getValue());
        verifyRequestUri(authenticationRequest.getRedirectionURI(), clientAuthenticationConfig);
    }

    private void verifyRequestUri(URI requestRedirectUri, Map<String, String> clientConfig)
            throws SessionValidationException {
        URI configRedirectUri = URI.create(clientConfig.get("redirectUri"));
        if (requestRedirectUri == null || !requestRedirectUri.equals(configRedirectUri)) {
            throw new SessionValidationException(
                    "redirect uri: "
                            + requestRedirectUri
                            + " does not match configuration uri: "
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
