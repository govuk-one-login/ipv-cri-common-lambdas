package uk.gov.di.ipv.cri.common.api.service;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthorizationValidatorServiceTest {

    @Mock private ConfigurationService mockConfigurationService;
    @InjectMocks private AuthorizationValidatorService authorizationValidatorService;

    @Test
    void shouldValidateSuccessfully() throws SessionValidationException {
        AuthenticationRequest mockAuthenticationRequest = mock(AuthenticationRequest.class);
        SessionItem mockSessionItem = mock(SessionItem.class);
        when(mockSessionItem.getClientId()).thenReturn("ipv-core");
        URI mockURI = URI.create("https://www.example/com/callback");
        when(mockAuthenticationRequest.getRedirectionURI()).thenReturn(mockURI);
        ClientID clientID = mock(ClientID.class);
        when(clientID.getValue()).thenReturn("ipv-core");
        when(mockAuthenticationRequest.getClientID()).thenReturn(clientID);
        initMockConfigurationService(standardSSMConfigMap());

        authorizationValidatorService.validate(mockAuthenticationRequest, mockSessionItem);
        verify(mockConfigurationService, times(1)).getParametersForPath(anyString());
    }

    @Test
    void shouldThrowValidationExceptionWhenRedirectUriDoesNotMatch() {
        AuthenticationRequest mockAuthenticationRequest = mock(AuthenticationRequest.class);
        SessionItem mockSessionItem = mock(SessionItem.class);
        when(mockSessionItem.getClientId()).thenReturn("ipv-core");
        URI mockURI = URI.create("https://www.example.com/not-valid-callback");
        when(mockAuthenticationRequest.getRedirectionURI()).thenReturn(mockURI);
        ClientID clientID = mock(ClientID.class);
        when(clientID.getValue()).thenReturn("ipv-core");
        when(mockAuthenticationRequest.getClientID()).thenReturn(clientID);
        initMockConfigurationService(standardSSMConfigMap());

        SessionValidationException exception =
                assertThrows(
                        SessionValidationException.class,
                        () ->
                                authorizationValidatorService.validate(
                                        mockAuthenticationRequest, mockSessionItem));

        assertThat(
                exception.getMessage(),
                containsString(
                        "redirect uri: https://www.example.com/not-valid-callback does not match configuration uri: https://www.example/com/callback"));
    }

    @Test
    void shouldThrowValidationExceptionWhenClientIdDoesNotMatch() {
        AuthenticationRequest mockAuthenticationRequest = mock(AuthenticationRequest.class);
        SessionItem mockSessionItem = mock(SessionItem.class);
        when(mockSessionItem.getClientId()).thenReturn("ipv-core");
        ClientID clientID = new ClientID("ipv-core-incorrect");
        when(mockAuthenticationRequest.getClientID()).thenReturn(clientID);

        SessionValidationException exception =
                assertThrows(
                        SessionValidationException.class,
                        () ->
                                authorizationValidatorService.validate(
                                        mockAuthenticationRequest, mockSessionItem));

        assertThat(
                exception.getMessage(),
                containsString(
                        "client_id: ipv-core-incorrect does not match configuration: ipv-core"));
    }

    private Map<String, String> standardSSMConfigMap() {
        HashMap<String, String> map = new HashMap<>();
        map.put("redirectUri", "https://www.example/com/callback");
        map.put("issuer", "ipv-core");
        return map;
    }

    private void initMockConfigurationService(Map<String, String> parameters) {
        when(mockConfigurationService.getParametersForPath("/clients/ipv-core/jwtAuthentication"))
                .thenReturn(parameters);
    }
}
