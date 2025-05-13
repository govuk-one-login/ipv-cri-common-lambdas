package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.AccessTokenValidationException;
import uk.gov.di.ipv.cri.common.library.exception.AuthorizationCodeExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionNotFoundException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.common.api.handler.AccessTokenHandler.JWT_VERIFICATION_FAILED;
import static uk.gov.di.ipv.cri.common.api.handler.AccessTokenHandler.METRIC_NAME_ACCESS_TOKEN;

@ExtendWith(MockitoExtension.class)
class AccessTokenHandlerTest {
    private static final String FOUND_SESSION_LOG_MESSAGE = "found session";

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock private EventProbe mockEventProbe;
    @Mock private AccessTokenService mockAccessTokenService;
    @Mock private SessionService mockSessionService;
    @Mock private TokenRequest tokenRequest;
    @InjectMocks private AccessTokenHandler handler;

    @Test
    void shouldReturnAccessTokenOnSuccessfulExchange() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String clientSessionId = "client-session-id";
        String authCodeValue = "12345";
        String grantType = "authorization_code";
        String tokenRequestBody =
                String.format(
                        "code=%s"
                                + "&client_assertion=%s"
                                + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                                + "&client_id=urn:uuid:ipv-core"
                                + "&grant_type=%s",
                        authCodeValue, "jwt-string", grantType);
        event.withBody(tokenRequestBody);
        AccessTokenResponse tokenResponse = createTestTokenResponse();
        SessionItem mockSessionItem = mock(SessionItem.class);
        when(mockSessionItem.getClientSessionId()).thenReturn(clientSessionId);

        when(mockEventProbe.addJourneyIdToLoggingContext(clientSessionId))
                .thenReturn(mockEventProbe);

        when(mockAccessTokenService.createTokenRequest(tokenRequestBody)).thenReturn(tokenRequest);
        when(mockAccessTokenService.getAuthorizationCode(tokenRequest)).thenReturn(authCodeValue);
        when(mockAccessTokenService.createToken(tokenRequest)).thenReturn(tokenResponse);
        when(mockSessionService.getSessionByAuthorisationCode(authCodeValue))
                .thenReturn(mockSessionItem);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, null);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(
                ContentType.APPLICATION_JSON.getType(), response.getHeaders().get("Content-Type"));
        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(
                tokenResponse.toSuccessResponse().getTokens().getAccessToken().getValue(),
                responseBody.get("access_token").toString());

        verify(mockAccessTokenService).createTokenRequest(tokenRequestBody);
        verify(mockAccessTokenService).getAuthorizationCode(tokenRequest);
        verify(mockAccessTokenService).createToken(tokenRequest);
        verify(mockSessionService).getSessionByAuthorisationCode(authCodeValue);
        verify(mockEventProbe).addJourneyIdToLoggingContext(clientSessionId);
        verify(mockEventProbe).log(Level.INFO, FOUND_SESSION_LOG_MESSAGE);
        verify(mockEventProbe).counterMetric(METRIC_NAME_ACCESS_TOKEN);
    }

    @Test
    void shouldReturn400WhenCannotCreateTokenRequest()
            throws AccessTokenValidationException, JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.withBody("some body");

        AccessTokenValidationException exception =
                new AccessTokenValidationException("an error message");
        when(mockAccessTokenService.createTokenRequest("some body")).thenThrow(exception);
        when(mockEventProbe.log(Level.ERROR, exception)).thenReturn(mockEventProbe);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, null);

        assertErrorResponse(response, ErrorResponse.TOKEN_VALIDATION_ERROR);
        verify(mockEventProbe).log(Level.ERROR, exception);
        verify(mockEventProbe).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
        verify(mockEventProbe).counterMetric(JWT_VERIFICATION_FAILED);
        verifyNoMoreInteractions(mockAccessTokenService);
    }

    @Test
    void shouldReturn400WhenCannotValidateTokenRequest()
            throws AccessTokenValidationException, JsonProcessingException,
                    AuthorizationCodeExpiredException, SessionExpiredException,
                    SessionNotFoundException {
        String clientSessionId = "client-session-id";
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.withBody("some body");
        SessionItem mockSessionItem = mock(SessionItem.class);
        when(mockSessionItem.getClientSessionId()).thenReturn(clientSessionId);
        String authCode = String.valueOf(UUID.randomUUID());
        AccessTokenValidationException exception =
                new AccessTokenValidationException("an error message");
        when(mockAccessTokenService.createTokenRequest("some body")).thenReturn(tokenRequest);
        when(mockAccessTokenService.getAuthorizationCode(tokenRequest)).thenReturn(authCode);
        when(mockSessionService.getSessionByAuthorisationCode(authCode))
                .thenReturn(mockSessionItem);
        when(mockAccessTokenService.validateTokenRequest(tokenRequest, mockSessionItem))
                .thenThrow(exception);

        when(mockEventProbe.addJourneyIdToLoggingContext(clientSessionId))
                .thenReturn(mockEventProbe);
        when(mockEventProbe.log(Level.INFO, FOUND_SESSION_LOG_MESSAGE)).thenReturn(mockEventProbe);
        when(mockEventProbe.log(Level.ERROR, exception)).thenReturn(mockEventProbe);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, null);

        assertErrorResponse(response, ErrorResponse.TOKEN_VALIDATION_ERROR);
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        verify(mockEventProbe).log(Level.INFO, FOUND_SESSION_LOG_MESSAGE);
        verify(mockEventProbe).log(Level.ERROR, exception);
        verify(mockEventProbe).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
        verify(mockEventProbe).counterMetric(JWT_VERIFICATION_FAILED);
        verifyNoMoreInteractions(mockAccessTokenService);
    }

    @Test
    void shouldReturn403WhenSessionExpired()
            throws AccessTokenValidationException, JsonProcessingException,
                    AuthorizationCodeExpiredException, SessionExpiredException,
                    SessionNotFoundException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.withBody("some body");
        String authCode = String.valueOf(UUID.randomUUID());
        var exception = new SessionExpiredException("expired");
        when(mockAccessTokenService.createTokenRequest("some body")).thenReturn(tokenRequest);
        when(mockAccessTokenService.getAuthorizationCode(tokenRequest)).thenReturn(authCode);
        when(mockSessionService.getSessionByAuthorisationCode(authCode)).thenThrow(exception);
        when(mockEventProbe.log(Level.ERROR, exception)).thenReturn(mockEventProbe);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, null);

        assertErrorResponse(response, ErrorResponse.SESSION_EXPIRED);
        assertEquals(HttpStatusCode.FORBIDDEN, response.getStatusCode());
        verify(mockEventProbe).log(Level.ERROR, exception);
        verify(mockEventProbe).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
        verifyNoMoreInteractions(mockAccessTokenService);
    }

    @Test
    void shouldReturn403WhenAuthorizationCodeExpired()
            throws AccessTokenValidationException, JsonProcessingException,
                    AuthorizationCodeExpiredException, SessionExpiredException,
                    SessionNotFoundException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.withBody("some body");
        String authCode = String.valueOf(UUID.randomUUID());
        var exception = new AuthorizationCodeExpiredException("expired");
        when(mockAccessTokenService.createTokenRequest("some body")).thenReturn(tokenRequest);
        when(mockAccessTokenService.getAuthorizationCode(tokenRequest)).thenReturn(authCode);
        when(mockSessionService.getSessionByAuthorisationCode(authCode)).thenThrow(exception);
        when(mockEventProbe.log(Level.ERROR, exception)).thenReturn(mockEventProbe);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, null);

        assertErrorResponse(response, ErrorResponse.AUTHORIZATION_CODE_EXPIRED);
        assertEquals(HttpStatusCode.FORBIDDEN, response.getStatusCode());
        verify(mockEventProbe).log(Level.ERROR, exception);
        verify(mockEventProbe).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
        verifyNoMoreInteractions(mockAccessTokenService);
    }

    private AccessTokenResponse createTestTokenResponse() {
        AccessToken accessToken =
                new BearerAccessToken(
                        Duration.of(1, ChronoUnit.HOURS).toSeconds(), Scope.parse("some-scope"));
        return new AccessTokenResponse(new Tokens(accessToken, null)).toSuccessResponse();
    }

    private void assertErrorResponse(
            APIGatewayProxyResponseEvent response, ErrorResponse errorResponse)
            throws JsonProcessingException {
        Map<?, ?> responseBody = new ObjectMapper().readValue(response.getBody(), Map.class);
        assertEquals(errorResponse.getCode(), responseBody.get("code"));
        assertEquals(errorResponse.getMessage(), responseBody.get("message"));
    }
}
