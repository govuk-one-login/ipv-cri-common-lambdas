package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.api.service.AuthorizationValidatorService;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationHandlerTest {
    private static final String FOUND_SESSION_LOG_MESSAGE = "found session";
    private static final String SESSION_ID = UUID.randomUUID().toString();

    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    @Mock private SessionService mockSessionService;
    @Mock private AuthorizationValidatorService mockAuthorizationValidatorService;
    @Mock private APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent;
    @Mock private EventProbe mockEventProbe;
    @InjectMocks private AuthorizationHandler authorizationHandler;

    @Test
    void shouldReturn200AndCreateAuthorisationSuccessfully() throws JsonProcessingException {
        String redirectUri = "https://example.com";
        String authCode = "auth-code";
        String state = "state-ipv";
        Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", redirectUri);
        params.put("client_id", "ipv-core");
        params.put("response_type", "code");
        params.put("scope", "openid");
        params.put("state", state);
        when(apiGatewayProxyRequestEvent.getQueryStringParameters()).thenReturn(params);

        when(apiGatewayProxyRequestEvent.getHeaders()).thenReturn(Map.of("session-id", SESSION_ID));

        SessionItem mockSessionItem = mock(SessionItem.class);
        when(mockSessionItem.getAuthorizationCode()).thenReturn(authCode);
        when(mockSessionItem.getClientSessionId()).thenReturn(SESSION_ID);

        when(mockSessionService.getSession(SESSION_ID)).thenReturn(mockSessionItem);

        when(mockEventProbe.addJourneyIdToLoggingContext(SESSION_ID)).thenReturn(mockEventProbe);
        when(mockEventProbe.log(Level.INFO, FOUND_SESSION_LOG_MESSAGE)).thenReturn(mockEventProbe);
        when(mockEventProbe.counterMetric(anyString())).thenReturn(mockEventProbe);
        when(mockEventProbe.auditEvent(any())).thenReturn(mockEventProbe);

        APIGatewayProxyResponseEvent responseEvent =
                authorizationHandler.handleRequest(apiGatewayProxyRequestEvent, null);
        assertNotNull(responseEvent.getBody());

        JsonNode node = objectMapper.readTree(responseEvent.getBody());
        assertEquals(redirectUri, node.get("redirectionURI").textValue());
        assertEquals(state, node.get("state").get("value").textValue());
        assertEquals(authCode, node.get("authorizationCode").get("value").textValue());

        verify(mockSessionService).getSession(SESSION_ID);
        verify(mockAuthorizationValidatorService)
                .validate(any(AuthenticationRequest.class), eq(mockSessionItem));
        verify(mockEventProbe).addJourneyIdToLoggingContext(SESSION_ID);
        verify(mockEventProbe).log(Level.INFO, FOUND_SESSION_LOG_MESSAGE);
        verify(mockEventProbe).counterMetric(anyString());
        verify(mockEventProbe).auditEvent(any());
    }

    @Test
    void shouldThrowServerExceptionWhenScopeParamIsMissing() throws JsonProcessingException {
        Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "https://example.com");
        params.put("client_id", "ipv-core");
        params.put("response_type", "code");
        params.put("state", "state-ipv");
        when(apiGatewayProxyRequestEvent.getQueryStringParameters()).thenReturn(params);

        when(mockEventProbe.log(any(Level.class), any(Exception.class))).thenReturn(mockEventProbe);

        APIGatewayProxyResponseEvent response =
                authorizationHandler.handleRequest(apiGatewayProxyRequestEvent, null);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(1020, responseBody.get("code"));
        assertEquals("Server Configuration Error", responseBody.get("message"));
        verify(mockEventProbe).log(eq(Level.ERROR), any(Exception.class));
    }

    @Test
    void shouldReturnBadRequestWhenSessionValidationFails() throws JsonProcessingException {
        Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "https://example.com");
        params.put("client_id", "ipv-core");
        params.put("response_type", "code");
        params.put("scope", "openid");
        params.put("state", "state-ipv");
        when(apiGatewayProxyRequestEvent.getQueryStringParameters()).thenReturn(params);

        when(apiGatewayProxyRequestEvent.getHeaders()).thenReturn(Map.of("session-id", SESSION_ID));

        SessionItem mockSessionItem = mock(SessionItem.class);
        when(mockSessionItem.getClientSessionId()).thenReturn(SESSION_ID);

        when(mockSessionService.getSession(SESSION_ID)).thenReturn(mockSessionItem);

        when(mockEventProbe.log(Level.INFO, FOUND_SESSION_LOG_MESSAGE)).thenReturn(mockEventProbe);
        when(mockEventProbe.addJourneyIdToLoggingContext(SESSION_ID)).thenReturn(mockEventProbe);
        when(mockEventProbe.log(eq(Level.ERROR), any(SessionValidationException.class)))
                .thenReturn(mockEventProbe);

        doThrow(new SessionValidationException("test exception"))
                .when(mockAuthorizationValidatorService)
                .validate(any(AuthenticationRequest.class), eq(mockSessionItem));

        APIGatewayProxyResponseEvent response =
                authorizationHandler.handleRequest(apiGatewayProxyRequestEvent, null);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(1019, responseBody.get("code"));
        assertEquals("Session Validation Exception", responseBody.get("message"));

        verify(mockSessionService).getSession(SESSION_ID);
        verify(mockEventProbe).log(Level.INFO, FOUND_SESSION_LOG_MESSAGE);
        verify(mockEventProbe).log(eq(Level.ERROR), any(SessionValidationException.class));
    }
}
