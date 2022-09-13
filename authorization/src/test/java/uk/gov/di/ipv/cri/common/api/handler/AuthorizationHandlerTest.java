package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.api.service.AuthorizationValidatorService;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationHandlerTest {

    @Mock private SessionService mockSessionService;
    @Mock private AuthorizationValidatorService mockAuthorizationValidatorService;
    @Mock private APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent;
    @Mock private EventProbe eventProbe;
    @InjectMocks private AuthorizationHandler authorizationHandler;

    @Test
    void shouldReturn200AndCreateAuthorisationSuccessfully() throws JsonProcessingException {
        Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "http://example.com");
        params.put("client_id", "ipv-core");
        params.put("response_type", "code");
        params.put("scope", "openid");
        params.put("state", "state-ipv");
        when(apiGatewayProxyRequestEvent.getQueryStringParameters()).thenReturn(params);
        UUID sessionId = UUID.randomUUID();
        when(apiGatewayProxyRequestEvent.getHeaders())
                .thenReturn(Map.of("session-id", sessionId.toString()));

        SessionItem mockSessionItem = mock(SessionItem.class);

        when(mockSessionItem.getAuthorizationCode()).thenReturn("auth-code");

        when(mockSessionService.getSession(sessionId.toString())).thenReturn(mockSessionItem);

        when(eventProbe.counterMetric(anyString())).thenReturn(eventProbe);
        when(eventProbe.auditEvent(any())).thenReturn(eventProbe);

        APIGatewayProxyResponseEvent responseEvent =
                authorizationHandler.handleRequest(apiGatewayProxyRequestEvent, null);
        assertNotNull(responseEvent.getBody());
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        JsonNode node = objectMapper.readTree(responseEvent.getBody());
        assertEquals("http://example.com", node.get("redirectionURI").textValue());
        assertEquals("state-ipv", node.get("state").get("value").textValue());
        assertEquals("auth-code", node.get("authorizationCode").get("value").textValue());

        verify(mockSessionService).getSession(sessionId.toString());
        verify(eventProbe).counterMetric(anyString());
        verify(eventProbe).auditEvent(any());
    }

    @Test
    void shouldThrowServerExceptionWhenScopeParamIsMissing() throws JsonProcessingException {
        Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "http://example.com");
        params.put("client_id", "ipv-core");
        params.put("response_type", "code");
        params.put("state", "state-ipv");
        when(apiGatewayProxyRequestEvent.getQueryStringParameters()).thenReturn(params);

        when(eventProbe.log(any(Level.class), any(Exception.class))).thenReturn(eventProbe);

        APIGatewayProxyResponseEvent response =
                authorizationHandler.handleRequest(apiGatewayProxyRequestEvent, null);
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(1020, responseBody.get("code"));
        assertEquals("Server Configuration Error", responseBody.get("message"));

        verify(eventProbe).log(any(Level.class), any(Exception.class));
    }

    @Test
    void shouldThrowSessionValidationExceptionWhenClientIDDoesNotMatch()
            throws JsonProcessingException {
        Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "http://example.com");
        params.put("client_id", "ipv-core");
        params.put("response_type", "code");
        params.put("scope", "openid");
        params.put("state", "state-ipv");
        when(apiGatewayProxyRequestEvent.getQueryStringParameters()).thenReturn(params);
        UUID sessionId = UUID.randomUUID();
        when(apiGatewayProxyRequestEvent.getHeaders())
                .thenReturn(Map.of("session-id", sessionId.toString()));

        SessionItem mockSessionItem = mock(SessionItem.class);
        when(mockSessionItem.getClientId()).thenReturn("wrong-client-id");
        when(mockSessionService.getSession(sessionId.toString())).thenReturn(mockSessionItem);

        when(eventProbe.log(any(Level.class), any(Exception.class))).thenReturn(eventProbe);

        ConfigurationService mockConfigurationService = mock(ConfigurationService.class);
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("redirectUri", "https://www.example/com/callback");

        AuthorizationValidatorService validatorService =
                new AuthorizationValidatorService(mockConfigurationService);
        AuthorizationHandler authorizationHandler =
                new AuthorizationHandler(mockSessionService, eventProbe, validatorService);

        APIGatewayProxyResponseEvent response =
                authorizationHandler.handleRequest(apiGatewayProxyRequestEvent, null);

        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(1019, responseBody.get("code"));
        assertEquals("Session Validation Exception", responseBody.get("message"));

        verify(mockSessionService).getSession(sessionId.toString());
        verify(eventProbe).log(any(Level.class), any(Exception.class));
    }
}
