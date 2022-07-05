package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.api.service.SessionRequestService;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.SharedClaims;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.ClientConfigurationException;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.common.api.handler.SessionHandler.REDIRECT_URI;
import static uk.gov.di.ipv.cri.common.api.handler.SessionHandler.SESSION_ID;
import static uk.gov.di.ipv.cri.common.api.handler.SessionHandler.STATE;

@ExtendWith(MockitoExtension.class)
class SessionHandlerTest {

    @Mock private SessionService sessionService;

    @Mock private SessionRequestService sessionRequestService;

    @Mock private PersonIdentityService personIdentityService;

    @Mock private APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent;

    @Mock private SessionRequest sessionRequest;

    @Mock private EventProbe eventProbe;

    @Mock private AuditService auditService;

    @InjectMocks private SessionHandler sessionHandler;

    @Test
    void shouldCreateAndSaveAddressSession()
            throws SessionValidationException, ClientConfigurationException,
                    JsonProcessingException, SqsException {

        UUID sessionId = UUID.randomUUID();
        SharedClaims sharedClaims = new SharedClaims();
        Map<String, String> requestHeaders = Map.of("header-name", "headerValue");
        String subject = "subject";
        ArgumentCaptor<AuditEventContext> auditEventContextArgumentCaptor =
                ArgumentCaptor.forClass(AuditEventContext.class);
        when(eventProbe.counterMetric(anyString())).thenReturn(eventProbe);
        when(sessionRequest.getClientId()).thenReturn("ipv-core");
        when(sessionRequest.getState()).thenReturn("some state");
        when(sessionRequest.getRedirectUri())
                .thenReturn(URI.create("https://www.example.com/callback"));
        when(sessionRequest.hasSharedClaims()).thenReturn(Boolean.TRUE);
        when(sessionRequest.getSharedClaims()).thenReturn(sharedClaims);
        when(sessionRequest.getSubject()).thenReturn(subject);
        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
        when(apiGatewayProxyRequestEvent.getHeaders()).thenReturn(requestHeaders);
        when(sessionRequestService.validateSessionRequest("some json")).thenReturn(sessionRequest);
        when(sessionService.saveSession(sessionRequest)).thenReturn(sessionId);

        APIGatewayProxyResponseEvent responseEvent =
                sessionHandler.handleRequest(apiGatewayProxyRequestEvent, null);

        assertEquals(HttpStatusCode.CREATED, responseEvent.getStatusCode());
        var responseBody = new ObjectMapper().readValue(responseEvent.getBody(), Map.class);
        assertEquals(sessionId.toString(), responseBody.get(SESSION_ID));
        assertEquals("some state", responseBody.get(STATE));
        assertEquals("https://www.example.com/callback", responseBody.get(REDIRECT_URI));

        verify(sessionService).saveSession(sessionRequest);
        verify(personIdentityService).savePersonIdentity(sessionId, sharedClaims);
        verify(eventProbe).addDimensions(Map.of("issuer", "ipv-core"));
        verify(eventProbe).counterMetric("session_created");
        verify(auditService)
                .sendAuditEvent(
                        eq(AuditEventType.START), auditEventContextArgumentCaptor.capture());
        AuditEventContext auditEventContext = auditEventContextArgumentCaptor.getValue();
        assertEquals(subject, auditEventContext.getSessionItem().getSubject());
        assertEquals(sessionId, auditEventContext.getSessionItem().getSessionId());
        assertEquals(requestHeaders, auditEventContext.getRequestHeaders());
    }

    @Test
    void shouldCatchValidationExceptionAndReturn400Response()
            throws SessionValidationException, ClientConfigurationException,
                    JsonProcessingException, SqsException {

        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
        SessionValidationException sessionValidationException = new SessionValidationException("");
        when(sessionRequestService.validateSessionRequest("some json"))
                .thenThrow(sessionValidationException);
        setupEventProbeErrorBehaviour();

        APIGatewayProxyResponseEvent responseEvent =
                sessionHandler.handleRequest(apiGatewayProxyRequestEvent, null);
        assertEquals(HttpStatusCode.BAD_REQUEST, responseEvent.getStatusCode());
        Map<String, Object> responseBody =
                new ObjectMapper().readValue(responseEvent.getBody(), new TypeReference<>() {});
        assertEquals(ErrorResponse.SESSION_VALIDATION_ERROR.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.SESSION_VALIDATION_ERROR.getMessage(), responseBody.get("message"));

        verify(eventProbe).counterMetric("session_created", 0d);
        verify(eventProbe).log(Level.ERROR, sessionValidationException);

        verify(auditService, never()).sendAuditEvent(any(AuditEventType.class));
        verify(sessionService, never()).saveSession(sessionRequest);
    }

    @Test
    void shouldCatchServerExceptionAndReturn500Response()
            throws SessionValidationException, ClientConfigurationException,
                    JsonProcessingException, SqsException {

        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
        when(sessionRequestService.validateSessionRequest("some json"))
                .thenThrow(new ClientConfigurationException(new NullPointerException()));
        setupEventProbeErrorBehaviour();

        APIGatewayProxyResponseEvent responseEvent =
                sessionHandler.handleRequest(apiGatewayProxyRequestEvent, null);
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, responseEvent.getStatusCode());
        Map<String, Object> responseBody =
                new ObjectMapper().readValue(responseEvent.getBody(), new TypeReference<>() {});
        assertEquals(ErrorResponse.SERVER_CONFIG_ERROR.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.SERVER_CONFIG_ERROR.getMessage(), responseBody.get("message"));

        verify(eventProbe).counterMetric("session_created", 0d);

        verify(auditService, never()).sendAuditEvent(any(AuditEventType.class));
        verify(sessionService, never()).saveSession(sessionRequest);
    }

    private void setupEventProbeErrorBehaviour() {
        when(eventProbe.counterMetric(anyString(), anyDouble())).thenReturn(eventProbe);
        when(eventProbe.log(any(Level.class), any(Exception.class))).thenReturn(eventProbe);
    }
}
