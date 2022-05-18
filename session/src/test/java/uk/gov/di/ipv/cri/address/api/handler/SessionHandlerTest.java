package uk.gov.di.ipv.cri.address.api.handler;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.address.api.service.SessionRequestService;
import uk.gov.di.ipv.cri.address.library.domain.AuditEventTypes;
import uk.gov.di.ipv.cri.address.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.address.library.domain.sharedclaims.SharedClaims;
import uk.gov.di.ipv.cri.address.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.address.library.exception.ClientConfigurationException;
import uk.gov.di.ipv.cri.address.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.address.library.exception.SqsException;
import uk.gov.di.ipv.cri.address.library.service.AuditService;
import uk.gov.di.ipv.cri.address.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.address.library.service.SessionService;
import uk.gov.di.ipv.cri.address.library.util.EventProbe;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.address.api.handler.SessionHandler.REDIRECT_URI;
import static uk.gov.di.ipv.cri.address.api.handler.SessionHandler.SESSION_ID;
import static uk.gov.di.ipv.cri.address.api.handler.SessionHandler.STATE;

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

        when(eventProbe.counterMetric(anyString())).thenReturn(eventProbe);

        UUID sessionId = UUID.randomUUID();
        SharedClaims sharedClaims = new SharedClaims();
        when(sessionRequest.getClientId()).thenReturn("ipv-core");
        when(sessionRequest.getState()).thenReturn("some state");
        when(sessionRequest.getRedirectUri())
                .thenReturn(URI.create("https://www.example.com/callback"));
        when(sessionRequest.hasSharedClaims()).thenReturn(Boolean.TRUE);
        when(sessionRequest.getSharedClaims()).thenReturn(sharedClaims);
        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
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
        verify(auditService).sendAuditEvent(AuditEventTypes.IPV_ADDRESS_CRI_START);
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
        Map responseBody = new ObjectMapper().readValue(responseEvent.getBody(), Map.class);
        assertEquals(ErrorResponse.SESSION_VALIDATION_ERROR.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.SESSION_VALIDATION_ERROR.getMessage(), responseBody.get("message"));

        verify(eventProbe).counterMetric("session_created", 0d);
        verify(eventProbe).log(Level.ERROR, sessionValidationException);

        verify(auditService, never()).sendAuditEvent(any());
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
        Map responseBody = new ObjectMapper().readValue(responseEvent.getBody(), Map.class);
        assertEquals(ErrorResponse.SERVER_CONFIG_ERROR.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.SERVER_CONFIG_ERROR.getMessage(), responseBody.get("message"));

        verify(eventProbe).counterMetric("session_created", 0d);

        verify(auditService, never()).sendAuditEvent(any());
        verify(sessionService, never()).saveSession(sessionRequest);
    }

    private void setupEventProbeErrorBehaviour() {
        when(eventProbe.counterMetric(anyString(), anyDouble())).thenReturn(eventProbe);
        when(eventProbe.log(any(Level.class), any(Exception.class))).thenReturn(eventProbe);
    }
}
