package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.api.domain.AuditEventExtensions;
import uk.gov.di.ipv.cri.common.api.domain.Evidence;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static uk.gov.di.ipv.cri.common.api.handler.SessionHandler.REDIRECT_URI;
import static uk.gov.di.ipv.cri.common.api.handler.SessionHandler.STATE;

@ExtendWith(MockitoExtension.class)
class SessionHandlerTest {
    private static final String SESSION_CREATED_METRIC = "session_created";
    private static final String JWT_VERIFICATION_FAILED = "jwt_verification_failed";
    private static final UUID SESSION_ID = UUID.randomUUID();

    @Mock private SessionService mockSessionService;
    @Mock private SessionRequestService mockSessionRequestService;
    @Mock private PersonIdentityService mockPersonIdentityService;
    @Mock private APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent;
    @Mock private SessionRequest mockSessionRequest;
    @Mock private EventProbe mockEventProbe;
    @Mock private AuditService mockAuditService;
    @InjectMocks private SessionHandler sessionHandler;

    @ParameterizedTest
    @CsvSource({"X-Forwarded-For", "X-forwarded-fOR"})
    void shouldCreateAndSaveSession(String xForwardedForHeaderName)
            throws SessionValidationException, ClientConfigurationException,
                    JsonProcessingException, SqsException {
        String clientIpAddress = "192.0.2.0";
        String redirectUri = "https://www.example.com/callback";
        SharedClaims sharedClaims = new SharedClaims();
        Map<String, String> requestHeaders =
                Map.of("header-name", "headerValue", xForwardedForHeaderName, clientIpAddress);
        String subject = "subject";
        String persistentSessionId = "persistent_session_id_value";
        String clientSessionId = "govuk_signin_journey_id_value";
        ArgumentCaptor<AuditEventContext> auditEventContextArgumentCaptor =
                ArgumentCaptor.forClass(AuditEventContext.class);

        when(mockEventProbe.addJourneyIdToLoggingContext(clientSessionId))
                .thenReturn(mockEventProbe);
        when(mockEventProbe.counterMetric(anyString())).thenReturn(mockEventProbe);
        when(mockSessionRequest.getClientId()).thenReturn("ipv-core");
        when(mockSessionRequest.getState()).thenReturn("some state");
        when(mockSessionRequest.getRedirectUri()).thenReturn(URI.create(redirectUri));
        when(mockSessionRequest.hasSharedClaims()).thenReturn(Boolean.TRUE);
        when(mockSessionRequest.getSharedClaims()).thenReturn(sharedClaims);
        when(mockSessionRequest.getSubject()).thenReturn(subject);
        when(mockSessionRequest.getPersistentSessionId()).thenReturn(persistentSessionId);
        when(mockSessionRequest.getClientSessionId()).thenReturn(clientSessionId);
        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
        when(apiGatewayProxyRequestEvent.getHeaders()).thenReturn(requestHeaders);
        when(mockSessionRequestService.validateSessionRequest("some json"))
                .thenReturn(mockSessionRequest);
        when(mockSessionService.saveSession(mockSessionRequest)).thenReturn(SESSION_ID);

        APIGatewayProxyResponseEvent responseEvent =
                sessionHandler.handleRequest(apiGatewayProxyRequestEvent, null);

        verify(mockSessionService).saveSession(mockSessionRequest);
        verify(apiGatewayProxyRequestEvent, times(2)).getHeaders();
        verify(mockSessionRequest).setClientIpAddress(clientIpAddress);
        verify(mockPersonIdentityService).savePersonIdentity(SESSION_ID, sharedClaims);
        verify(mockEventProbe).addJourneyIdToLoggingContext(clientSessionId);
        verify(mockEventProbe).log(Level.INFO, "created session");
        verify(mockEventProbe).addDimensions(Map.of("issuer", "ipv-core"));
        verify(mockEventProbe).counterMetric(SESSION_CREATED_METRIC);
        verify(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventType.START),
                        auditEventContextArgumentCaptor.capture(),
                        eq(null));
        assertEquals(HttpStatusCode.CREATED, responseEvent.getStatusCode());
        var responseBody = new ObjectMapper().readValue(responseEvent.getBody(), Map.class);
        assertEquals(SESSION_ID.toString(), responseBody.get(SessionHandler.SESSION_ID));
        assertEquals("some state", responseBody.get(STATE));
        assertEquals(redirectUri, responseBody.get(REDIRECT_URI));

        AuditEventContext auditEventContext = auditEventContextArgumentCaptor.getValue();
        assertEquals(subject, auditEventContext.getSessionItem().getSubject());
        assertEquals(SESSION_ID, auditEventContext.getSessionItem().getSessionId());
        assertEquals(
                persistentSessionId, auditEventContext.getSessionItem().getPersistentSessionId());
        assertEquals(clientSessionId, auditEventContext.getSessionItem().getClientSessionId());
        assertEquals(requestHeaders, auditEventContext.getRequestHeaders());
    }

    @ParameterizedTest
    @CsvSource({"X-Forwarded-For", "X-forwarded-fOR"})
    void shouldCreateAndSaveSessionWithContext(String xForwardedForHeaderName)
            throws SessionValidationException, ClientConfigurationException,
                    JsonProcessingException, SqsException {
        String clientIpAddress = "192.0.2.0";
        String redirectUri = "https://www.example.com/callback";
        SharedClaims sharedClaims = new SharedClaims();
        Map<String, String> requestHeaders =
                Map.of("header-name", "headerValue", xForwardedForHeaderName, clientIpAddress);
        String subject = "subject";
        String persistentSessionId = "persistent_session_id_value";
        String clientSessionId = "govuk_signin_journey_id_value";
        String context = "check_details";
        ArgumentCaptor<AuditEventContext> auditEventContextArgumentCaptor =
                ArgumentCaptor.forClass(AuditEventContext.class);

        ArgumentCaptor<AuditEventExtensions> auditEventExtensionsArgumentCaptor =
                ArgumentCaptor.forClass(AuditEventExtensions.class);

        when(mockEventProbe.addJourneyIdToLoggingContext(clientSessionId))
                .thenReturn(mockEventProbe);
        when(mockEventProbe.counterMetric(anyString())).thenReturn(mockEventProbe);
        when(mockSessionRequest.getClientId()).thenReturn("ipv-core");
        when(mockSessionRequest.getState()).thenReturn("some state");
        when(mockSessionRequest.getRedirectUri()).thenReturn(URI.create(redirectUri));
        when(mockSessionRequest.hasSharedClaims()).thenReturn(Boolean.TRUE);
        when(mockSessionRequest.getSharedClaims()).thenReturn(sharedClaims);
        when(mockSessionRequest.getSubject()).thenReturn(subject);
        when(mockSessionRequest.getPersistentSessionId()).thenReturn(persistentSessionId);
        when(mockSessionRequest.getClientSessionId()).thenReturn(clientSessionId);
        when(mockSessionRequest.getContext()).thenReturn(context);
        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
        when(apiGatewayProxyRequestEvent.getHeaders()).thenReturn(requestHeaders);
        when(mockSessionRequestService.validateSessionRequest("some json"))
                .thenReturn(mockSessionRequest);
        when(mockSessionService.saveSession(mockSessionRequest)).thenReturn(SESSION_ID);

        APIGatewayProxyResponseEvent responseEvent =
                sessionHandler.handleRequest(apiGatewayProxyRequestEvent, null);

        verify(mockSessionService).saveSession(mockSessionRequest);
        verify(apiGatewayProxyRequestEvent, times(2)).getHeaders();
        verify(mockSessionRequest).setClientIpAddress(clientIpAddress);
        verify(mockPersonIdentityService).savePersonIdentity(SESSION_ID, sharedClaims);
        verify(mockEventProbe).addJourneyIdToLoggingContext(clientSessionId);
        verify(mockEventProbe).log(Level.INFO, "created session");
        verify(mockEventProbe).addDimensions(Map.of("issuer", "ipv-core"));
        verify(mockEventProbe).counterMetric(SESSION_CREATED_METRIC);
        verify(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventType.START),
                        auditEventContextArgumentCaptor.capture(),
                        auditEventExtensionsArgumentCaptor.capture());
        assertEquals(HttpStatusCode.CREATED, responseEvent.getStatusCode());
        var responseBody = new ObjectMapper().readValue(responseEvent.getBody(), Map.class);
        assertEquals(SESSION_ID.toString(), responseBody.get(SessionHandler.SESSION_ID));
        assertEquals("some state", responseBody.get(STATE));
        assertEquals(redirectUri, responseBody.get(REDIRECT_URI));

        AuditEventContext auditEventContext = auditEventContextArgumentCaptor.getValue();
        assertEquals(subject, auditEventContext.getSessionItem().getSubject());
        assertEquals(SESSION_ID, auditEventContext.getSessionItem().getSessionId());
        assertEquals(
                persistentSessionId, auditEventContext.getSessionItem().getPersistentSessionId());
        assertEquals(clientSessionId, auditEventContext.getSessionItem().getClientSessionId());
        assertEquals(requestHeaders, auditEventContext.getRequestHeaders());

        AuditEventExtensions auditEventExtensions = auditEventExtensionsArgumentCaptor.getValue();
        List<Evidence> evidenceList = auditEventExtensions.getEvidence();
        assertEquals(1, evidenceList.size());
        assertEquals(context, evidenceList.get(0).getContext());
    }

    @Test
    void shouldCatchValidationExceptionAndReturn400Response()
            throws SessionValidationException, ClientConfigurationException,
                    JsonProcessingException, SqsException {

        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
        SessionValidationException sessionValidationException = new SessionValidationException("");
        when(mockSessionRequestService.validateSessionRequest("some json"))
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

        verify(mockEventProbe).counterMetric(SESSION_CREATED_METRIC, 0d);
        verify(mockEventProbe).counterMetric(JWT_VERIFICATION_FAILED);

        verify(mockEventProbe).log(Level.ERROR, sessionValidationException);
        verify(mockAuditService, never()).sendAuditEvent(any(AuditEventType.class));
        verify(mockSessionService, never()).saveSession(mockSessionRequest);
    }

    @Test
    void shouldCatchClientConfigurationExceptionAndReturn500Response()
            throws SessionValidationException, ClientConfigurationException,
                    JsonProcessingException, SqsException {
        ClientConfigurationException exception =
                new ClientConfigurationException(new NullPointerException());
        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
        when(mockSessionRequestService.validateSessionRequest("some json")).thenThrow(exception);
        setupEventProbeErrorBehaviour();

        APIGatewayProxyResponseEvent responseEvent =
                sessionHandler.handleRequest(apiGatewayProxyRequestEvent, null);
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, responseEvent.getStatusCode());
        Map<String, Object> responseBody =
                new ObjectMapper().readValue(responseEvent.getBody(), new TypeReference<>() {});
        assertEquals(ErrorResponse.SERVER_CONFIG_ERROR.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.SERVER_CONFIG_ERROR.getMessage(), responseBody.get("message"));

        verify(mockEventProbe).counterMetric(SESSION_CREATED_METRIC, 0d);
        verify(mockEventProbe).counterMetric(JWT_VERIFICATION_FAILED);
        verify(mockEventProbe).log(Level.ERROR, exception);
        verify(mockAuditService, never()).sendAuditEvent(any(AuditEventType.class));
        verify(mockSessionService, never()).saveSession(mockSessionRequest);
    }

    @ParameterizedTest
    @CsvSource({"X-Forwarded-For", "X-forwarded-fOR"})
    void shouldCatchSqsExceptionAndReturn500Response(String xForwardedForHeaderName)
            throws SessionValidationException, ClientConfigurationException,
                    JsonProcessingException, SqsException {
        SqsException exception =
                new SqsException(new NullPointerException());

        String clientIpAddress = "192.0.2.0";
        String redirectUri = "https://www.example.com/callback";
        SharedClaims sharedClaims = new SharedClaims();
        Map<String, String> requestHeaders =
                Map.of("header-name", "headerValue", xForwardedForHeaderName, clientIpAddress);
        String subject = "subject";
        String persistentSessionId = "persistent_session_id_value";
        String clientSessionId = "govuk_signin_journey_id_value";

        when(mockEventProbe.addJourneyIdToLoggingContext(clientSessionId))
                .thenReturn(mockEventProbe);
        when(mockEventProbe.log(eq(Level.INFO), anyString())).thenReturn(mockEventProbe);
        when(mockEventProbe.log(eq(Level.ERROR), any(Exception.class))).thenReturn(mockEventProbe);
        when(mockEventProbe.counterMetric(SESSION_CREATED_METRIC)).thenReturn(mockEventProbe);
        when(mockSessionRequest.getClientId()).thenReturn("ipv-core");
        when(mockSessionRequest.hasSharedClaims()).thenReturn(Boolean.TRUE);
        when(mockSessionRequest.getSharedClaims()).thenReturn(sharedClaims);
        when(mockSessionRequest.getSubject()).thenReturn(subject);
        when(mockSessionRequest.getPersistentSessionId()).thenReturn(persistentSessionId);
        when(mockSessionRequest.getClientSessionId()).thenReturn(clientSessionId);
        when(apiGatewayProxyRequestEvent.getBody()).thenReturn("some json");
        when(apiGatewayProxyRequestEvent.getHeaders()).thenReturn(requestHeaders);
        when(mockSessionRequestService.validateSessionRequest("some json"))
                .thenReturn(mockSessionRequest);
        when(mockSessionService.saveSession(mockSessionRequest)).thenReturn(SESSION_ID);
        doThrow(exception).when(mockAuditService).sendAuditEvent(eq(AuditEventType.START), any(AuditEventContext.class), isNull());

        APIGatewayProxyResponseEvent responseEvent =
                sessionHandler.handleRequest(apiGatewayProxyRequestEvent, null);
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, responseEvent.getStatusCode());
        Map<String, Object> responseBody =
                new ObjectMapper().readValue(responseEvent.getBody(), new TypeReference<>() {});
        assertEquals(ErrorResponse.SERVER_CONFIG_ERROR.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.SERVER_CONFIG_ERROR.getMessage(), responseBody.get("message"));

        verify(mockEventProbe, never()).counterMetric(SESSION_CREATED_METRIC, 0d);
        verify(mockEventProbe, never()).counterMetric(JWT_VERIFICATION_FAILED);
        verify(mockEventProbe).log(Level.ERROR, exception);
    }

    private void setupEventProbeErrorBehaviour() {
        when(mockEventProbe.counterMetric(SESSION_CREATED_METRIC, 0d)).thenReturn(mockEventProbe);
        when(mockEventProbe.log(eq(Level.ERROR), any(Exception.class))).thenReturn(mockEventProbe);
    }
}
