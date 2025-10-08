package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.Level;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.api.domain.AuditEventExtensions;
import uk.gov.di.ipv.cri.common.api.domain.Evidence;
import uk.gov.di.ipv.cri.common.api.service.SessionRequestService;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.ClientConfigurationException;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AuditEventFactory;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.ClientProviderFactory;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import static org.apache.logging.log4j.Level.ERROR;

public class SessionHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    protected static final String SESSION_ID = "session_id";
    protected static final String STATE = "state";
    protected static final String REDIRECT_URI = "redirect_uri";
    private static final String EVENT_SESSION_CREATED = "session_created";
    private static final String JWT_VERIFICATION_FAILED = "jwt_verification_failed";
    private static final String HEADER_IP_ADDRESS = "x-forwarded-for";
    private final SessionService sessionService;
    private final SessionRequestService sessionRequestService;
    private final PersonIdentityService personIdentityService;
    private final EventProbe eventProbe;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public SessionHandler() {
        ClientProviderFactory clientProviderFactory = new ClientProviderFactory(true, true);
        ConfigurationService configurationService =
                new ConfigurationService(
                        clientProviderFactory.getSSMProvider(),
                        clientProviderFactory.getSecretsProvider());
        ObjectMapper sharedObjectMapper = new ObjectMapper();
        this.sessionService =
                new SessionService(
                        configurationService, clientProviderFactory.getDynamoDbEnhancedClient());
        this.eventProbe = new EventProbe();
        this.sessionRequestService =
                new SessionRequestService(
                        configurationService,
                        clientProviderFactory.getKMSClient(),
                        sharedObjectMapper,
                        eventProbe);
        this.personIdentityService =
                new PersonIdentityService(
                        configurationService, clientProviderFactory.getDynamoDbEnhancedClient());
        this.auditService =
                new AuditService(
                        clientProviderFactory.getSqsClient(),
                        configurationService,
                        sharedObjectMapper,
                        new AuditEventFactory(configurationService, Clock.systemUTC()));
    }

    public SessionHandler(
            SessionService sessionService,
            SessionRequestService sessionRequestService,
            PersonIdentityService personIdentityService,
            EventProbe eventProbe,
            AuditService auditService) {
        this.sessionService = sessionService;
        this.sessionRequestService = sessionRequestService;
        this.personIdentityService = personIdentityService;
        this.eventProbe = eventProbe;
        this.auditService = auditService;
    }

    @Override
    @Logging(correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST, clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        System.out.println("4");
        try {
            SessionRequest sessionRequest =
                    sessionRequestService.validateSessionRequest(input.getBody());
            Map<String, String> inputHeadersCaseInsensitiveMap =
                    new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            inputHeadersCaseInsensitiveMap.putAll(input.getHeaders());
            var sessionHeaderIpAddress = inputHeadersCaseInsensitiveMap.get(HEADER_IP_ADDRESS);
            sessionRequest.setClientIpAddress(sessionHeaderIpAddress);
            eventProbe.addDimensions(Map.of("issuer", sessionRequest.getClientId()));

            UUID sessionId = sessionService.saveSession(sessionRequest);
            eventProbe
                    .addJourneyIdToLoggingContext(sessionRequest.getClientSessionId())
                    .log(Level.INFO, "created session");
            if (sessionRequest.hasSharedClaims()) {
                personIdentityService.savePersonIdentity(
                        sessionId, sessionRequest.getSharedClaims());
            }

            eventProbe.counterMetric(EVENT_SESSION_CREATED).auditEvent(sessionRequest);

            SessionItem auditSessionItem = new SessionItem();
            auditSessionItem.setSessionId(sessionId);
            auditSessionItem.setSubject(sessionRequest.getSubject());
            auditSessionItem.setPersistentSessionId(sessionRequest.getPersistentSessionId());
            auditSessionItem.setClientSessionId(sessionRequest.getClientSessionId());
            sendStartAuditEvent(input.getHeaders(), auditSessionItem, sessionRequest.getContext());

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.CREATED,
                    Map.of(
                            SESSION_ID, sessionId.toString(),
                            STATE, sessionRequest.getState(),
                            REDIRECT_URI, sessionRequest.getRedirectUri().toString()));

        } catch (SessionValidationException e) {

            eventProbe.log(ERROR, e).counterMetric(EVENT_SESSION_CREATED, 0d);
            eventProbe.counterMetric(JWT_VERIFICATION_FAILED);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.SESSION_VALIDATION_ERROR);
        } catch (ClientConfigurationException | SqsException e) {
            eventProbe.log(ERROR, e);

            if (e instanceof ClientConfigurationException) {
                eventProbe.counterMetric(EVENT_SESSION_CREATED, 0d);
                eventProbe.counterMetric(JWT_VERIFICATION_FAILED);
            }

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, ErrorResponse.SERVER_CONFIG_ERROR);
        }
    }

    private void sendStartAuditEvent(
            Map<String, String> headers, SessionItem auditSessionItem, String sessionContext)
            throws SqsException {
        List<Evidence> evidenceList = new ArrayList<>();
        if (!StringUtils.isBlank(sessionContext)) {
            Evidence evidence = new Evidence();
            evidence.setContext(sessionContext);
            evidenceList.add(evidence);
        }
        auditService.sendAuditEvent(
                AuditEventType.START,
                new AuditEventContext(headers, auditSessionItem),
                evidenceList.isEmpty() ? null : new AuditEventExtensions(evidenceList));
    }
}
