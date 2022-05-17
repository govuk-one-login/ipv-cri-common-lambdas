package uk.gov.di.ipv.cri.address.api.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.address.api.service.SessionRequestService;
import uk.gov.di.ipv.cri.address.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.address.library.domain.AuditEventTypes;
import uk.gov.di.ipv.cri.address.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.address.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.address.library.exception.ClientConfigurationException;
import uk.gov.di.ipv.cri.address.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.address.library.exception.SqsException;
import uk.gov.di.ipv.cri.address.library.service.AuditService;
import uk.gov.di.ipv.cri.address.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.address.library.service.SessionService;
import uk.gov.di.ipv.cri.address.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.address.library.util.EventProbe;

import java.util.Map;
import java.util.UUID;

import static org.apache.logging.log4j.Level.ERROR;

public class SessionHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    protected static final String SESSION_ID = "session_id";
    protected static final String STATE = "state";
    protected static final String REDIRECT_URI = "redirect_uri";
    public static final String EVENT_SESSION_CREATED = "session_created";
    private final SessionService sessionService;
    private final SessionRequestService sesssionRequestService;
    private final EventProbe eventProbe;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public SessionHandler() {
        this(
                new SessionService(),
                new SessionRequestService(),
                new EventProbe(),
                new AuditService(SqsClient.builder().build(), new ConfigurationService()));
    }

    public SessionHandler(
            SessionService sessionService,
            SessionRequestService sessionRequestService,
            EventProbe eventProbe,
            AuditService auditService) {
        this.sessionService = sessionService;
        this.sesssionRequestService = sessionRequestService;
        this.eventProbe = eventProbe;
        this.auditService = auditService;
    }

    @Override
    @Logging(correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            SessionRequest sessionRequest =
                    sesssionRequestService.validateSessionRequest(input.getBody());

            eventProbe.addDimensions(Map.of("issuer", sessionRequest.getClientId()));

            UUID sessionId = sessionService.createAndSaveAddressSession(sessionRequest);

            eventProbe.counterMetric(EVENT_SESSION_CREATED).auditEvent(sessionRequest);

            auditService.sendAuditEvent(
                    AuditEventTypes.SESSION_CREATED, sessionId, sessionRequest.getClientId());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_CREATED,
                    Map.of(
                            SESSION_ID, sessionId.toString(),
                            STATE, sessionRequest.getState(),
                            REDIRECT_URI, sessionRequest.getRedirectUri().toString()));

        } catch (SessionValidationException e) {

            eventProbe.log(ERROR, e).counterMetric(EVENT_SESSION_CREATED, 0d);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.SESSION_VALIDATION_ERROR);
        } catch (ClientConfigurationException | SqsException e) {

            eventProbe.log(ERROR, e).counterMetric(EVENT_SESSION_CREATED, 0d);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.SERVER_CONFIG_ERROR);
        }
    }
}
