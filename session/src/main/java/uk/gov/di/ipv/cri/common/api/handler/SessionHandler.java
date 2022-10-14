package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.api.domain.JarResponse;
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
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.text.ParseException;
import java.time.Clock;
import java.util.Map;
import java.util.UUID;

import static org.apache.logging.log4j.Level.ERROR;
import static software.amazon.awssdk.http.HttpStatusCode.BAD_REQUEST;

public class SessionHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    protected static final String SESSION_ID = "session_id";
    protected static final String STATE = "state";
    protected static final String REDIRECT_URI = "redirect_uri";
    private static final String EVENT_SESSION_CREATED = "session_created";
    private static final String HEADER_IP_ADDRESS = "x-forwarded-for";
    private static final String SHARED_CLAIMS = "shared_claims";

    private final SessionService sessionService;
    private final SessionRequestService sesssionRequestService;
    private final PersonIdentityService personIdentityService;
    private final EventProbe eventProbe;
    private final AuditService auditService;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public SessionHandler() {
        this.configurationService = new ConfigurationService();
        this.sessionService = new SessionService();
        this.sesssionRequestService = new SessionRequestService();
        this.personIdentityService = new PersonIdentityService();
        this.eventProbe = new EventProbe();
        this.auditService =
                new AuditService(
                        SqsClient.builder()
                                .credentialsProvider(
                                        EnvironmentVariableCredentialsProvider.create())
                                .region(Region.of(System.getenv("AWS_REGION")))
                                .build(),
                        configurationService,
                        new ObjectMapper(),
                        new AuditEventFactory(configurationService, Clock.systemUTC()));
    }

    public SessionHandler(
            SessionService sessionService,
            SessionRequestService sessionRequestService,
            PersonIdentityService personIdentityService,
            EventProbe eventProbe,
            AuditService auditService,
            ConfigurationService configurationService) {
        this.sessionService = sessionService;
        this.sesssionRequestService = sessionRequestService;
        this.personIdentityService = personIdentityService;
        this.eventProbe = eventProbe;
        this.auditService = auditService;
        this.configurationService = configurationService;
    }

    @Override
    @Logging(correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            SessionRequest sessionRequest =
                    sesssionRequestService.validateSessionRequest(input.getBody());

            var sessionHeaderIpAddress = input.getHeaders().get(HEADER_IP_ADDRESS);
            sessionRequest.setClientIpAddress(sessionHeaderIpAddress);
            eventProbe.addDimensions(Map.of("issuer", sessionRequest.getClientId()));

            String clientId = sessionRequest.getClientId();
            LogHelper.attachClientIdToLogs(clientId);

            UUID sessionId = sessionService.saveSession(sessionRequest);

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

            // Must ensure issuer param is set for passport
            auditService.sendAuditEvent(
                    AuditEventType.START,
                    new AuditEventContext(input.getHeaders(), auditSessionItem));

            if (configurationService.getVerifiableCredentialIssuer().contains("review-p")) {
                JarResponse jarResponse =
                        generateJarResponse(
                                sessionRequest.getSignedJWT().getJWTClaimsSet(), sessionId);
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatusCode.CREATED, jarResponse);
            }

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.CREATED,
                    Map.of(
                            SESSION_ID, sessionId.toString(),
                            STATE, sessionRequest.getState(),
                            REDIRECT_URI, sessionRequest.getRedirectUri().toString()));

        } catch (SessionValidationException e) {

            eventProbe.log(ERROR, e).counterMetric(EVENT_SESSION_CREATED, 0d);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, ErrorResponse.SESSION_VALIDATION_ERROR);
        } catch (ClientConfigurationException | SqsException e) {

            eventProbe.log(ERROR, e).counterMetric(EVENT_SESSION_CREATED, 0d);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, ErrorResponse.SERVER_CONFIG_ERROR);
        } catch (ParseException e) {
            eventProbe.log(ERROR, e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_SHARED_ATTRIBUTES_JWT);
        }
    }

    private JarResponse generateJarResponse(JWTClaimsSet claimsSet, UUID sessionId)
            throws ParseException {
        return new JarResponse(claimsSet.getJSONObjectClaim(SHARED_CLAIMS), sessionId.toString());
    }
}
