package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.api.service.AuthorizationValidatorService;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.apache.logging.log4j.Level.ERROR;

public class AuthorizationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String HEADER_SESSION_ID = "session-id";
    public static final String EVENT_AUTHORIZATION_SENT = "authorization_sent";
    private final SessionService sessionService;
    private final EventProbe eventProbe;
    private final AuthorizationValidatorService authorizationValidatorService;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationHandler() {
        this(new SessionService(), new EventProbe(), new AuthorizationValidatorService());
    }

    public AuthorizationHandler(
            SessionService sessionService,
            EventProbe eventProbe,
            AuthorizationValidatorService authorizationValidatorService) {
        this.sessionService = sessionService;
        this.eventProbe = eventProbe;
        this.authorizationValidatorService = authorizationValidatorService;
    }

    @Override
    @Logging(correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST, clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            // populate all details from incoming request
            Map<String, List<String>> queryStringParameters = getQueryStringParametersAsMap(input);
            AuthenticationRequest authenticationRequest =
                    AuthenticationRequest.parse(queryStringParameters);
            String sessionId = input.getHeaders().get(HEADER_SESSION_ID);
            SessionItem sessionItem = sessionService.getSession(sessionId);
            eventProbe.log(Level.INFO, "found session");

            // validate
            authorizationValidatorService.validate(authenticationRequest, sessionItem);

            // create authorization
            AuthorizationSuccessResponse authorizationSuccessResponse =
                    new AuthorizationSuccessResponse(
                            authenticationRequest.getRedirectionURI(),
                            new AuthorizationCode(sessionItem.getAuthorizationCode()),
                            null,
                            authenticationRequest.getState(),
                            null);

            eventProbe
                    .counterMetric(EVENT_AUTHORIZATION_SENT)
                    .auditEvent(authorizationSuccessResponse);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.OK, authorizationSuccessResponse);

        } catch (ParseException e) {
            eventProbe.log(ERROR, e).counterMetric(EVENT_AUTHORIZATION_SENT, 0d);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, ErrorResponse.SERVER_CONFIG_ERROR);
        } catch (SessionValidationException e) {
            eventProbe.log(ERROR, e).counterMetric(EVENT_AUTHORIZATION_SENT, 0d);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.SESSION_VALIDATION_ERROR);
        }
    }

    private Map<String, List<String>> getQueryStringParametersAsMap(
            APIGatewayProxyRequestEvent input) {
        if (input.getQueryStringParameters() != null) {
            return input.getQueryStringParameters().entrySet().stream()
                    .collect(
                            Collectors.toMap(
                                    Map.Entry::getKey, entry -> List.of(entry.getValue())));
        }
        return Collections.emptyMap();
    }
}
