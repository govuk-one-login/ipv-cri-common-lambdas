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
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.api.service.AuthorizationValidatorService;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.error.OauthErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.SessionValidationException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.ClientProviderFactory;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.apache.logging.log4j.Level.ERROR;
import static org.apache.logging.log4j.Level.INFO;

public class AuthorizationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String HEADER_SESSION_ID = "session-id";
    public static final String EVENT_AUTHORIZATION_SENT = "authorization_sent";
    public static final String EVENT_NO_AUTHORIZATION_CODE = "no_authorization_code";
    private SessionService sessionService;
    private EventProbe eventProbe;
    private AuthorizationValidatorService authorizationValidatorService;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationHandler() {
        ClientProviderFactory clientProviderFactory = new ClientProviderFactory();
        ConfigurationService configurationService =
                new ConfigurationService(
                        clientProviderFactory.getSSMProvider(),
                        clientProviderFactory.getSecretsProvider());
        this.sessionService =
                new SessionService(
                        configurationService, clientProviderFactory.getDynamoDbEnhancedClient());
        this.eventProbe = new EventProbe();
        this.authorizationValidatorService =
                new AuthorizationValidatorService(configurationService);
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
            eventProbe
                    .addJourneyIdToLoggingContext(sessionItem.getClientSessionId())
                    .log(INFO, "found session");
            // validate
            authorizationValidatorService.validate(authenticationRequest, sessionItem);

            // Return access denied if there is no authcode found
            if (StringUtils.isBlank(sessionItem.getAuthorizationCode())) {

                eventProbe
                        .log(INFO, "No Auth Code retrieved returning Oauth access_denied")
                        .counterMetric(EVENT_NO_AUTHORIZATION_CODE);

                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatusCode.FORBIDDEN, OauthErrorResponse.ACCESS_DENIED_ERROR);
            }

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
        } catch (Exception e) {
            eventProbe.log(ERROR, e).counterMetric(EVENT_AUTHORIZATION_SENT, 0d);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, OauthErrorResponse.ACCESS_DENIED_ERROR);
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
