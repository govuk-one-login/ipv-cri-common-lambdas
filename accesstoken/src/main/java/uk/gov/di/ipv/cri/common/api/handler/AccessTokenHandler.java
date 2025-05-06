package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import org.apache.logging.log4j.Level;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.AccessTokenValidationException;
import uk.gov.di.ipv.cri.common.library.exception.AuthorizationCodeExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionNotFoundException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.ClientProviderFactory;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

public class AccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private EventProbe eventProbe;
    private AccessTokenService accessTokenService;
    private SessionService sessionService;
    static final String METRIC_NAME_ACCESS_TOKEN = "accesstoken";
    private static final String JWT_VERIFICATION_FAILED = "jwt_verification_failed";

    public AccessTokenHandler(
            AccessTokenService accessTokenService,
            SessionService sessionService,
            EventProbe eventProbe) {
        this.accessTokenService = accessTokenService;
        this.sessionService = sessionService;
        this.eventProbe = eventProbe;
    }

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenHandler() {
        ClientProviderFactory clientProviderFactory = new ClientProviderFactory(true, true);
        ConfigurationService configurationService =
                new ConfigurationService(
                        clientProviderFactory.getSSMProvider(),
                        clientProviderFactory.getSecretsProvider());
        this.accessTokenService = new AccessTokenService(configurationService);
        this.sessionService =
                new SessionService(
                        configurationService, clientProviderFactory.getDynamoDbEnhancedClient());
        this.eventProbe = new EventProbe();
    }

    @Override
    @Logging(correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST, clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            TokenRequest tokenRequest = accessTokenService.createTokenRequest(input.getBody());
            String authCode = accessTokenService.getAuthorizationCode(tokenRequest);
            SessionItem sessionItem = sessionService.getSessionByAuthorisationCode(authCode);
            eventProbe
                    .addJourneyIdToLoggingContext(sessionItem.getClientSessionId())
                    .log(Level.INFO, "found session");
            accessTokenService.validateTokenRequest(tokenRequest, sessionItem);
            AccessTokenResponse accessTokenResponse = accessTokenService.createToken(tokenRequest);
            accessTokenService.updateSessionAccessToken(sessionItem, accessTokenResponse);
            sessionService.updateSession(sessionItem);

            eventProbe.counterMetric(METRIC_NAME_ACCESS_TOKEN);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.OK, accessTokenResponse.toJSONObject());
        } catch (AccessTokenValidationException e) {
            eventProbe.log(Level.ERROR, e).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
            eventProbe.counterMetric(JWT_VERIFICATION_FAILED);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.TOKEN_VALIDATION_ERROR);
        } catch (SessionExpiredException e) {
            eventProbe.log(Level.ERROR, e).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN, ErrorResponse.SESSION_EXPIRED);
        } catch (AuthorizationCodeExpiredException e) {
            eventProbe.log(Level.ERROR, e).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN, ErrorResponse.AUTHORIZATION_CODE_EXPIRED);
        } catch (SessionNotFoundException e) {
            eventProbe.log(Level.ERROR, e).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN, ErrorResponse.ACCESS_TOKEN_EXPIRED);
        }
    }
}
