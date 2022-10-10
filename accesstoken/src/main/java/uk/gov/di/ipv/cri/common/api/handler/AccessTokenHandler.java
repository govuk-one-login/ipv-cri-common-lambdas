package uk.gov.di.ipv.cri.common.api.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenRequest;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import uk.gov.di.ipv.cri.common.library.helper.LogHelper;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.util.Objects;

public class AccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final EventProbe eventProbe;
    private final AccessTokenService accessTokenService;
    private final SessionService sessionService;
    static final String METRIC_NAME_ACCESS_TOKEN = "accesstoken";

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
        this(new AccessTokenService(), new SessionService(), new EventProbe());
    }

    @Override
    @Logging(correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            TokenRequest tokenRequest = accessTokenService.createTokenRequest(input.getBody());

            String authCode = accessTokenService.getAuthorizationCode(tokenRequest);

            if (authCode == null) {
                LOGGER.error(
                        "Access Token could not be issued. The supplied authorization code was not found");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.INVALID_GRANT.getHTTPStatusCode(),
                        OAuth2Error.INVALID_GRANT.toJSONObject());
            }

            SessionItem sessionItem = sessionService.getSessionByAuthorisationCode(authCode);
            LogHelper.attachPassportSessionIdToLogs(sessionItem.getSessionId().toString());
            LogHelper.attachGovukSigninJourneyIdToLogs(sessionItem.getClientSessionId());
            accessTokenService.validateTokenRequest(tokenRequest, sessionItem);

            if (sessionItem.getAccessToken() != null) {
                LOGGER.error(
                        "Auth code has been used multiple times. Auth code was exchanged for an access token at: {}",
                        sessionItem.getAccessTokenExchangedDateTime());

                ErrorObject error = revokeAccessToken(sessionItem);
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            if (redirectUrlsDoNotMatch(
                    sessionItem, (AuthorizationCodeGrant) tokenRequest.getAuthorizationGrant())) {
                LOGGER.error(
                        "Redirect URL in token request does not match that received in auth code request. Session ID: {}",
                        sessionItem.getSessionId());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.INVALID_GRANT.getHTTPStatusCode(),
                        OAuth2Error.INVALID_GRANT.toJSONObject());
            }

            AccessTokenResponse accessTokenResponse = accessTokenService.createToken(tokenRequest);
            accessTokenService.updateSessionAccessToken(sessionItem, accessTokenResponse);
            sessionService.updateSession(sessionItem);

            eventProbe.counterMetric(METRIC_NAME_ACCESS_TOKEN);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.OK, accessTokenResponse.toJSONObject());
        } catch (AccessTokenValidationException e) {
            eventProbe.log(Level.ERROR, e).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
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
        } catch (Exception e) {
            eventProbe.log(Level.ERROR, e).counterMetric(METRIC_NAME_ACCESS_TOKEN, 0d);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN, ErrorResponse.SESSION_VALIDATION_ERROR);
        }
    }

    private ErrorObject revokeAccessToken(SessionItem sessionItem) {
        try {
            sessionService.revokeAccessToken(sessionItem);
            return OAuth2Error.INVALID_GRANT.setDescription(
                    "Authorization code used too many times");
        } catch (IllegalArgumentException e) {
            LOGGER.error("Failed to revoke access token because: {}", e.getMessage());
            return OAuth2Error.INVALID_GRANT.setDescription("Failed to revoke access token");
        }
    }

    private boolean redirectUrlsDoNotMatch(
            SessionItem sessionItem, AuthorizationCodeGrant authorizationGrant) {

        if (Objects.isNull(sessionItem.getRedirectUri())
                && Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return false;
        }

        if (Objects.isNull(sessionItem.getRedirectUri())
                || Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return true;
        }

        return !authorizationGrant
                .getRedirectionURI()
                .toString()
                .equals(sessionItem.getRedirectUri().toString());
    }
}
