import middy from "@middy/core";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/lib/middleware/middy";

import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { AuthorizationLambda } from "../../../src/handlers/authorization-handler";
import { ConfigService } from "../../../src/common/config/config-service";
import { SessionService } from "../../../src/services/session-service";
import { AuthorizationRequestValidator } from "../../../src/services/auth-request-validator";
import { SessionItem } from "../../../src/types/session-item";
import {
    APIGatewayProxyEvent,
    APIGatewayProxyEventHeaders,
    APIGatewayProxyEventQueryStringParameters,
} from "aws-lambda/trigger/api-gateway-proxy";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import {
    InvalidRequestError,
    ServerError,
    SessionNotFoundError,
    SessionValidationError,
    AccessDeniedError,
} from "../../../src/common/utils/errors";
import getSessionByIdMiddleware from "../../../src/middlewares/session/get-session-by-id-middleware";
import { ClientConfigKey, CommonConfigKey } from "../../../src/types/config-keys";
import initialiseConfigMiddleware from "../../../src/middlewares/config/initialise-config-middleware";
import errorMiddleware from "../../../src/middlewares/error/error-middleware";
import { Context } from "aws-lambda";
import setGovUkSigningJourneyIdMiddleware from "../../../src/middlewares/session/set-gov-uk-signing-journey-id-middleware";
import initialiseClientConfigMiddleware from "../../../src/middlewares/config/initialise-client-config-middleware";
import setRequestedVerificationScoreMiddleware from "../../../src/middlewares/session/set-requested-verification-score-middleware";
import { SSMProvider } from "@aws-lambda-powertools/parameters/ssm";

jest.mock("../../../src/common/config/config-service");
jest.mock("@aws-lambda-powertools/metrics");
jest.mock("@aws-lambda-powertools/logger");
jest.mock("@aws-sdk/lib-dynamodb", () => {
    return {
        __esModule: true,
        ...jest.requireActual("@aws-sdk/lib-dynamodb"),
        GetCommand: jest.fn(),
        UpdateCommand: jest.fn(),
        send: jest.fn(),
    };
});
const AUTHORIZATION_SENT_METRIC = "authorization_sent";

describe("authorization-handler.ts", () => {
    const mockDynamoDbClient = jest.mocked(DynamoDBDocument);

    beforeEach(() => {
        jest.resetAllMocks();
        const impl = () => jest.fn().mockImplementation(() => Promise.resolve({ Parameters: [] }));
        mockDynamoDbClient.prototype.send = impl();
        mockDynamoDbClient.prototype.query = impl();
    });

    describe("Handler", () => {
        let body = {};
        let headers = {};
        let authorizationHandlerLambda: AuthorizationLambda;
        let lambdaHandler: middy.MiddyfiedHandler;
        const configService = new ConfigService(jest.fn() as unknown as SSMProvider);
        const sessionService = new SessionService(mockDynamoDbClient.prototype, configService);
        const authorizationRequestValidator = new AuthorizationRequestValidator();
        const mockConfigService = jest.mocked(ConfigService);
        const logger = jest.mocked(Logger);
        const metrics = jest.mocked(Metrics);

        beforeEach(() => {
            body = {
                code: "",
                grant_type: "authorization_code",
                redirect_uri: "",
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion: "2",
            };
            headers = {
                "session-id": "1",
            } as APIGatewayProxyEventHeaders;
            jest.resetAllMocks();
            configService.init = () => Promise.resolve();
            authorizationHandlerLambda = new AuthorizationLambda(authorizationRequestValidator);
            lambdaHandler = middy(authorizationHandlerLambda.handler.bind(authorizationHandlerLambda))
                .use(
                    errorMiddleware(logger.prototype, metrics.prototype, {
                        metric_name: AUTHORIZATION_SENT_METRIC,
                        message: "Authorization Lambda error occurred",
                    }),
                )
                .use(injectLambdaContext(logger.prototype, { clearState: true }))
                .use(
                    initialiseConfigMiddleware({
                        configService: configService,
                        config_keys: [CommonConfigKey.SESSION_TABLE_NAME],
                    }),
                )
                .use(getSessionByIdMiddleware({ sessionService: sessionService }))
                .use(
                    initialiseClientConfigMiddleware({
                        configService: configService,
                        client_config_keys: [ClientConfigKey.JWT_REDIRECT_URI],
                    }),
                )
                .use(setGovUkSigningJourneyIdMiddleware(logger.prototype))
                .use(setRequestedVerificationScoreMiddleware(logger.prototype));

            const sessionItem: Partial<SessionItem> = {
                sessionId: "abc",
                authorizationCodeExpiryDate: 1,
                clientId: "1",
                clientSessionId: "1",
                redirectUri: "http://123.com",
                accessToken: "",
                accessTokenExpiryDate: 0,
                authorizationCode: "abc",
            };
            jest.spyOn(sessionService, "getSession").mockReturnValue(Promise.resolve(sessionItem as SessionItem));
            const clientConfig = new Map<string, string>();
            clientConfig.set("code", "abc");
            clientConfig.set("redirectUri", "http://123.com");
            jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValueOnce(clientConfig);
        });

        describe("has queryStringParameters parameters all populated", () => {
            let queryString = {};
            beforeEach(() => {
                queryString = {
                    client_id: "1",
                    redirect_uri: "http://123.com",
                    response_type: "test",
                } as APIGatewayProxyEventQueryStringParameters;
            });
            it("should pass with 200 status code and return non empty body", async () => {
                const metricsSpyAddMetrics = jest.spyOn(metrics.prototype, "addMetric");
                const loggerSpyAppendkeys = jest.spyOn(logger.prototype, "appendKeys");
                const loggerSpyInfo = jest.spyOn(logger.prototype, "info");

                const output = await lambdaHandler(
                    {
                        body,
                        headers,
                        queryStringParameters: queryString,
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );

                expect(output.statusCode).toBe(200);
                expect(output.body).not.toBeNull();
                expect(loggerSpyInfo).toHaveBeenCalledWith("Session found");
                expect(loggerSpyAppendkeys).toHaveBeenCalledWith({ govuk_signin_journey_id: "1" });
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 1);
            });

            it("should pass with log message and metrics sent", async () => {
                const metricsSpyAddMetrics = jest.spyOn(metrics.prototype, "addMetric");
                const loggerSpyAppendkeys = jest.spyOn(logger.prototype, "appendKeys");
                const loggerSpyInfo = jest.spyOn(logger.prototype, "info");

                await lambdaHandler(
                    {
                        body,
                        headers,
                        queryStringParameters: queryString,
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );

                expect(loggerSpyInfo).toHaveBeenCalledWith("Session found");
                expect(loggerSpyAppendkeys).toHaveBeenCalledWith({ govuk_signin_journey_id: "1" });
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 1);
            });
        });

        describe("authorization request returns access_denied", () => {
            let metricsSpyAddMetrics: jest.SpyInstance;
            let loggerSpyError: jest.SpyInstance;
            const sessionItem: Partial<SessionItem> = {
                sessionId: "abc",
                authorizationCodeExpiryDate: 1,
                clientId: "1",
                clientSessionId: "1",
                redirectUri: "http://123.com",
                accessTokenExpiryDate: 0,
                authorizationCode: undefined,
            };
            beforeEach(() => {
                metricsSpyAddMetrics = jest.spyOn(metrics.prototype, "addMetric");
                loggerSpyError = jest.spyOn(logger.prototype, "error");
                jest.spyOn(sessionService, "getSession").mockReturnValueOnce(
                    Promise.resolve(sessionItem as SessionItem),
                );
            });
            it("should return 403 status code and return body with access_denied", async () => {
                const result = await lambdaHandler(
                    {
                        body: body,
                        headers: headers,
                        queryStringParameters: {
                            client_id: "1",
                            redirect_uri: "http://123.com",
                            response_type: "a_response_type",
                        },
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );

                expect(result).toEqual({
                    statusCode: 403,
                    body: JSON.stringify({
                        message: "Authorization permission denied",
                        code: "access_denied",
                        errorSummary: "access_denied: Authorization permission denied",
                    }),
                });
                expect(loggerSpyError).toHaveBeenCalledWith(
                    "Authorization Lambda error occurred: access_denied: Authorization permission denied",
                    expect.any(AccessDeniedError),
                );
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 0);
            });
        });

        describe("authorization request has missing attributes", () => {
            let metricsSpyAddMetrics: jest.SpyInstance;
            let loggerSpyError: jest.SpyInstance;
            beforeEach(() => {
                metricsSpyAddMetrics = jest.spyOn(metrics.prototype, "addMetric");
                loggerSpyError = jest.spyOn(logger.prototype, "error");
            });

            it("should fail validation when response_type is missing from queryString", async () => {
                const queryString = {
                    client_id: "1",
                    redirect_uri: "http://123.com",
                } as APIGatewayProxyEventQueryStringParameters;

                const output = await lambdaHandler(
                    {
                        body: body,
                        headers: headers,
                        queryStringParameters: queryString,
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );

                expect(output.statusCode).toBe(400);
                expect(output.body).toContain("Session Validation Exception");

                expect(loggerSpyError).toHaveBeenCalledWith(
                    "Authorization Lambda error occurred: 1019: Session Validation Exception - Missing response_type parameter",
                    expect.any(SessionValidationError),
                );
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 0);
            });
            it("should fail validation when the redirect_uri is missing from from queryString", async () => {
                const queryString = {
                    client_id: "1",
                    response_type: "test",
                } as APIGatewayProxyEventQueryStringParameters;

                const output = await lambdaHandler(
                    {
                        body: body,
                        headers: headers,
                        queryStringParameters: queryString,
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );

                expect(output.statusCode).toBe(400);
                expect(output.body).toContain("Session Validation Exception");

                expect(loggerSpyError).toHaveBeenCalledWith(
                    "Authorization Lambda error occurred: 1019: Session Validation Exception - Missing redirect_uri parameter",
                    expect.any(SessionValidationError),
                );
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 0);
            });
            it("should fail validation should fail when the client_id is missing", async () => {
                const queryString = {
                    redirect_uri: "http://123.com",
                    response_type: "test",
                } as APIGatewayProxyEventQueryStringParameters;

                const output = await lambdaHandler(
                    {
                        body: body,
                        headers: headers,
                        queryStringParameters: queryString,
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );

                expect(output.statusCode).toBe(400);
                expect(output.body).toContain("Session Validation Exception");

                expect(loggerSpyError).toHaveBeenCalledWith(
                    "Authorization Lambda error occurred: 1019: Session Validation Exception - Missing client_id parameter",
                    expect.any(SessionValidationError),
                );
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 0);
            });
        });

        describe("has session present", () => {
            it("should should fail when there is no session-id in the authorization request header", async () => {
                const metricsSpyAddMetrics = jest.spyOn(metrics.prototype, "addMetric");
                const loggerSpyError = jest.spyOn(logger.prototype, "error");
                const output = await lambdaHandler(
                    {
                        body,
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );
                expect(output.statusCode).toBe(400);
                expect(output.body).toContain("Invalid request: Missing session-id header");
                expect(loggerSpyError).toHaveBeenCalledWith(
                    "Authorization Lambda error occurred: Invalid request: Missing session-id header",
                    expect.any(InvalidRequestError),
                );
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 0);
            });
            it("should should fail when no existing session is found for the current request", async () => {
                const metricsSpyAddMetrics = jest.spyOn(metrics.prototype, "addMetric");
                const loggerSpyError = jest.spyOn(logger.prototype, "error");
                const sessionId = "1";
                const sessionNotFound = new SessionNotFoundError(sessionId);
                jest.spyOn(sessionService, "getSession").mockRejectedValueOnce(sessionNotFound);

                const output = await lambdaHandler(
                    {
                        body,
                        headers,
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );
                expect(output.statusCode).toBe(400);
                expect(output.body).toContain(`Could not find session item with id: ${sessionId}`);
                expect(loggerSpyError).toHaveBeenCalledWith(
                    "Authorization Lambda error occurred: 1029: Could not find session item with id: 1",
                    sessionNotFound,
                );
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 0);
            });

            it("should should fail when a server error occurs", async () => {
                const metricsSpyAddMetrics = jest.spyOn(metrics.prototype, "addMetric");
                const loggerSpyError = jest.spyOn(logger.prototype, "error");
                const serverError = new ServerError();
                jest.spyOn(sessionService, "getSession").mockRejectedValueOnce(serverError);

                const output = await lambdaHandler(
                    {
                        body,
                        headers,
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );
                expect(output.statusCode).toBe(500);
                expect(output.body).toContain("Server error");
                expect(loggerSpyError).toHaveBeenCalledWith(
                    "Authorization Lambda error occurred: Server error",
                    serverError,
                );
                expect(metricsSpyAddMetrics).toHaveBeenCalledWith("authorization_sent", "Count", 0);
            });
        });
    });
});
