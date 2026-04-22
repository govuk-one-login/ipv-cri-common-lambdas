import middy from "@middy/core";
import { afterEach, beforeEach, describe, expect, it, vi, type MockedObject, type MockInstance } from "vitest";

import { APIGatewayProxyEvent, Context } from "aws-lambda";
import { AccessTokenLambda } from "../../../src/handlers/access-token-handler";
import { SessionService } from "../../../src/services/session-service";
import validateEventPayloadMiddleware from "../../../src/middlewares/access-token/validate-event-payload-middleware";
import { AccessTokenRequestValidator } from "../../../src/services/token-request-validator";
import { logger } from "@govuk-one-login/cri-logger";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { DynamoDBDocument, QueryCommandInput } from "@aws-sdk/lib-dynamodb";
import { ConfigService } from "../../../src/common/config/config-service";
import { JwtVerificationConfig } from "../../../src/types/jwt-verification-config";
import { JwtVerifier, JwtVerifierFactory } from "../../../src/common/security/jwt-verifier";
import { BearerAccessTokenFactory } from "../../../src/services/bearer-access-token-factory";
import { InvalidRequestError, ServerError } from "../../../src/common/utils/errors";
import errorMiddleware from "../../../src/middlewares/error/error-middleware";
import initialiseConfigMiddleware from "../../../src/middlewares/config/initialise-config-middleware";
import getSessionByAuthCodeMiddleware from "../../../src/middlewares/session/get-session-by-auth-code-middleware";
import getSessionByIdMiddleware from "../../../src/middlewares/session/get-session-by-id-middleware";
import setGovUkSigningJourneyIdMiddleware from "../../../src/middlewares/session/set-gov-uk-signing-journey-id-middleware";
import { CommonConfigKey } from "../../../src/types/config-keys";
import setRequestedVerificationScoreMiddleware from "../../../src/middlewares/session/set-requested-verification-score-middleware";
import { SSMProvider } from "@aws-lambda-powertools/parameters/ssm";
import { captureMetric } from "@govuk-one-login/cri-metrics";

vi.mock("../../../src/common/config/config-service");
vi.mock("../../../src/common/security/jwt-verifier");
vi.mock("@govuk-one-login/cri-metrics", () => ({
    metrics: {
        addDimension: vi.fn(),
        publishStoredMetrics: vi.fn(),
        logMetrics: vi.fn(),
    },
    captureMetric: vi.fn(),
}));
vi.mock("@govuk-one-login/cri-logger", () => ({
    logger: {
        info: vi.fn(),
        error: vi.fn(),
        clearBuffer: vi.fn(),
        resetKeys: vi.fn(),
        refreshSampleRateCalculation: vi.fn(),
        addContext: vi.fn(),
        logEventIfEnabled: vi.fn(),
        appendKeys: vi.fn(),
    },
}));

describe("access-token-handler.ts", () => {
    let configService: ConfigService;
    let sessionService: SessionService;
    let accessTokenLambda: AccessTokenLambda;
    let lambdaHandler: middy.MiddyfiedHandler;
    let mockDynamoDbClient: MockedObject<typeof DynamoDBDocument>;
    let mockJwtVerifierFactory: MockedObject<typeof JwtVerifierFactory>;
    let accessTokenRequestValidator: AccessTokenRequestValidator;
    const metricsSpy = vi.mocked(captureMetric);

    afterEach(() => vi.resetAllMocks());

    beforeEach(() => {
        const impl = () => vi.fn().mockImplementation(() => Promise.resolve({ Parameters: [] }));
        mockDynamoDbClient = vi.mocked(DynamoDBDocument);
        mockDynamoDbClient.prototype.send = impl();
        mockDynamoDbClient.prototype.query = impl();
        mockJwtVerifierFactory = vi.mocked(JwtVerifierFactory);

        configService = new ConfigService(vi.fn() as unknown as SSMProvider);
        sessionService = new SessionService(mockDynamoDbClient.prototype, configService);
        accessTokenRequestValidator = new AccessTokenRequestValidator(mockJwtVerifierFactory.prototype);
        accessTokenLambda = new AccessTokenLambda(
            configService,
            new BearerAccessTokenFactory(10),
            sessionService,
            accessTokenRequestValidator,
        );

        configService.init = () => Promise.resolve();

        lambdaHandler = middy(accessTokenLambda.handler.bind(accessTokenLambda))
            .use(
                errorMiddleware(logger, {
                    metric_name: "accesstoken",
                    message: "Access Token Lambda error occurred",
                }),
            )
            .use(injectLambdaContext(logger, { clearState: true }))
            .use(
                initialiseConfigMiddleware({
                    configService: configService,
                    config_keys: [CommonConfigKey.SESSION_TABLE_NAME, CommonConfigKey.SESSION_TTL],
                }),
            )
            .use(
                validateEventPayloadMiddleware({
                    requestValidator: accessTokenRequestValidator,
                }),
            )
            .use(getSessionByAuthCodeMiddleware({ sessionService: sessionService }))
            .use(getSessionByIdMiddleware({ sessionService: sessionService }))
            .use(setGovUkSigningJourneyIdMiddleware(logger))
            .use(setRequestedVerificationScoreMiddleware(logger));
    });

    describe("Handler", () => {
        const jwtVerificationConfig: JwtVerificationConfig = {
            publicSigningJwk: "",
            jwtSigningAlgorithm: "",
            jwksEndpoint: "",
        };
        let jwtVerifier: JwtVerifier;
        let mockConfigService: MockedObject<typeof ConfigService>;

        const redirectUri = "http://123.abc.com";
        const code = "123abc";
        const clientSessionId = "1";
        const clientConfig = new Map<string, string>();
        clientConfig.set("code", code);
        clientConfig.set("redirectUri", redirectUri);
        describe("success paths", () => {
            const twentyFourthOfFeb2023InMs = 1677249836658;
            const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
            const expiry = Math.floor((twentyFourthOfFeb2023InMs + sevenDaysInMilliseconds) / 1000);

            beforeEach(() => {
                jwtVerifier = new JwtVerifier(jwtVerificationConfig, logger);
                mockConfigService = vi.mocked(ConfigService);

                vi.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                vi.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValueOnce(clientConfig);
                vi.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                vi.spyOn(jwtVerifier, "verify").mockResolvedValueOnce({});
            });

            afterEach(() => vi.resetAllMocks());

            it("should pass when payload matches session", async () => {
                const sessionItem = {
                    sessionId: code,
                    clientSessionId: clientSessionId,
                    authorizationCode: code,
                };
                vi.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(async () => ({
                    Items: [sessionItem],
                }));
                vi.spyOn(mockDynamoDbClient.prototype, "send").mockImplementation(async () => ({
                    Item: sessionItem,
                }));

                const response = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: redirectUri,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );

                expect(response.statusCode).toBe(200);
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken");
            });

            it("should return http 200 if the authorizationCodeExpiryDate is within date", async () => {
                const sessionItem = {
                    sessionId: code,
                    authorizationCodeExpiryDate: expiry,
                    clientId: "1",
                    clientSessionId,
                    redirectUri,
                    accessToken: "",
                    accessTokenExpiryDate: expiry,
                    authorizationCode: code,
                };
                vi.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(async () => ({
                    Items: [sessionItem],
                }));
                vi.spyOn(mockDynamoDbClient.prototype, "send").mockImplementation(async () => ({
                    Item: sessionItem,
                }));

                const response = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: redirectUri,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );

                expect(response.statusCode).toBe(200);
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken");
            });
        });

        describe("Fail paths", () => {
            let loggerSpy: MockInstance;

            afterEach(() => vi.resetAllMocks());
            beforeEach(() => {
                mockConfigService = vi.mocked(ConfigService);
                jwtVerifier = new JwtVerifier(jwtVerificationConfig, logger);

                loggerSpy = vi.spyOn(logger, "error");

                vi.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValueOnce(clientConfig);
                vi.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                vi.spyOn(jwtVerifier, "verify").mockResolvedValueOnce({});
            });

            it("should fail when no body is passed in the request", async () => {
                const event = {} as unknown as APIGatewayProxyEvent;

                const response = await lambdaHandler(event, {} as Context);

                const body = JSON.parse(response.body);
                expect(response).toEqual({
                    statusCode: 400,
                    body: expect.anything(),
                });
                expect(body.message).toContain("missing body");
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: Invalid request: missing body",
                    expect.objectContaining({ message: "Invalid request: missing body" }),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should fail when request payload is not valid", async () => {
                const event = { body: {} } as unknown as APIGatewayProxyEvent;

                const response = await lambdaHandler(event, {} as Context);

                const body = JSON.parse(response.body);
                expect(response.statusCode).toBe(400);
                expect(response.body).not.toBeNull;
                expect(body.message).toContain("Invalid request");
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: Invalid request: Missing redirectUri parameter",
                    expect.objectContaining({ message: "Invalid request: Missing redirectUri parameter" }),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should fail when session is not found", async () => {
                vi.spyOn(jwtVerifier, "verify").mockReturnValueOnce(Promise.resolve(expect.anything()));
                const response = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: redirectUri,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    } as unknown as APIGatewayProxyEvent,
                    {} as Context,
                );
                const body = JSON.parse(response.body);
                expect(response.statusCode).toBe(403);
                expect(response.body).not.toBeNull;
                expect(body.message).toContain("Access token expired");
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: 1026: Access token expired",
                    expect.objectContaining({ message: "Access token expired" }),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should fail when authorization code is not found", async () => {
                vi.spyOn(jwtVerifier, "verify").mockResolvedValueOnce({});
                const redirectUri = "http://123.abc.com";
                const code = "DOES_NOT_MATCH";

                vi.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(async () => ({ Items: [] }));

                const output = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: redirectUri,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    },
                    {} as Context,
                );

                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(403);
                expect(body.code).toBe(1026);
                expect(body.message).toContain("Access token expired");
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: 1026: Access token expired",
                    expect.objectContaining({ message: "Access token expired" }),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should fail when redirect URIs do not match", async () => {
                const badUrl = "http://does-not-match";
                const sessionItem = {
                    sessionId: code,
                    clientId: "1",
                    clientSessionId: "1",
                    redirectUri: badUrl,
                    accessToken: "",
                    authorizationCode: code,
                };
                vi.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(async () => ({
                    Items: [sessionItem],
                }));
                vi.spyOn(mockDynamoDbClient.prototype, "send").mockImplementation(async () => ({
                    Item: sessionItem,
                }));

                const output = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: badUrl,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    },
                    {} as Context,
                );
                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(400);
                expect(body.message).toContain(`redirect uri ${badUrl} does not match`);
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should error when jwt verify fails", async () => {
                const sessionItem = {
                    sessionId: code,
                    clientId: "1",
                    clientSessionId: "1",
                    redirectUri,
                    accessToken: "",
                    authorizationCode: code,
                };
                vi.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(async () => ({
                    Items: [sessionItem],
                }));
                vi.spyOn(mockDynamoDbClient.prototype, "send").mockImplementation(async () => ({
                    Item: sessionItem,
                }));

                vi.spyOn(accessTokenRequestValidator, "verifyJwtSignature").mockRejectedValueOnce(
                    new InvalidRequestError("JWT signature verification failed"),
                );

                const output = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: redirectUri,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    },
                    {} as Context,
                );

                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(400);
                expect(body.message).toContain(`JWT signature verification failed`);
                expect(loggerSpy).toHaveBeenCalledOnce();
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: JWT signature verification failed",
                    expect.objectContaining({ message: "JWT signature verification failed" }),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
                expect(metricsSpy).toHaveBeenCalledWith("jwt_verification_failed");
            });

            it("should return http 403 when the session item is invalid", async () => {
                const anInValidSessionItem = {
                    Items: [],
                };

                mockDynamoDbClient.prototype.query = vi
                    .fn()
                    .mockImplementation(() => Promise.resolve(anInValidSessionItem));

                const response = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: redirectUri,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    },
                    {} as Context,
                );

                expect(response.statusCode).toBe(403);
                expect(response.body).toContain("Access token expired");
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should return http 403 if the authorizationCodeExpiryDate has expired", async () => {
                const twentyFourthOfFeb2023InMs = 1677249836658;
                vi.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs - sevenDaysInMilliseconds) / 1000);
                const futureExpiry = Math.floor((twentyFourthOfFeb2023InMs + sevenDaysInMilliseconds) / 1000);

                vi.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(async () => ({
                    Items: [
                        {
                            expiryDate: futureExpiry,
                            sessionId: code,
                            authorizationCodeExpiryDate: expiry,
                            clientId: "1",
                            clientSessionId: "1",
                            redirectUri: redirectUri,
                            accessToken: "",
                            accessTokenExpiryDate: expiry,
                            authorizationCode: code,
                        },
                    ],
                }));

                const output = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: redirectUri,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    },
                    {} as Context,
                );

                expect(output.statusCode).toBe(403);
                expect(output.body).toContain("Authorization code expired");
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should return http 403 if the session has expired", async () => {
                const twentyFourthOfFeb2023InMs = 1677249836658;
                vi.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs - sevenDaysInMilliseconds) / 1000);
                const futureExpiry = Math.floor((twentyFourthOfFeb2023InMs + sevenDaysInMilliseconds) / 1000);

                vi.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(async () => ({
                    Items: [
                        {
                            sessionId: code,
                            expiryDate: expiry,
                            authorizationCodeExpiryDate: futureExpiry,
                            clientId: "1",
                            clientSessionId: "1",
                            redirectUri: redirectUri,
                            accessToken: "",
                            accessTokenExpiryDate: futureExpiry,
                            authorizationCode: code,
                        },
                    ],
                }));

                const output = await lambdaHandler(
                    {
                        body: {
                            code,
                            grant_type: "authorization_code",
                            redirect_uri: redirectUri,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    },
                    {} as Context,
                );

                expect(output.statusCode).toBe(403);
                expect(output.body).toContain("Session expired");
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should return http 403 when there is more than 1 session item", async () => {
                vi.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValueOnce(jwtVerifier);
                vi.spyOn(jwtVerifier, "verify").mockReturnValueOnce(Promise.resolve(expect.anything()));

                const twoSessionItems = {
                    Items: [{}, {}],
                } as unknown as QueryCommandInput;

                mockDynamoDbClient.prototype.query = vi.fn().mockImplementation(() => Promise.resolve(twoSessionItems));

                const output = await lambdaHandler(
                    {
                        body: {
                            authorizationCode: code,
                            sessionId: code,
                            clientSessionId,
                            redirect_uri: redirectUri,
                            clientId: "1",
                            grant_type: "authorization_code",
                            code,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    },
                    {} as Context,
                );

                expect(output.statusCode).toBe(403);
                expect(output.body).toContain("Access token expired");
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });

            it("should fail when dynamoDb is not available", async () => {
                vi.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                vi.spyOn(jwtVerifier, "verify").mockReturnValue(Promise.resolve(expect.anything()));
                vi.spyOn(sessionService, "getSessionByAuthorizationCode").mockRejectedValueOnce(new ServerError());

                const event = {
                    body: {
                        code,
                        grant_type: "authorization_code",
                        redirect_uri: redirectUri,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent;
                const output = await lambdaHandler(event, {} as Context);
                expect(output.statusCode).toBe(500);
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: Server error",
                    new ServerError(),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", 0);
            });
        });
    });
});
