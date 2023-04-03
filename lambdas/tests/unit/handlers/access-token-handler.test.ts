import middy from "@middy/core";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { APIGatewayProxyEvent, Context } from "aws-lambda";
import { AccessTokenLambda } from "../../../src/handlers/access-token-handler";
import { SessionService } from "../../../src/services/session-service";
import validateEventPayloadMiddleware from "../../../src/middlewares/access-token/validate-event-payload-middleware";
import { AccessTokenRequestValidator } from "../../../src/services/token-request-validator";
import { Logger } from "@aws-lambda-powertools/logger";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/lib/middleware/middy";
import { DynamoDBDocument, QueryCommandInput } from "@aws-sdk/lib-dynamodb";
import { ConfigService } from "../../../src/common/config/config-service";
import { JwtVerificationConfig } from "../../../src/types/jwt-verification-config";
import { JwtVerifier, JwtVerifierFactory } from "../../../src/common/security/jwt-verifier";
import { BearerAccessTokenFactory } from "../../../src/services/bearer-access-token-factory";
import { SSMClient } from "@aws-sdk/client-ssm";
import { InvalidRequestError, ServerError } from "../../../src/common/utils/errors";
import errorMiddleware from "../../../src/middlewares/error/error-middleware";
import configurationInitMiddleware from "../../../src/middlewares/config/configuration-init-middleware";
import getSessionByAuthCodeMiddleware from "../../../src/middlewares/session/get-session-by-auth-code-middleware";
import getSessionById from "../../../src/middlewares/session/get-session-by-id";
import setGovUkSigningJourneyIdMiddleware from "../../../src/middlewares/session/set-gov-uk-signing-journey-id-middleware";

jest.mock("../../../src/common/config/config-service");
jest.mock("../../../src/common/security/jwt-verifier");
jest.mock("@aws-lambda-powertools/metrics");
jest.mock("@aws-lambda-powertools/logger");
jest.mock("@aws-sdk/lib-dynamodb", () => {
    return {
        __esModule: true,
        ...jest.requireActual("@aws-sdk/lib-dynamodb"),
        GetCommand: jest.fn(),
        UpdateCommand: jest.fn(),
    };
});
jest.mock("@aws-lambda-powertools/logger/lib/middleware/middy", () => {
    return {
        __esModule: true,
        ...jest.requireActual("@aws-lambda-powertools/logger/lib/middleware/middy"),
        default: jest.fn(() => ({
            before: jest.fn(),
        })),
    };
});

describe("access-token-handler.ts", () => {
    let logger: Logger;
    let metrics: Metrics;
    let configService: ConfigService;
    let sessionService: SessionService;
    let accessTokenLambda: AccessTokenLambda;
    let lambdaHandler: middy.MiddyfiedHandler;
    let mockDynamoDbClient: jest.MockedObjectDeep<typeof DynamoDBDocument>;
    let mockJwtVerifierFactory: jest.MockedObjectDeep<typeof JwtVerifierFactory>;
    let accessTokenRequestValidator: AccessTokenRequestValidator;

    afterEach(() => jest.resetAllMocks());

    beforeEach(() => {
        const impl = () => jest.fn().mockImplementation(() => Promise.resolve({ Parameters: [] }));
        mockDynamoDbClient = jest.mocked(DynamoDBDocument);
        mockDynamoDbClient.prototype.send = impl();
        mockDynamoDbClient.prototype.query = impl();
        mockJwtVerifierFactory = jest.mocked(JwtVerifierFactory);

        logger = new Logger();
        metrics = new Metrics();
        configService = new ConfigService(jest.fn() as unknown as SSMClient);
        sessionService = new SessionService(mockDynamoDbClient.prototype, configService);
        accessTokenRequestValidator = new AccessTokenRequestValidator(mockJwtVerifierFactory.prototype);
        accessTokenLambda = new AccessTokenLambda(
            new BearerAccessTokenFactory(10),
            sessionService,
            accessTokenRequestValidator,
        );

        configService.init = () => Promise.resolve();

        lambdaHandler = middy(accessTokenLambda.handler.bind(accessTokenLambda))
            .use(
                errorMiddleware(logger, metrics, {
                    metric_name: "accesstoken",
                    message: "Access Token Lambda error occurred",
                }),
            )
            .use(injectLambdaContext(logger, { clearState: true }))
            .use(configurationInitMiddleware())
            .use(
                validateEventPayloadMiddleware({
                    requestValidator: accessTokenRequestValidator,
                }),
            )
            .use(getSessionByAuthCodeMiddleware({ sessionService: sessionService }))
            .use(getSessionById({ sessionService: sessionService }))
            .use(setGovUkSigningJourneyIdMiddleware(logger));
    });

    describe("Handler", () => {
        const jwtVerificationConfig: JwtVerificationConfig = {
            publicSigningJwk: "",
            jwtSigningAlgorithm: "",
        };
        let jwtVerifier: JwtVerifier;
        let mockMetrics: jest.MockedObjectDeep<typeof Metrics>;
        let metricsSpy: jest.SpyInstance<unknown, never, unknown>;
        let mockConfigService: jest.MockedObjectDeep<typeof ConfigService>;

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
                mockMetrics = jest.mocked(Metrics);
                metricsSpy = jest.spyOn(mockMetrics.prototype, "addMetric");

                jwtVerifier = new JwtVerifier(jwtVerificationConfig, logger);
                mockConfigService = jest.mocked(ConfigService);

                jest.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValueOnce(clientConfig);
                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockResolvedValueOnce(Promise.resolve(expect.anything()));
            });

            afterEach(() => jest.resetAllMocks());

            it("should pass when payload matches session", async () => {
                const sessionItem = {
                    sessionId: code,
                    clientSessionId: clientSessionId,
                    authorizationCode: code,
                };
                mockDynamoDbClient.prototype.query.mockImplementation(() => Promise.resolve({ Items: [sessionItem] }));
                mockDynamoDbClient.prototype.send.mockImplementation(() => Promise.resolve({ Item: sessionItem }));

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
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 1);
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
                mockDynamoDbClient.prototype.query.mockImplementation(() => Promise.resolve({ Items: [sessionItem] }));
                mockDynamoDbClient.prototype.send.mockImplementation(() => Promise.resolve({ Item: sessionItem }));

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
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 1);
            });
        });

        describe("Fail paths", () => {
            let mockLogger: jest.MockedObjectDeep<typeof Logger>;
            let loggerSpy: jest.SpyInstance<unknown, never, unknown>;

            afterEach(() => jest.resetAllMocks());
            beforeEach(() => {
                mockMetrics = jest.mocked(Metrics);
                mockLogger = jest.mocked(Logger);
                mockConfigService = jest.mocked(ConfigService);
                jwtVerifier = new JwtVerifier(jwtVerificationConfig, logger);

                metricsSpy = jest.spyOn(mockMetrics.prototype, "addMetric");
                loggerSpy = jest.spyOn(mockLogger.prototype, "error");

                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValueOnce(clientConfig);
                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockResolvedValueOnce(Promise.resolve(expect.anything()));
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
                    Error("Invalid request: missing body"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
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
                    Error("Invalid request: Missing redirectUri parameter"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should fail when session is not found", async () => {
                jest.spyOn(jwtVerifier, "verify").mockReturnValueOnce(Promise.resolve(expect.anything()));
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
                    Error("Access token expired"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should fail when authorization code is not found", async () => {
                jest.spyOn(jwtVerifier, "verify").mockReturnValueOnce(Promise.resolve(expect.anything()));
                const redirectUri = "http://123.abc.com";
                const code = "DOES_NOT_MATCH";

                jest.spyOn(mockDynamoDbClient.prototype, "query").mockReturnValueOnce({ Items: [] });

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
                    Error("Access token expired"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
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
                mockDynamoDbClient.prototype.query.mockImplementation(() => Promise.resolve({ Items: [sessionItem] }));
                mockDynamoDbClient.prototype.send.mockImplementation(() => Promise.resolve({ Item: sessionItem }));

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
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
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
                mockDynamoDbClient.prototype.query.mockImplementation(() => Promise.resolve({ Items: [sessionItem] }));
                mockDynamoDbClient.prototype.send.mockImplementation(() => Promise.resolve({ Item: sessionItem }));

                jest.spyOn(accessTokenRequestValidator, "verifyJwtSignature").mockRejectedValueOnce(
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
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: JWT signature verification failed",
                    Error("JWT signature verification failed"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should return http 403 when the session item is invalid", async () => {
                const anInValidSessionItem = {
                    Items: [],
                };

                mockDynamoDbClient.prototype.query = jest
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
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should return http 403 if the authorizationCodeExpiryDate has expired", async () => {
                const twentyFourthOfFeb2023InMs = 1677249836658;
                jest.spyOn(Date, "now").mockReturnValueOnce(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs - sevenDaysInMilliseconds) / 1000);

                mockDynamoDbClient.prototype.query.mockImplementation(() =>
                    Promise.resolve({
                        Items: [
                            {
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
                    }),
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

                expect(output.statusCode).toBe(403);
                expect(output.body).toContain("Authorization code expired");
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should return http 403 if the session has expired", async () => {
                const twentyFourthOfFeb2023InMs = 1677249836658;
                jest.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs - sevenDaysInMilliseconds) / 1000);
                const futureExpiry = Math.floor((twentyFourthOfFeb2023InMs + sevenDaysInMilliseconds) / 1000);

                mockDynamoDbClient.prototype.query.mockImplementation(() =>
                    Promise.resolve({
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
                    }),
                );

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
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should return http 403 when there is more than 1 session item", async () => {
                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValueOnce(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockReturnValueOnce(Promise.resolve(expect.anything()));

                const twoSessionItems = {
                    Items: [{}, {}],
                } as unknown as QueryCommandInput;

                mockDynamoDbClient.prototype.query = jest
                    .fn()
                    .mockImplementation(() => Promise.resolve(twoSessionItems));

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
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should fail when dynamoDb is not available", async () => {
                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(Promise.resolve(expect.anything()));
                jest.spyOn(sessionService, "getSessionByAuthorizationCode").mockRejectedValueOnce(new ServerError());

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
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });
        });
    });
});
