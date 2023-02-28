import { JwtVerificationConfig } from "../../../src/types/jwt-verification-config";
import { AccessTokenLambda } from "../../../src/handlers/access-token-handler";
import { ConfigService } from "../../../src/common/config/config-service";
import { AccessTokenRequestValidator } from "../../../src/services/token-request-validator";
import { SessionService } from "../../../src/services/session-service";
import { APIGatewayProxyEvent } from "aws-lambda/trigger/api-gateway-proxy";
import { SSMClient } from "@aws-sdk/client-ssm";
import { JwtVerifier, JwtVerifierFactory } from "../../../src/common/security/jwt-verifier";
import { Logger } from "@aws-lambda-powertools/logger";
import { DynamoDBDocument, QueryCommandInput, QueryCommandOutput } from "@aws-sdk/lib-dynamodb";
import { SessionItem } from "../../../src/types/session-item";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { ServerError } from "../../../src/types/errors";
import { BearerAccessTokenFactory } from "../../../src/services/bearer-access-token-factory";
import { JWTPayload } from "jose";

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

describe("access-token-handler.ts", () => {
    const mockDynamoDbClient = jest.mocked(DynamoDBDocument);

    beforeEach(() => {
        jest.resetAllMocks();
        const impl = () => {
            const mockPromise = new Promise<unknown>((resolve) => {
                resolve({ Parameters: [] });
            });
            return jest.fn().mockImplementation(() => {
                return mockPromise;
            });
        };
        mockDynamoDbClient.prototype.send = impl();
        mockDynamoDbClient.prototype.query = impl();
    });

    describe("Handler", () => {
        let accessTokenLambda: AccessTokenLambda;
        const configService = new ConfigService(jest.fn() as unknown as SSMClient);
        const logger = new Logger();
        const jwtVerificationConfig: JwtVerificationConfig = {
            publicSigningJwk: "",
            jwtSigningAlgorithm: "",
        };
        const jwtVerifier = new JwtVerifier(jwtVerificationConfig, logger);
        const mockJwtVerifierFactory = jest.mocked(JwtVerifierFactory);
        const mockConfigService = jest.mocked(ConfigService);
        const accessTokenService = new BearerAccessTokenFactory(10);
        const sessionService = new SessionService(mockDynamoDbClient.prototype, configService);
        const accessTokenRequestValidator = new AccessTokenRequestValidator(mockJwtVerifierFactory.prototype);

        const mockLogger = jest.mocked(Logger);
        const mockMetrics = jest.mocked(Metrics);
        const metricsSpy = jest.spyOn(mockMetrics.prototype, "addMetric");

        describe("success paths", () => {
            beforeEach(() => {
                jest.resetAllMocks();
                configService.init = () => Promise.resolve();
                accessTokenLambda = new AccessTokenLambda(
                    accessTokenService,
                    sessionService,
                    accessTokenRequestValidator,
                );
                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<JWTPayload>((resolve) => {
                        resolve(expect.anything());
                    }),
                );
            });

            it("should pass when payload matches session", async () => {
                const redirectUri = "http://123.abc.com";
                const code = "123abc";
                const clientSessionId = "1";

                const twentyFourthOfFeb2023InMs = 1677249836658;
                jest.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs + sevenDaysInMilliseconds) / 1000);

                jest.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(() => {
                    return Promise.resolve({
                        Items: [
                            {
                                clientSessionId: clientSessionId,
                                authorizationCode: code,
                                redirectUri,
                            },
                        ],
                    });
                });

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const sessionItem = {
                    Items: [
                        {
                            sessionId: code,
                            authorizationCodeExpiryDate: expiry,
                            clientId: "1",
                            clientSessionId: clientSessionId,
                            redirectUri: redirectUri,
                            accessToken: "",
                            accessTokenExpiryDate: expiry,
                            authorizationCode: code,
                        } as SessionItem,
                    ],
                } as unknown as QueryCommandInput;

                const impl = () => {
                    const mockPromise = new Promise<unknown>((resolve) => {
                        resolve(sessionItem);
                    });
                    return jest.fn().mockImplementation(() => {
                        return mockPromise;
                    });
                };
                mockDynamoDbClient.prototype.query = impl();

                const event = {
                    body: {
                        code,
                        grant_type: "authorization_code",
                        redirect_uri: redirectUri,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent;
                const output = await accessTokenLambda.handler(event, null);
                expect(output.statusCode).toBe(200);
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 1);
            });

            it("should return http 200 if the authorizationCodeExpiryDate is within date", async () => {
                const redirectUri = "http://123.abc.com";
                const code = "123abc";

                const twentyFourthOfFeb2023InMs = 1677249836658;
                jest.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs + sevenDaysInMilliseconds) / 1000);

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const sessionItem = {
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
                        } as SessionItem,
                    ],
                } as unknown as QueryCommandInput;

                const impl = () => {
                    const mockPromise = new Promise<unknown>((resolve) => {
                        resolve(sessionItem);
                    });
                    return jest.fn().mockImplementation(() => {
                        return mockPromise;
                    });
                };
                mockDynamoDbClient.prototype.query = impl();

                const output = await accessTokenLambda.handler(
                    {
                        body: {
                            code,
                            grant_type: "authorization_code",
                            redirect_uri: redirectUri,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    } as unknown as APIGatewayProxyEvent,
                    null,
                );

                expect(output.statusCode).toBe(200);
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 1);
            });
        });

        describe("Fail paths", () => {
            const sessionService = new SessionService(mockDynamoDbClient.prototype, configService);
            const loggerSpy = jest.spyOn(mockLogger.prototype, "error");
            beforeEach(() => {
                jest.resetAllMocks();
                configService.init = () => Promise.resolve();
                accessTokenLambda = new AccessTokenLambda(
                    accessTokenService,
                    sessionService,
                    accessTokenRequestValidator,
                );
                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
            });

            it("should fail when no body is passed in the request", async () => {
                const event = {} as unknown as APIGatewayProxyEvent;
                const output = await accessTokenLambda.handler(event, null);
                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(400);
                expect(output.body).not.toBeNull;
                expect(body.message).toContain("missing body");
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: Invalid request: missing body",
                    Error("Invalid request: missing body"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should fail when request payload is not valid", async () => {
                const event = { body: {} } as unknown as APIGatewayProxyEvent;
                const output = await accessTokenLambda.handler(event, null);
                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(400);
                expect(output.body).not.toBeNull;
                expect(body.message).toContain("Invalid request");
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: Invalid request: Missing redirectUri parameter",
                    Error("Invalid request: Missing redirectUri parameter"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should fail when session is not found", async () => {
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<JWTPayload>((resolve) => {
                        resolve(expect.anything());
                    }),
                );
                const redirectUri = "http://123.abc.com";
                const code = "123abc";
                const event = {
                    body: {
                        code,
                        grant_type: "authorization_code",
                        redirect_uri: redirectUri,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent;
                const output = await accessTokenLambda.handler(event, null);
                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(403);
                expect(output.body).not.toBeNull;
                expect(body.message).toContain("Access token expired");
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: 1026: Access token expired",
                    Error("Access token expired"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should fail when authorization code is not found", async () => {
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<JWTPayload>((resolve) => {
                        resolve(expect.anything());
                    }),
                );
                const redirectUri = "http://123.abc.com";
                const code = "DOES_NOT_MATCH";
                const event = {
                    body: {
                        code: code,
                        grant_type: "authorization_code",
                        redirect_uri: redirectUri,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent;
                const mockDynamoDbClientQueryResult: unknown = {
                    Items: [
                        {
                            clientSessionId: "1",
                            authorizationCode: "123abc",
                            redirectUri,
                        },
                    ],
                };
                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);

                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);
                jest.spyOn(mockDynamoDbClient.prototype, "query").mockReturnValue(
                    mockDynamoDbClientQueryResult as void,
                );

                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<JWTPayload>((resolve) => {
                        resolve(expect.anything());
                    }),
                );

                const output = await accessTokenLambda.handler(event, null);
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
                const redirectUri = "http://123.abc.com";
                const badUrl = "http://does-not-match";
                const code = "DOES_NOT_MATCH";

                const twentyFourthOfFeb2023InMs = 1677249836658;
                jest.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs + sevenDaysInMilliseconds) / 1000);

                const event = {
                    body: {
                        code: code,
                        grant_type: "authorization_code",
                        redirect_uri: redirectUri,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent;

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);

                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const mockDynamoDbClientQueryResult: unknown = {
                    Items: [
                        {
                            clientSessionId: "1",
                            authorizationCode: code,
                            redirectUri,
                        },
                    ],
                };

                jest.spyOn(mockDynamoDbClient.prototype, "query").mockReturnValue(
                    mockDynamoDbClientQueryResult as void,
                );

                const sessionItem = {
                    Items: [
                        {
                            sessionId: code,
                            authorizationCodeExpiryDate: expiry,
                            clientId: "1",
                            clientSessionId: "1",
                            redirectUri: "http://does-not-match",
                            accessToken: "",
                            accessTokenExpiryDate: expiry,
                            authorizationCode: code,
                        } as SessionItem,
                    ],
                } as unknown as QueryCommandInput;

                const impl = () => {
                    const mockPromise = new Promise<unknown>((resolve) => {
                        resolve(sessionItem);
                    });
                    return jest.fn().mockImplementation(() => {
                        return mockPromise;
                    });
                };
                mockDynamoDbClient.prototype.query = impl();

                const output = await accessTokenLambda.handler(event, null);
                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(400);
                expect(body.message).toContain(`redirect uri ${badUrl} does not match`);
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should error when jwt verify fails", async () => {
                const redirectUri = "http://123.abc.com";

                const twentyFourthOfFeb2023InMs = 1677249836658;
                jest.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs + sevenDaysInMilliseconds) / 1000);

                const event = {
                    body: {
                        code: "123abc",
                        grant_type: "authorization_code",
                        redirect_uri: redirectUri,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent;
                const mockDynamoDbClientQueryResult: unknown = {
                    Items: [
                        {
                            clientSessionId: "1",
                            authorizationCode: "123abc",
                            redirectUri,
                        },
                    ],
                };
                const clientConfig = new Map<string, string>();
                clientConfig.set("code", "123abc");
                clientConfig.set("redirectUri", redirectUri);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const sessionItem = {
                    Items: [
                        {
                            sessionId: "1",
                            authorizationCodeExpiryDate: expiry,
                            clientId: "1",
                            clientSessionId: "1",
                            redirectUri: redirectUri,
                            accessToken: "",
                            accessTokenExpiryDate: expiry,
                            authorizationCode: "1",
                        } as SessionItem,
                    ],
                } as unknown as QueryCommandInput;

                const impl = () => {
                    const mockPromise = new Promise<unknown>((resolve) => {
                        resolve(sessionItem);
                    });
                    return jest.fn().mockImplementation(() => {
                        return mockPromise;
                    });
                };
                mockDynamoDbClient.prototype.query = impl();

                jest.spyOn(mockDynamoDbClient.prototype, "query").mockReturnValue(
                    mockDynamoDbClientQueryResult as void,
                );
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<null>((resolve) => {
                        resolve(null);
                    }),
                );
                const output = await accessTokenLambda.handler(event, null);
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
                const redirectUri = "http://123.abc.com";
                const code = "123abc";

                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<JWTPayload>((resolve) => {
                        resolve(expect.anything());
                    }),
                );

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const sessionItem = {
                    Items: [],
                } as unknown as QueryCommandInput;

                const impl = () => {
                    const mockPromise = new Promise<unknown>((resolve) => {
                        resolve(sessionItem);
                    });
                    return jest.fn().mockImplementation(() => {
                        return mockPromise;
                    });
                };
                mockDynamoDbClient.prototype.query = impl();

                const output = await accessTokenLambda.handler(
                    {
                        body: {
                            code,
                            grant_type: "authorization_code",
                            redirect_uri: redirectUri,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    } as unknown as APIGatewayProxyEvent,
                    null,
                );

                expect(output.statusCode).toBe(403);
                expect(output.body).toContain("Access token expired");
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should return http 403 if the authorizationCodeExpiryDate has expired", async () => {
                const redirectUri = "http://123.abc.com";
                const code = "123abc";

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const twentyFourthOfFeb2023InMs = 1677249836658;
                jest.spyOn(Date, "now").mockReturnValue(twentyFourthOfFeb2023InMs);
                const sevenDaysInMilliseconds = 7 * 24 * 60 * 60 * 1000;
                const expiry = Math.floor((twentyFourthOfFeb2023InMs - sevenDaysInMilliseconds) / 1000);

                const sessionItem = {
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
                        } as SessionItem,
                    ],
                } as unknown as QueryCommandOutput;

                mockDynamoDbClient.prototype.query.mockImplementation(() => {
                    return new Promise<JWTPayload>((resolve) => {
                        resolve(sessionItem);
                    });
                });

                const output = await accessTokenLambda.handler(
                    {
                        body: {
                            code,
                            grant_type: "authorization_code",
                            redirect_uri: redirectUri,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    } as unknown as APIGatewayProxyEvent,
                    null,
                );

                expect(output.statusCode).toBe(403);
                expect(output.body).toContain("Authorization code expired");
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should return http 403 when there is more than 1 session item", async () => {
                const redirectUri = "http://123.abc.com";
                const code = "123abc";

                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<JWTPayload>((resolve) => {
                        resolve(expect.anything());
                    }),
                );

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const sessionItem = {
                    Items: [{}, {}],
                } as unknown as QueryCommandInput;

                const impl = () => {
                    const mockPromise = new Promise<unknown>((resolve) => {
                        resolve(sessionItem);
                    });
                    return jest.fn().mockImplementation(() => {
                        return mockPromise;
                    });
                };
                mockDynamoDbClient.prototype.query = impl();

                const output = await accessTokenLambda.handler(
                    {
                        body: {
                            code,
                            grant_type: "authorization_code",
                            redirect_uri: redirectUri,
                            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            client_assertion: "2",
                        },
                    } as unknown as APIGatewayProxyEvent,
                    null,
                );

                expect(output.statusCode).toBe(403);
                expect(output.body).toContain("Access token expired");
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });

            it("should fail when dynamoDb is not available", async () => {
                const redirectUri = "http://123.abc.com";
                const code = "123abc";

                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<JWTPayload>((resolve) => {
                        resolve(expect.anything());
                    }),
                );

                jest.spyOn(sessionService, "getSessionByAuthorizationCode").mockReturnValue(
                    Promise.reject(new ServerError()),
                );

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const event = {
                    body: {
                        code,
                        grant_type: "authorization_code",
                        redirect_uri: redirectUri,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent;
                const output = await accessTokenLambda.handler(event, null);
                expect(output.statusCode).toBe(500);
                expect(loggerSpy).toHaveBeenCalledWith(
                    "Access Token Lambda error occurred: Server error",
                    Error("Server error"),
                );
                expect(metricsSpy).toHaveBeenCalledWith("accesstoken", MetricUnits.Count, 0);
            });
        });
    });
});
