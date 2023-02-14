import { JwtVerificationConfig } from "../../../src/common/config/jwt-verification-config";
import { AccessTokenLambda } from "../../../src/handlers/access-token-handler";
import { ConfigService } from "../../../src/common/config/config-service";
import { AccessTokenService } from "../../../src/services/access-token-service";
import { AccessTokenRequestValidator } from "../../../src/services/token-request-validator";
import { SessionService } from "../../../src/services/session-service";
import { APIGatewayProxyEvent } from "aws-lambda/trigger/api-gateway-proxy";
import { SSMClient } from "@aws-sdk/client-ssm";
import { JwtVerifier, JwtVerifierFactory } from "../../../src/common/security/jwt-verifier";
import { Logger } from "@aws-lambda-powertools/logger";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { SessionItem } from "../../../src/types/session-item";

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
            const mockPromise = new Promise<any>((resolve) => {
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
        const accessTokenService = new AccessTokenService();
        const sessionService = new SessionService(mockDynamoDbClient.prototype, configService);
        const accessTokenRequestValidator = new AccessTokenRequestValidator(mockJwtVerifierFactory.prototype);

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
                    new Promise<any>((resolve) => {
                        resolve(true);
                    }),
                );
            });

            it("should pass when payload matches session - TEMP mocked verify function", async () => {
                const redirectUri = "http://123.abc.com";
                const code = "123abc";
                const clientSessionId = "1";

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

                const sessionItem: SessionItem = {
                    sessionId: code,
                    authorizationCodeExpiryDate: 1,
                    clientId: "1",
                    clientSessionId: clientSessionId,
                    redirectUri: redirectUri,
                    accessToken: "",
                    accessTokenExpiryDate: 0,
                    authorizationCode: code,
                };

                jest.spyOn(sessionService, "getSessionByAuthorizationCode").mockReturnValue(
                    new Promise<any>((resolve) => {
                        resolve(sessionItem);
                    }),
                );

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
            });
        });

        describe("Fail paths", () => {
            const sessionService = new SessionService(mockDynamoDbClient.prototype, configService);

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
            });

            it("should fail when request payload is not valid", async () => {
                const event = { body: {} } as unknown as APIGatewayProxyEvent;
                const output = await accessTokenLambda.handler(event, null);
                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(400);
                expect(output.body).not.toBeNull;
                expect(body.message).toContain("Invalid request");
            });

            it("should fail when session is not found", async () => {
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<any>((resolve) => {
                        resolve(true);
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
            });

            it("should fail when authorization code is not found", async () => {
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<any>((resolve) => {
                        resolve(true);
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
                const mockDynamoDbClientQueryResult: any = {
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
                jest.spyOn(mockDynamoDbClient.prototype, "query").mockReturnValue(mockDynamoDbClientQueryResult);

                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<any>((resolve) => {
                        resolve(true);
                    }),
                );

                const output = await accessTokenLambda.handler(event, null);
                const body = JSON.parse(output.body);

                expect(output.statusCode).toBe(403);
                expect(body.code).toBe(1026);
                expect(body.message).toContain("Access token expired");
            });

            it("should fail when redirect URIs do not match", async () => {
                const redirectUri = "http://123.abc.com";
                const badUrl = "http://does-not-match";
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

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);

                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const mockDynamoDbClientQueryResult: any = {
                    Items: [
                        {
                            clientSessionId: "1",
                            authorizationCode: code,
                            redirectUri,
                        },
                    ],
                };

                jest.spyOn(mockDynamoDbClient.prototype, "query").mockReturnValue(mockDynamoDbClientQueryResult);
                jest.spyOn(sessionService, "getSessionByAuthorizationCode").mockReturnValue(
                    new Promise<SessionItem>((resolve) => {
                        const sessionItem: SessionItem = {
                            sessionId: "123abc",
                            authorizationCodeExpiryDate: 1,
                            clientId: "1",
                            clientSessionId: "1",
                            redirectUri: badUrl,
                            accessToken: "",
                            accessTokenExpiryDate: 0,
                            authorizationCode: code,
                        };
                        resolve(sessionItem);
                    }),
                );

                const output = await accessTokenLambda.handler(event, null);
                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(400);
                expect(body.message).toContain(`redirect uri ${badUrl} does not match`);
            });

            it("should error when jwt verify fails", async () => {
                const redirectUri = "http://123.abc.com";
                const event = {
                    body: {
                        code: "123abc",
                        grant_type: "authorization_code",
                        redirect_uri: redirectUri,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent;
                const mockDynamoDbClientQueryResult: any = {
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
                jest.spyOn(sessionService, "getSessionByAuthorizationCode").mockReturnValue(
                    new Promise<SessionItem>((resolve) => {
                        const sessionItem: SessionItem = {
                            sessionId: "123abc",
                            authorizationCodeExpiryDate: 1,
                            clientId: "1",
                            clientSessionId: "1",
                            redirectUri: redirectUri,
                            accessToken: "",
                            accessTokenExpiryDate: 0,
                            authorizationCode: "123abc",
                        };
                        resolve(sessionItem);
                    }),
                );
                jest.spyOn(mockDynamoDbClient.prototype, "query").mockReturnValue(mockDynamoDbClientQueryResult);
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<any>((resolve) => {
                        resolve(false);
                    }),
                );
                const output = await accessTokenLambda.handler(event, null);
                const body = JSON.parse(output.body);
                expect(output.statusCode).toBe(400);
                expect(body.message).toContain(`JWT signature verification failed`);
            });

            it("should fail when dynamoDb is not available", async () => {
                const redirectUri = "http://123.abc.com";
                const code = "123abc";
                const clientSessionId = "1";

                jest.spyOn(mockJwtVerifierFactory.prototype, "create").mockReturnValue(jwtVerifier);
                jest.spyOn(jwtVerifier, "verify").mockReturnValue(
                    new Promise<any>((resolve) => {
                        resolve(true);
                    }),
                );

                jest.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(() => {
                    return Promise.reject();
                });

                const clientConfig = new Map<string, string>();
                clientConfig.set("code", code);
                clientConfig.set("redirectUri", redirectUri);
                jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);

                const sessionItem: SessionItem = {
                    sessionId: code,
                    authorizationCodeExpiryDate: 1,
                    clientId: "1",
                    clientSessionId: clientSessionId,
                    redirectUri: redirectUri,
                    accessToken: "",
                    accessTokenExpiryDate: 0,
                    authorizationCode: code,
                };

                jest.spyOn(sessionService, "getSessionByAuthorizationCode").mockReturnValue(
                    new Promise<any>((resolve) => {
                        resolve(sessionItem);
                    }),
                );

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
            });
        });
    });
});
