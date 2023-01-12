jest.mock("../../src/services/config-service");
jest.mock("../../src/lib/dynamo-db-client");
jest.mock("../../src/services/jwt-verifier"); // Todo: properly implement/mock Jose
jest.mock("@aws-lambda-powertools/metrics");
jest.mock("@aws-lambda-powertools/logger");

import { AccessTokenLambda } from "../../src/app";
import { ConfigService } from "../../src/services/config-service";
import { AccessTokenService } from "../../src/services/access-token-service";
import { AccessTokenRequestValidator } from "../../src/services/token-request-validator";
import { SessionService } from "../../src/services/session-service";
import { DynamoDbClient } from "../../src/lib/dynamo-db-client";
import { APIGatewayProxyEvent } from "aws-lambda/trigger/api-gateway-proxy";
import { SSMClient } from "@aws-sdk/client-ssm";
import { JwtVerifier } from "../../src/services/jwt-verifier";

describe("Handler", () => {
    let accessTokenLambda: AccessTokenLambda;

    const configService = new ConfigService(jest.fn() as unknown as SSMClient);
    const jwtVerifier = new JwtVerifier(configService);
    const accessTokenService = new AccessTokenService();
    const sessionService = new SessionService(DynamoDbClient, configService);
    const accessTokenRequestValidator = new AccessTokenRequestValidator(configService, jwtVerifier);

    const mockDynamoDbClient = jest.mocked(DynamoDbClient);
    const mockJwtVerifier = jest.mocked(JwtVerifier);
    const mockConfigService = jest.mocked(ConfigService);

    beforeEach(() => {
        jest.clearAllMocks();

        configService.init = () => Promise.resolve([]);

        accessTokenLambda = new AccessTokenLambda(accessTokenService, sessionService, accessTokenRequestValidator);
    });

    describe("success paths", () => {
        it("should pass when payload matches session - TEMP mocked verify function", async () => {
            const redirectUri = "http://123.abc.com";
            const code = "123abc";
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const mockDynamoDbClientQueryResult: any = {
                Items: [
                    {
                        clientSessionId: "1",
                        authorizationCode: code,
                        redirectUri,
                    },
                ],
            };

            mockDynamoDbClient.query.mockReturnValueOnce(mockDynamoDbClientQueryResult);
            mockConfigService.prototype.getRedirectUri.mockReturnValueOnce(redirectUri);
            mockConfigService.prototype.getJwtAudience.mockResolvedValueOnce("audience")
            mockJwtVerifier.prototype.verify.mockResolvedValueOnce({jti: "something"});
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
            //todo expand
        });
    });

    describe("Fail paths", () => {
        it("should fail when no body is passed in the request", async () => {
            const event = {} as unknown as APIGatewayProxyEvent;
            const output = await accessTokenLambda.handler(event, null);
            expect(output.statusCode).toBe(400);
            expect(output.body).not.toBeNull;
            const body = JSON.parse(output.body);
            expect(body.message).toContain("missing body");
        });

        it("should fail when request payload is not valid", async () => {
            const event = { body: {} } as unknown as APIGatewayProxyEvent;
            const output = await accessTokenLambda.handler(event, null);
            expect(output.statusCode).toBe(400);
            expect(output.body).not.toBeNull;
            const body = JSON.parse(output.body);
            expect(body.message).toContain("Invalid client_assertion parameter");
        });

        it("should fail when session is not found", async () => {
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

            const mockDynamoDbClientQueryResult: any = {
                Items: [],
            };

            mockDynamoDbClient.query.mockReturnValueOnce(mockDynamoDbClientQueryResult);
            const output = await accessTokenLambda.handler(event, null);
            expect(output.statusCode).toBe(403);
            expect(output.body).not.toBeNull;
            const body = JSON.parse(output.body);
            expect(body.message).toContain("Access token expired")
        });

        it("should fail when authorization code is not found", async () => {
            const redirectUri = "http://123.abc.com";
            const event = {
                body: {
                    code: "DOES_NOT_MATCH",
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

            mockConfigService.prototype.getRedirectUri.mockReturnValueOnce(redirectUri);
            mockConfigService.prototype.getJwtAudience.mockResolvedValueOnce("audience")
            mockJwtVerifier.prototype.verify.mockResolvedValueOnce({jti: "something"});

            mockDynamoDbClient.query.mockReturnValueOnce(mockDynamoDbClientQueryResult);
            const output = await accessTokenLambda.handler(event, null);
            expect(output.statusCode).toBe(403);
            const body = JSON.parse(output.body);
            expect(body.code).toBe(1026)
            expect(body.message).toContain("Access token expired");
            expect(body.errorSummary).toBe("1026: Access token expired");
        });

        it("should fail when redirect URIs do not match", async () => {
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

            mockConfigService.prototype.getRedirectUri.mockReturnValueOnce("http://DOES_NOT_MATCH");
            mockConfigService.prototype.getJwtAudience.mockResolvedValueOnce("audience")
            mockJwtVerifier.prototype.verify.mockResolvedValueOnce({jti: "something"});

            mockDynamoDbClient.query.mockReturnValueOnce(mockDynamoDbClientQueryResult);
            const output = await accessTokenLambda.handler(event, null);
            expect(output.statusCode).toBe(400);
            const body = JSON.parse(output.body);
            expect(body.message).toContain(`redirect uri ${redirectUri} does not match`);
        });

        it("should fail when audience is not found", async () => {
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

            mockDynamoDbClient.query.mockReturnValueOnce(mockDynamoDbClientQueryResult);
            const output = await accessTokenLambda.handler(event, null);
            expect(output.statusCode).toBe(400);
            const body = JSON.parse(output.body);
            expect(body.message).toContain(`audience is missing`);
        });

        it("should fail when jti is not found", async () => {
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

            mockConfigService.prototype.getJwtAudience.mockResolvedValueOnce("audience")
            mockJwtVerifier.prototype.verify.mockResolvedValueOnce({});

            mockDynamoDbClient.query.mockReturnValueOnce(mockDynamoDbClientQueryResult);
            const output = await accessTokenLambda.handler(event, null);
            expect(output.statusCode).toBe(400);
            const body = JSON.parse(output.body);
            expect(body.message).toContain(`jti is missing`);
        });

        it.todo("should fail when access token validation fails");
        it.todo("should fail when dynamoDb is not available");
        it.todo("should fail when SSM is not available");
    });
});
