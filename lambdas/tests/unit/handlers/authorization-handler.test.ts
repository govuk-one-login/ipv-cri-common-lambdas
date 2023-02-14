import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { AuthorizationLambda } from "../../../src/handlers/authorization-handler";
import { ConfigService } from "../../../src/common/config/config-service";
import { SSMClient } from "@aws-sdk/client-ssm";
import { SessionService } from "../../../src/services/session-service";
import { AuthorizationRequestValidator } from "../../../src/services/auth-request-validator";
import { SessionItem } from "../../../src/types/session-item";
import {
    APIGatewayProxyEvent,
    APIGatewayProxyEventHeaders,
    APIGatewayProxyEventQueryStringParameters,
} from "aws-lambda/trigger/api-gateway-proxy";

jest.mock("../../../src/common/config/config-service");
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

describe("authorization-handler.ts", () => {
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
        let authorizationHandlerLambda: AuthorizationLambda;
        const configService = new ConfigService(jest.fn() as unknown as SSMClient);
        const sessionService = new SessionService(mockDynamoDbClient.prototype, configService);
        const authorizationRequestValidator = new AuthorizationRequestValidator();
        const mockConfigService = jest.mocked(ConfigService);

        beforeEach(() => {
            jest.resetAllMocks();
            configService.init = () => Promise.resolve();
            authorizationHandlerLambda = new AuthorizationLambda(sessionService, authorizationRequestValidator);
            const sessionItem: SessionItem = {
                sessionId: "abc",
                authorizationCodeExpiryDate: 1,
                clientId: "1",
                clientSessionId: "1",
                redirectUri: "http://123.com",
                accessToken: "",
                accessTokenExpiryDate: 0,
                authorizationCode: "abc",
            };
            jest.spyOn(sessionService, "getSession").mockReturnValue(
                new Promise<any>((resolve) => {
                    resolve(sessionItem);
                }),
            );
            const clientConfig = new Map<string, string>();
            clientConfig.set("code", "abc");
            clientConfig.set("redirectUri", "http://123.com");
            jest.spyOn(mockConfigService.prototype, "getClientConfig").mockReturnValue(clientConfig);
        });

        it("should fail when the response_type is missing", async () => {
            const body = {
                code: "",
                grant_type: "authorization_code",
                redirect_uri: "",
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion: "2",
            };

            const headers = {
                "session-id": "1",
            } as APIGatewayProxyEventHeaders;

            const queryString = {
                client_id: "1",
                redirect_url: "http://123.com",
            } as APIGatewayProxyEventQueryStringParameters;

            const output = await authorizationHandlerLambda.handler(
                {
                    body: body,
                    headers: headers,
                    queryStringParameters: queryString,
                } as unknown as APIGatewayProxyEvent,
                null,
            );

            expect(output.statusCode).toBe(400);
            expect(output.body).toContain("Session Validation Exception");
        });

        it("should fail when the redirect_uri is missing", async () => {
            const body = {
                code: "",
                grant_type: "authorization_code",
                redirect_uri: "",
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion: "2",
            };

            const headers = {
                "session-id": "1",
            } as APIGatewayProxyEventHeaders;

            const queryString = {
                client_id: "1",
                response_type: "test",
            } as APIGatewayProxyEventQueryStringParameters;

            const output = await authorizationHandlerLambda.handler(
                {
                    body: body,
                    headers: headers,
                    queryStringParameters: queryString,
                } as unknown as APIGatewayProxyEvent,
                null,
            );

            expect(output.statusCode).toBe(400);
            expect(output.body).toContain("Session Validation Exception");
        });

        it("should fail when the client_id is missing", async () => {
            const body = {
                code: "",
                grant_type: "authorization_code",
                redirect_uri: "",
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion: "2",
            };

            const headers = {
                "session-id": "1",
            } as APIGatewayProxyEventHeaders;

            const queryString = {
                redirect_uri: "http://123.com",
                response_type: "test",
            } as APIGatewayProxyEventQueryStringParameters;

            const output = await authorizationHandlerLambda.handler(
                {
                    body: body,
                    headers: headers,
                    queryStringParameters: queryString,
                } as unknown as APIGatewayProxyEvent,
                null,
            );

            expect(output.statusCode).toBe(400);
            expect(output.body).toContain("Session Validation Exception");
        });

        it("should pass with all queryStringParameters parameters populated", async () => {
            const body = {
                code: "",
                grant_type: "authorization_code",
                redirect_uri: "",
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion: "2",
            };

            const headers = {
                "session-id": "1",
            } as APIGatewayProxyEventHeaders;

            const queryString = {
                client_id: "1",
                redirect_uri: "http://123.com",
                response_type: "test",
            } as APIGatewayProxyEventQueryStringParameters;

            const output = await authorizationHandlerLambda.handler(
                {
                    body: body,
                    headers: headers,
                    queryStringParameters: queryString,
                } as unknown as APIGatewayProxyEvent,
                null,
            );

            expect(output.statusCode).toBe(200);
            expect(output.body).not.toBeNull();
        });

        it("should should fail when there is no session-id", async () => {
            const output = await authorizationHandlerLambda.handler(
                {
                    body: {
                        code: "",
                        grant_type: "authorization_code",
                        redirect_uri: "",
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: "2",
                    },
                } as unknown as APIGatewayProxyEvent,
                null,
            );
            expect(output.statusCode).toBe(400);
            expect(output.body).toContain("Invalid request: Missing session-id header");
        });
    });
});
