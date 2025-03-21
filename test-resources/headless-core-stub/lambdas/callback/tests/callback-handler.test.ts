import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { CallbackLambdaHandler } from "../src/callback-handler";
import { CallBackService } from "../src/services/callback-service";
import { ConfigurationHelper } from "../src/services/configuration-helper";
import { TestKeys } from "./test_keys";

describe("callback-handler", () => {
    const sessionTableName = "session-common-cri-api";
    const authorizationCode = "an-authorization-code";
    const accessTokenValue = "access_token_value";
    const clientId = "headless-core-stub";
    const redirectUri = "https://test-resources.headless-core-stub.redirect/callback";

    let mockSessionByAuthorizationCode: jest.Mock;
    let mockGetParameters: jest.Mock;
    let mockGetToken: jest.Mock;
    let mockIssueCredential: jest.Mock;

    let lambdaHandler: (_event: APIGatewayProxyEvent, _context: Context) => Promise<APIGatewayProxyResult>;

    beforeEach(() => {
        mockSessionByAuthorizationCode = jest.fn();
        mockGetParameters = jest.fn();
        mockGetToken = jest.fn();
        mockIssueCredential = jest.fn();

        const mockCallbackService = {
            getSessionByAuthorizationCode: mockSessionByAuthorizationCode,
            getToken: mockGetToken,
            issueCredential: mockIssueCredential,
        } as Partial<CallBackService>;

        const mockConfigHelper = {
            getParameters: mockGetParameters,
        } as Partial<ConfigurationHelper>;

        const callbackHandler = new CallbackLambdaHandler(
            mockConfigHelper as ConfigurationHelper,
            mockCallbackService as CallBackService,
        );
        lambdaHandler = callbackHandler.handler.bind(callbackHandler);
    });

    afterEach(() => jest.clearAllMocks());

    it("returns 200 when entire flow is successfully", async () => {
        mockSessionByAuthorizationCode.mockResolvedValueOnce({
            clientId,
            redirectUri,
        });
        mockGetParameters.mockResolvedValueOnce({
            redirectUri,
            audience: "my-audience",
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify(TestKeys.privateSigningJwk),
        });
        mockGetToken.mockResolvedValueOnce({
            ok: true,
            status: 200,
            text: async () => "200 OK",
            json: async () => ({ access_token: accessTokenValue }),
        });
        mockIssueCredential.mockResolvedValueOnce({
            ok: true,
            status: 200,
            text: async () => "vc.jwt.credential",
        });

        const response = await lambdaHandler(
            {
                queryStringParameters: {
                    authorizationCode,
                },
            } as unknown as APIGatewayProxyEvent,
            {} as Context,
        );

        expect(mockSessionByAuthorizationCode).toHaveBeenCalledWith(sessionTableName, authorizationCode);
        expect(mockGetParameters).toHaveBeenCalledWith(clientId);
        expect(mockIssueCredential).toHaveBeenCalledWith(expect.any(String), accessTokenValue);
        expect(response).toEqual({ statusCode: 200, body: "vc.jwt.credential" });
    });

    it("returns 404 if session is not found", async () => {
        mockSessionByAuthorizationCode.mockRejectedValueOnce(
            new Error("No session item found for provided authorizationCode"),
        );

        const event: Partial<APIGatewayProxyEvent> = { queryStringParameters: { authorizationCode } };
        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(mockSessionByAuthorizationCode).toHaveBeenCalledWith(sessionTableName, authorizationCode);
        expect(response).toEqual({
            statusCode: 500,
            body: "No session item found for provided authorizationCode",
        });
    });

    it("returns 400 if authorizationCode is missing", async () => {
        const event: Partial<APIGatewayProxyEvent> = { queryStringParameters: {} };
        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(mockSessionByAuthorizationCode).not.toHaveBeenCalledWith(sessionTableName, authorizationCode);
        expect(response).toEqual({ statusCode: 400, body: "Missing authorization code" });
    });

    it("handles token endpoint failure gracefully", async () => {
        const event: Partial<APIGatewayProxyEvent> = {
            queryStringParameters: {
                authorizationCode,
            },
        };
        mockSessionByAuthorizationCode.mockResolvedValueOnce({
            clientId,
            redirectUri,
        });
        mockGetParameters.mockResolvedValueOnce({
            redirectUri,
            audience: "my-audience",
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify(TestKeys.privateSigningJwk),
        });
        mockGetToken.mockResolvedValueOnce({ ok: false, status: 500, text: async () => "mock-token-error" });

        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(mockSessionByAuthorizationCode).toHaveBeenCalledWith(sessionTableName, authorizationCode);
        expect(mockGetParameters).toHaveBeenCalledWith(clientId);
        expect(response.statusCode).toBe(500);
        expect(response.body).toBe("mock-token-error");
    });

    it("handles credential endpoint failure gracefully", async () => {
        const event: Partial<APIGatewayProxyEvent> = {
            queryStringParameters: {
                authorizationCode,
            },
        };

        mockSessionByAuthorizationCode.mockResolvedValueOnce({ clientId, redirectUri });
        mockGetParameters.mockResolvedValueOnce({
            redirectUri,
            audience: "my-audience",
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify(TestKeys.privateSigningJwk),
        });
        mockGetToken.mockResolvedValue({ ok: true, json: async () => ({ access_token: accessTokenValue }) });
        mockIssueCredential.mockResolvedValueOnce({
            ok: false,
            status: 500,
            text: async () => "mock-credential-error",
        });

        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(mockSessionByAuthorizationCode).toHaveBeenCalledWith(sessionTableName, authorizationCode);
        expect(mockGetParameters).toHaveBeenCalledWith(clientId);
        expect(mockIssueCredential).toHaveBeenCalledWith(expect.any(String), accessTokenValue);
        expect(response.statusCode).toBe(500);
        expect(response.body).toBe("mock-credential-error");
    });
});
