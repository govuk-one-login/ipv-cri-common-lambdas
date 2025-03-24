import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { CallbackLambdaHandler } from "../src/callback-handler";
import { CallBackService } from "../src/services/callback-service";
import { ConfigurationHelper } from "../src/services/configuration-helper";
import * as KeyJwtHelper from "../src/services/private-key-jwt-helper";
import { SessionItem } from "../src/services/session-item";
jest.mock("../src/services/callback-service");
jest.mock("../src/services/configuration-helper");

describe("callback-handler", () => {
    const sessionTableName = "session-common-cri-api";
    const authorizationCode = "an-authorization-code";
    const accessTokenValue = "access_token_value";
    const clientId = "headless-core-stub";
    const audience = "my-audience";
    const redirectUri = "https://test-resources.headless-core-stub.redirect/callback";
    const keyJwtValue =
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=an-authorization-code&grant_type=authorization_code&redirect_uri=https%3A%2F%2Ftest-resources.headless-core-stub.redirect%2Fcallback&client_assertion=fake.jwt.key";

    let getTokenSpy: jest.SpyInstance;
    let getParametersSpy: jest.SpyInstance;
    let issueCredentialSpy: jest.SpyInstance;
    let sessionByAuthorizationCodeSpy: jest.SpyInstance;
    let lambdaHandler: (_event: APIGatewayProxyEvent, _context: Context) => Promise<APIGatewayProxyResult>;

    beforeEach(() => {
        const callbackHandler = new CallbackLambdaHandler();
        lambdaHandler = callbackHandler.handler.bind(callbackHandler);
    });
    afterEach(() => jest.clearAllMocks());

    it("returns 200 when entire flow is successful", async () => {
        sessionByAuthorizationCodeSpy = jest
            .spyOn(CallBackService.prototype, "getSessionByAuthorizationCode")
            .mockResolvedValueOnce({ clientId, redirectUri } as SessionItem);

        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);

        getParametersSpy = jest.spyOn(ConfigurationHelper.prototype, "getParameters").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        getTokenSpy = jest.spyOn(CallBackService.prototype, "getToken").mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ access_token: accessTokenValue }),
        } as Response);
        issueCredentialSpy = jest.spyOn(CallBackService.prototype, "callIssueCredential").mockResolvedValueOnce({
            ok: true,
            status: 200,
            text: async () => "vc.jwt.credential",
        } as Response);

        const response = await lambdaHandler(
            {
                queryStringParameters: { authorizationCode },
            } as unknown as APIGatewayProxyEvent,
            {} as Context,
        );

        expect(getParametersSpy).toHaveBeenCalledWith(clientId);
        expect(getTokenSpy).toHaveBeenCalledWith("my-audience/token", keyJwtValue);
        expect(issueCredentialSpy).toHaveBeenCalledWith("my-audience/credential/issue", "access_token_value");
        expect(sessionByAuthorizationCodeSpy).toHaveBeenLastCalledWith("session-common-cri-api", authorizationCode);
        expect(response).toEqual({
            statusCode: 200,
            headers: {
                "Content-Type": "application/jwt",
            },
            body: "vc.jwt.credential",
        });
    });

    it("returns 404 if session is not found", async () => {
        sessionByAuthorizationCodeSpy = jest
            .spyOn(CallBackService.prototype, "getSessionByAuthorizationCode")
            .mockRejectedValueOnce(new Error("No session item found for provided authorizationCode"));

        const event: Partial<APIGatewayProxyEvent> = { queryStringParameters: { authorizationCode } };
        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(sessionByAuthorizationCodeSpy).toHaveBeenCalledWith(sessionTableName, authorizationCode);
        expect(response).toEqual({
            statusCode: 500,
            body: "No session item found for provided authorizationCode",
        });
    });

    it("handles token endpoint failure gracefully", async () => {
        const event: Partial<APIGatewayProxyEvent> = {
            queryStringParameters: {
                authorizationCode,
            },
        };
        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);

        sessionByAuthorizationCodeSpy = jest
            .spyOn(CallBackService.prototype, "getSessionByAuthorizationCode")
            .mockResolvedValueOnce({
                clientId,
                redirectUri,
            } as SessionItem);
        getParametersSpy = jest.spyOn(ConfigurationHelper.prototype, "getParameters").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        getTokenSpy = jest
            .spyOn(CallBackService.prototype, "getToken")
            .mockResolvedValueOnce({ ok: false, status: 500, text: async () => "mock-token-error" } as Response);

        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(sessionByAuthorizationCodeSpy).toHaveBeenCalledWith(sessionTableName, authorizationCode);
        expect(getParametersSpy).toHaveBeenCalledWith(clientId);
        expect(response.statusCode).toBe(500);
        expect(response.body).toBe("mock-token-error");
    });

    it("handles credential endpoint failure gracefully", async () => {
        const event: Partial<APIGatewayProxyEvent> = {
            queryStringParameters: {
                authorizationCode,
            },
        };

        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);
        sessionByAuthorizationCodeSpy = jest
            .spyOn(CallBackService.prototype, "getSessionByAuthorizationCode")
            .mockResolvedValueOnce({ clientId, redirectUri } as SessionItem);
        getParametersSpy = jest.spyOn(ConfigurationHelper.prototype, "getParameters").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        getTokenSpy = jest.spyOn(CallBackService.prototype, "getToken").mockResolvedValueOnce({
            ok: true,
            json: async () => ({ access_token: accessTokenValue }),
        } as Response);
        issueCredentialSpy = jest.spyOn(CallBackService.prototype, "callIssueCredential").mockResolvedValueOnce({
            ok: false,
            status: 500,
            text: async () => "mock-credential-error",
        } as Response);

        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(sessionByAuthorizationCodeSpy).toHaveBeenCalledWith(sessionTableName, authorizationCode);
        expect(getParametersSpy).toHaveBeenCalledWith(clientId);
        expect(issueCredentialSpy).toHaveBeenCalledWith(expect.any(String), accessTokenValue);
        expect(response.statusCode).toBe(500);
        expect(response.body).toBe("mock-credential-error");
    });
});
