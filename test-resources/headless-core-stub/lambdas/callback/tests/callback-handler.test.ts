import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { CallbackLambdaHandler } from "../src/callback-handler";
import { CallBackService } from "../src/services/callback-service";
import * as KeyJwtHelper from "../src/services/private-key-jwt-helper";
import { ClientConfiguration } from "../../../utils/src/services/client-configuration";
import { DEFAULT_CLIENT_ID } from "../../../utils/src/constants";

jest.mock("../src/services/callback-service");
jest.mock("../../../utils/src/services/client-configuration");

jest.spyOn(CallBackService.prototype, "fetchApiKeyValue").mockReturnValue(Promise.resolve("test-api-key"));

describe("callback-handler", () => {
    const authorizationCode = "an-authorization-code";
    const accessTokenValue = "access_token_value";
    const audience = "https://my-audience.example.com";
    const redirectUri = "https://test-resources.headless-core-stub.redirect/callback";
    const keyJwtValue =
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=an-authorization-code&grant_type=authorization_code&redirect_uri=https%3A%2F%2Ftest-resources.headless-core-stub.redirect%2Fcallback&client_assertion=fake.jwt.key";

    let getTokenSpy: jest.SpyInstance;
    let getParametersSpy: jest.SpyInstance;
    let issueCredentialSpy: jest.SpyInstance;
    let lambdaHandler: (_event: APIGatewayProxyEvent, _context: Context) => Promise<APIGatewayProxyResult>;

    beforeEach(() => {
        const callbackHandler = new CallbackLambdaHandler();
        lambdaHandler = callbackHandler.handler.bind(callbackHandler);
    });
    afterEach(() => jest.clearAllMocks());

    it("returns 200 when entire flow is successful", async () => {
        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);

        getParametersSpy = jest.spyOn(ClientConfiguration, "getConfig").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        getTokenSpy = jest.spyOn(CallBackService.prototype, "invokeTokenEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: JSON.stringify({ access_token: accessTokenValue }),
        });
        issueCredentialSpy = jest.spyOn(CallBackService.prototype, "invokeCredentialEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: "vc.jwt.credential",
        });

        const response = await lambdaHandler(
            {
                queryStringParameters: { code: authorizationCode },
            } as unknown as APIGatewayProxyEvent,
            {} as Context,
        );

        expect(getParametersSpy).toHaveBeenCalledWith(DEFAULT_CLIENT_ID);
        expect(getTokenSpy).toHaveBeenCalledWith("https://my-audience.example.com/token", keyJwtValue);
        expect(issueCredentialSpy).toHaveBeenCalledWith(
            "https://my-audience.example.com/credential/issue",
            "access_token_value",
        );
        expect(response).toEqual({
            statusCode: 200,
            headers: {
                "Content-Type": "text/plain",
            },
            body: "vc.jwt.credential",
        });
    });

    it("uses client_id from request params if provided", async () => {
        const clientIdOverride = "test-client-id";

        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);

        getParametersSpy = jest.spyOn(ClientConfiguration, "getConfig").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        getTokenSpy = jest.spyOn(CallBackService.prototype, "invokeTokenEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: JSON.stringify({ access_token: accessTokenValue }),
        });
        issueCredentialSpy = jest.spyOn(CallBackService.prototype, "invokeCredentialEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: "vc.jwt.credential",
        });

        const response = await lambdaHandler(
            {
                queryStringParameters: { code: authorizationCode, client_id: clientIdOverride },
            } as unknown as APIGatewayProxyEvent,
            {} as Context,
        );

        expect(getParametersSpy).toHaveBeenCalledWith(clientIdOverride);
        expect(getTokenSpy).toHaveBeenCalledWith("https://my-audience.example.com/token", keyJwtValue);
        expect(issueCredentialSpy).toHaveBeenCalledWith(
            "https://my-audience.example.com/credential/issue",
            "access_token_value",
        );
        expect(response).toEqual({
            statusCode: 200,
            headers: {
                "Content-Type": "text/plain",
            },
            body: "vc.jwt.credential",
        });
    });

    it("uses state from request params if provided", async () => {
        // This is { aud: "https://audience-override.example.com", redirect_uri: "redirect-uri-override" } encoded
        const stateOverride =
            "eyJhdWQiOiJodHRwczovL2F1ZGllbmNlLW92ZXJyaWRlLmV4YW1wbGUuY29tIiwicmVkaXJlY3RfdXJpIjoicmVkaXJlY3QtdXJpLW92ZXJyaWRlIn0="; // pragma: allowlist secret

        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);

        getParametersSpy = jest.spyOn(ClientConfiguration, "getConfig").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        getTokenSpy = jest.spyOn(CallBackService.prototype, "invokeTokenEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: JSON.stringify({ access_token: accessTokenValue }),
        });
        issueCredentialSpy = jest.spyOn(CallBackService.prototype, "invokeCredentialEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: "vc.jwt.credential",
        });

        const response = await lambdaHandler(
            {
                queryStringParameters: { code: authorizationCode, state: stateOverride },
            } as unknown as APIGatewayProxyEvent,
            {} as Context,
        );

        expect(getParametersSpy).toHaveBeenCalledWith(DEFAULT_CLIENT_ID);
        expect(getTokenSpy).toHaveBeenCalledWith("https://audience-override.example.com/token", keyJwtValue);
        expect(issueCredentialSpy).toHaveBeenCalledWith(
            "https://audience-override.example.com/credential/issue",
            "access_token_value",
        );
        expect(response).toEqual({
            statusCode: 200,
            headers: {
                "Content-Type": "text/plain",
            },
            body: "vc.jwt.credential",
        });
    });

    it("handles token endpoint failure gracefully", async () => {
        const event: Partial<APIGatewayProxyEvent> = {
            queryStringParameters: {
                code: authorizationCode,
            },
        };
        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);

        getParametersSpy = jest.spyOn(ClientConfiguration, "getConfig").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        getTokenSpy = jest.spyOn(CallBackService.prototype, "invokeTokenEndpoint").mockRejectedValueOnce(
            new Error("failed with 500 status", {
                cause: "No session item found for provided authorizationCode",
            }),
        );

        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(getParametersSpy).toHaveBeenCalledWith(DEFAULT_CLIENT_ID);
        expect(response.statusCode).toBe(500);
        expect(JSON.parse(response.body).message).toBe("Server error");
    });

    it("handles credential endpoint failure gracefully", async () => {
        const event: Partial<APIGatewayProxyEvent> = {
            queryStringParameters: {
                code: authorizationCode,
            },
        };

        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);

        getParametersSpy = jest.spyOn(ClientConfiguration, "getConfig").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        getTokenSpy = jest.spyOn(CallBackService.prototype, "invokeTokenEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: JSON.stringify({ access_token: accessTokenValue }),
        });
        issueCredentialSpy = jest.spyOn(CallBackService.prototype, "invokeCredentialEndpoint").mockResolvedValueOnce({
            statusCode: 500,
            body: "mock-credential-error",
        });

        const response = await lambdaHandler(event as APIGatewayProxyEvent, {} as Context);

        expect(getParametersSpy).toHaveBeenCalledWith(DEFAULT_CLIENT_ID);
        expect(issueCredentialSpy).toHaveBeenCalledWith(expect.any(String), accessTokenValue);
        expect(response.statusCode).toBe(500);
        expect(response.body).toBe("mock-credential-error");
    });

    it("returns a 400 if state is not base64 encoded JSON", async () => {
        // This is "test string" encoded
        const stateOverride = "dGVzdCBzdHJpbmc=";

        jest.spyOn(ClientConfiguration, "getConfig").mockResolvedValueOnce({
            redirectUri,
            audience,
            issuer: "https://issuer.example.com",
            privateSigningKey: JSON.stringify({}),
        });
        jest.spyOn(KeyJwtHelper, "generatePrivateJwtParams").mockResolvedValueOnce(keyJwtValue);

        jest.spyOn(CallBackService.prototype, "invokeTokenEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: JSON.stringify({ access_token: accessTokenValue }),
        });
        jest.spyOn(CallBackService.prototype, "invokeCredentialEndpoint").mockResolvedValueOnce({
            statusCode: 200,
            body: "vc.jwt.credential",
        });

        const response = await lambdaHandler(
            {
                queryStringParameters: { code: authorizationCode, state: stateOverride },
            } as unknown as APIGatewayProxyEvent,
            {} as Context,
        );

        expect(response.statusCode).toBe(400);
        expect(JSON.parse(response.body).message).toBe("State param is not a valid JSON bas64 encoded string");
    });
});
