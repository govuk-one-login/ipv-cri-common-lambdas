import { CallBackService } from "../../src/services/callback-service";
import { Logger } from "@aws-lambda-powertools/logger";
import * as CloudFormation from "../../../../utils/src/stack-outputs";

global.fetch = jest.fn();
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

describe("CallBack Service", () => {
    let mockLoggerError: jest.Mock;
    let mockLoggerInfo: jest.Mock;
    let mockLoggerWarn: jest.Mock;

    let callbackService: CallBackService;

    beforeEach(() => {
        process.env.API_KEY = "test-api-key";

        mockLoggerError = jest.fn();
        mockLoggerInfo = jest.fn();
        mockLoggerWarn = jest.fn();

        spyStackOutputs = jest.spyOn(CloudFormation, "stackOutputs").mockResolvedValue({ ApiKey1: "test-api-key" });

        callbackService = new CallBackService({
            error: mockLoggerError,
            info: mockLoggerInfo,
            warn: mockLoggerWarn,
        } as unknown as Logger);
    });
    afterEach(() => jest.clearAllMocks());

    describe("callTokenEndpoint", () => {
        const accessTokenValue = "mock-access-token";
        it("requests using POST with the correct headers and body succeeds", async () => {
            const mockResponse = {
                body: JSON.stringify({ access_token: accessTokenValue }),
                status: 200,
                ok: true,
                text: async () => "200 OK",
                json: async () => ({ access_token: accessTokenValue }),
            } as unknown as Response;

            mockFetch.mockResolvedValueOnce(mockResponse);

            const tokenUrl = "https://cri-api.host/token";
            const requestBody =
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=an-authorization-code&grant_type=authorization_code&redirect_uri=https%3A%2F%2Ftest-resources.headless-core-stub.redirect%2Fcallback&client_assertion=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJoZWFkbGVzcy1jb3JlLXN0dWIiLCJzdWIiOiJoZWFkbGVzcy1jb3JlLXN0dWIiLCJhdWQiOiJteS1hdWRpZW5jZSIsImV4cCI6MTc0MjU0NjA0NCwianRpIjoiZWI5YjZiYjAtOWE5NC00YWIxLTlkMTYtOTdiMmFlMDdjNzBjIn0.GOfjQV9gerLQ8mTr3ZMouQG7Ri7lyeKdAto2IDovSaVZjEyUYomqIAVhV9xWgBsdsP1OfXTHFNEmPm_PzBA1zg";
            const response = await callbackService.invokeTokenEndpoint(tokenUrl, requestBody);

            expect(mockFetch).toHaveBeenCalledWith(tokenUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                    "x-api-key": "test-api-key",
                },
                body: requestBody,
            });
            expect(response).toEqual({
                body: "200 OK",
                statusCode: 200,
            } as unknown as Response);
        });
        it("handles errors gracefully", async () => {
            mockFetch.mockRejectedValueOnce(new Error("Fetch error"));
            const tokenUrl = "https://cri-api.host/token";
            const requestBody =
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=an-authorization-code&grant_type=authorization_code&redirect_uri=https%3A%2F%2Ftest-resources.headless-core-stub.redirect%2Fcallback&client_assertion=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJoZWFkbGVzcy1jb3JlLXN0dWIiLCJzdWIiOiJoZWFkbGVzcy1jb3JlLXN0dWIiLCJhdWQiOiJteS1hdWRpZW5jZSIsImV4cCI6MTc0MjU0NjA0NCwianRpIjoiZWI5YjZiYjAtOWE5NC00YWIxLTlkMTYtOTdiMmFlMDdjNzBjIn0.GOfjQV9gerLQ8mTr3ZMouQG7Ri7lyeKdAto2IDovSaVZjEyUYomqIAVhV9xWgBsdsP1OfXTHFNEmPm_PzBA1zg";
            process.env.API_KEY = "test-api-key";
            await expect(callbackService.invokeTokenEndpoint(tokenUrl, requestBody)).rejects.toThrow("Fetch error");

            expect(mockFetch).toHaveBeenCalledWith(tokenUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                    "x-api-key": "test-api-key",
                },
                body: requestBody,
            });
        });

        it("handles non-200 response from token endpoint", async () => {
            const mockResponse = {
                status: 400,
                ok: false,
                text: async () => "Bad Request",
                headers: new Map([["content-type", "application/json"]]),
            } as unknown as Response;

            mockFetch.mockResolvedValueOnce(mockResponse);

            const tokenUrl = "https://cri-api.host/token";
            const requestBody = "test-body";

            await expect(callbackService.invokeTokenEndpoint(tokenUrl, requestBody)).rejects.toThrow(
                "Failed with 400 status: Bad Request",
            );

            expect(mockLoggerError).toHaveBeenCalledWith({
                message: "Request to token endpoint failed",
                tokenEndpoint: tokenUrl,
                status: 400,
                responseBody: "Bad Request",
                headers: { "content-type": "application/json" },
            });
        });
    });

    describe("invokeCredentialEndpoint", () => {
        it("requests using POST with correct headers and succeeds", async () => {
            const mockResponse = {
                status: 200,
                ok: true,
                text: async () => JSON.stringify({ credential: "test-credential" }),
            } as unknown as Response;

            mockFetch.mockResolvedValueOnce(mockResponse);

            const credentialUrl = "https://cri-api.host/credential/issue";
            const accessToken = "test-access-token";

            const response = await callbackService.invokeCredentialEndpoint(credentialUrl, accessToken);

            expect(mockFetch).toHaveBeenCalledWith(credentialUrl, {
                method: "POST",
                headers: {
                    Authorization: "Bearer test-access-token",
                    "x-api-key": "test-api-key",
                },
            });
            expect(response).toEqual({
                statusCode: 200,
                body: JSON.stringify({ credential: "test-credential" }),
            });
            expect(mockLoggerInfo).toHaveBeenCalledWith({
                message: "Successfully called /credential/issue endpoint",
            });
        });

        it("handles non-200 response from credential endpoint", async () => {
            const mockResponse = {
                status: 401,
                ok: false,
                text: async () => "Unauthorized",
            } as unknown as Response;

            mockFetch.mockResolvedValueOnce(mockResponse);

            const credentialUrl = "https://cri-api.host/credential/issue";
            const accessToken = "invalid-token";

            const response = await callbackService.invokeCredentialEndpoint(credentialUrl, accessToken);

            expect(response).toEqual({
                statusCode: 401,
                body: "Unauthorized",
            });
            expect(mockLoggerError).toHaveBeenCalledWith({
                message: "Request to credential endpoint failed",
                credentialEndpoint: credentialUrl,
                status: 401,
                responseBody: "Unauthorized",
            });
        });

        it("handles fetch error for credential endpoint", async () => {
            mockFetch.mockRejectedValueOnce(new Error("Network error"));

            const credentialUrl = "https://cri-api.host/credential/issue";
            const accessToken = "test-token";

            await expect(callbackService.invokeCredentialEndpoint(credentialUrl, accessToken)).rejects.toThrow(
                "Network error",
            );
        });
    });
});
