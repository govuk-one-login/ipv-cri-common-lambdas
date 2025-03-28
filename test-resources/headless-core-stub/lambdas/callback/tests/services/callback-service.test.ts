import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { CallBackService } from "../../src/services/callback-service";
import { Logger } from "@aws-lambda-powertools/logger";

global.fetch = jest.fn();
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

describe("CallBack Service", () => {
    const sessionTableName = "session-common-cri-api";
    const authorizationCode = "an-authorization-code";
    const clientId = "headless-core-stub";

    const redirectUri = "https://test-resources.headless-core-stub.redirect/callback";
    let mockSend: jest.Mock;
    let mockLoggerError: jest.Mock;
    let mockLoggerInfo: jest.Mock;
    let mockLoggerWarn: jest.Mock;

    let callbackService: CallBackService;

    beforeEach(() => {
        mockSend = jest.fn();
        mockLoggerError = jest.fn();
        mockLoggerInfo = jest.fn();
        mockLoggerWarn = jest.fn();

        callbackService = new CallBackService(
            { error: mockLoggerError, info: mockLoggerInfo, warn: mockLoggerWarn } as unknown as Logger,
            { send: mockSend } as unknown as DynamoDBClient,
        );
    });
    afterEach(() => jest.clearAllMocks());

    describe("getSessionByAuthorizationCode", () => {
        it("returns a sessionItem when given a valid authorizationCode", async () => {
            mockSend.mockResolvedValueOnce({
                Items: [
                    {
                        clientId: { S: clientId },
                        redirectUri: { S: redirectUri },
                        authorizationCode: { S: authorizationCode },
                    },
                ],
            });

            const sessionItem = await callbackService.getSessionByAuthorizationCode(
                sessionTableName,
                authorizationCode,
            );

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        ExpressionAttributeValues: { ":authorizationCode": { S: authorizationCode } },
                        IndexName: "authorizationCode-index",
                        KeyConditionExpression: "authorizationCode = :authorizationCode",
                        TableName: sessionTableName,
                    },
                }),
            );
            expect(sessionItem).toEqual(
                expect.objectContaining({
                    authorizationCode: "an-authorization-code",
                    clientId: "headless-core-stub",
                    redirectUri: "https://test-resources.headless-core-stub.redirect/callback",
                }),
            );
        });

        it("errors when no sessionItem is found when given an authorizationCode", async () => {
            mockSend.mockResolvedValueOnce({ Count: 0, Items: [] });

            await expect(
                callbackService.getSessionByAuthorizationCode(sessionTableName, authorizationCode),
            ).rejects.toThrow("No session item found for provided authorizationCode");
        });
    });
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

            await expect(callbackService.invokeTokenEndpoint(tokenUrl, requestBody)).rejects.toThrow("Fetch error");

            expect(mockFetch).toHaveBeenCalledWith(tokenUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                },
                body: requestBody,
            });
        });
    });
});
