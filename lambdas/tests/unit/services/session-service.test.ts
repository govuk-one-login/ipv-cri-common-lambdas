import { SessionService } from "../../../src/services/session-service";
import { ConfigService } from "../../../src/common/config/config-service";
import { SSMClient } from "@aws-sdk/client-ssm";
import { DynamoDBDocument, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { InvalidAccessTokenError, SessionNotFoundError } from "../../../src/common/utils/errors";
import { SessionItem } from "../../../src/types/session-item";

jest.mock("@aws-sdk/lib-dynamodb", () => {
    return {
        __esModule: true,
        ...jest.requireActual("@aws-sdk/lib-dynamodb"),
        GetCommand: jest.fn(),
        UpdateCommand: jest.fn(),
    };
});

jest.mock("../../../src/common/config/config-service");

describe("session-service", () => {
    let sessionService: SessionService;

    const configService = new ConfigService(jest.fn() as unknown as SSMClient);
    const mockDynamoDbClient = jest.mocked(DynamoDBDocument);
    const mockConfigService = jest.mocked(ConfigService);
    const mockGetCommand = jest.mocked(GetCommand);
    const mockUpdateCommand = jest.mocked(UpdateCommand);

    beforeEach(() => {
        jest.resetAllMocks();
        sessionService = new SessionService(mockDynamoDbClient.prototype, configService);
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

    describe("getSession", () => {
        it("Should return session item", async () => {
            const tableName = "sessionTable";
            const sessionVal = "myItem";
            const sessionId = "1";
            jest.spyOn(mockDynamoDbClient.prototype, "send").mockImplementation(() => {
                return Promise.resolve({
                    Item: sessionVal,
                });
            });
            jest.spyOn(mockConfigService.prototype, "getConfigEntry").mockReturnValue(tableName);
            const output = await sessionService.getSession(sessionId);
            expect(output).toBe("myItem");
            expect(mockGetCommand).toHaveBeenCalled();
            expect(mockGetCommand).toHaveBeenCalledWith({ TableName: tableName, Key: { sessionId: sessionId } });
            expect(mockDynamoDbClient.prototype.send).toHaveBeenCalled();
        });

        it("Should throw session item not found when session not found", async () => {
            expect.assertions(3);
            try {
                const tableName = "sessionTable";
                const sessionId = "1";
                jest.spyOn(mockDynamoDbClient.prototype, "send").mockImplementation(() => {
                    return Promise.resolve({});
                });
                jest.spyOn(mockConfigService.prototype, "getConfigEntry").mockReturnValue(tableName);
                await sessionService.getSession(sessionId);
            } catch (err) {
                expect(mockGetCommand).toHaveBeenCalled();
                expect(mockDynamoDbClient.prototype.send).toHaveBeenCalled();
                expect(err).toBeInstanceOf(SessionNotFoundError);
            }
        });
    });

    describe("createAuthorizationCode", () => {
        it("should call the update command with the a payload that includes ", async () => {
            const tableName = "sessionTable";
            const sessionItem: Partial<SessionItem> = {
                sessionId: "123abc",
                authorizationCodeExpiryDate: 1,
                clientId: "",
                clientSessionId: "",
                redirectUri: "",
                accessToken: "",
                accessTokenExpiryDate: 0,
            };
            jest.spyOn(mockConfigService.prototype, "getConfigEntry").mockReturnValue(tableName);
            expect.assertions(2);
            await sessionService.createAuthorizationCode(sessionItem as SessionItem);
            expect(mockUpdateCommand).toHaveBeenCalled();
            expect(mockUpdateCommand).toHaveBeenCalledWith(
                expect.objectContaining({
                    TableName: tableName,
                    ExpressionAttributeValues: {
                        ":authCode": sessionItem.authorizationCode,
                        ":authCodeExpiry": sessionItem.authorizationCodeExpiryDate,
                    },
                }),
            );
        });
    });

    describe("getSessionByAuthorizationCode", () => {
        it("should call dynamodb with the authorization code and tablename", async () => {
            const tableName = "sessionTable";
            const authCode = "123";
            jest.spyOn(mockConfigService.prototype, "getConfigEntry").mockReturnValue(tableName);
            jest.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(() => {
                return Promise.resolve({ Items: ["1"] } as never);
            });
            expect.assertions(3);
            const output = await sessionService.getSessionByAuthorizationCode(authCode);
            expect(mockDynamoDbClient.prototype.query).toHaveBeenCalled();
            expect(mockDynamoDbClient.prototype.query).toHaveBeenCalledWith(
                expect.objectContaining({
                    TableName: tableName,
                    ExpressionAttributeValues: { ":authorizationCode": authCode },
                }),
            );
            expect(output).toBe("1");
        });

        it("should throw a Invalid Access token Error when Session not found", async () => {
            const tableName = "sessionTable";
            const authCode = "123";
            jest.spyOn(mockConfigService.prototype, "getConfigEntry").mockReturnValue(tableName);
            jest.spyOn(mockDynamoDbClient.prototype, "query").mockImplementation(() => {
                return Promise.resolve({} as never);
            });
            expect.assertions(1);
            try {
                await sessionService.getSessionByAuthorizationCode(authCode);
            } catch (err) {
                expect(err).toBeInstanceOf(InvalidAccessTokenError);
            }
        });
    });

    describe("createAccessTokenCode", () => {
        it("should update dynamo db with the access token", async () => {
            const sessionItem = {
                sessionId: "session-id",
                clientId: "client-id",
                clientSessionId: "client-session-id",
                authorizationCodeExpiryDate: 0,
                redirectUri: "redirect-uri",
                accessToken: "access-token",
                accessTokenExpiryDate: 0,
            };
            const accessToken = {
                access_token: "access-token",
                token_type: "token-type",
                expires_in: 0,
            };
            jest.spyOn(configService, "getConfigEntry").mockReturnValue("session-table-name");
            jest.spyOn(configService, "getBearerAccessTokenExpirationEpoch").mockReturnValueOnce(1675382400000);
            await sessionService.createAccessTokenCode(sessionItem as SessionItem, accessToken);

            expect(mockUpdateCommand).toHaveBeenCalledWith({
                TableName: "session-table-name",
                Key: { sessionId: "session-id" },
                UpdateExpression:
                    "SET accessToken=:accessTokenCode, accessTokenExpiryDate=:accessTokenExpiry REMOVE authorizationCode",
                ExpressionAttributeValues: {
                    ":accessTokenCode": "token-type access-token",
                    ":accessTokenExpiry": 1675382400000,
                },
            });
            expect(mockDynamoDbClient.prototype.send).toHaveBeenCalledTimes(1);
        });
    });

    describe("saveSession", () => {
        it("should save the session data to dynamo db", async () => {
            const mockSessionRequestSummary = {
                clientId: "test-jwt-client-id",
                clientIpAddress: "test-client-ip-address",
                clientSessionId: "test-journey-id",
                persistentSessionId: "test-persistent-session-id",
                redirectUri: "test-redirect-uri",
                state: "test-state",
                subject: "test-sub",
            };

            jest.spyOn(global.Date, "now").mockReturnValueOnce(1675382400000);
            jest.spyOn(configService, "getSessionExpirationEpoch").mockReturnValue(1675382500000);
            jest.spyOn(configService, "getConfigEntry").mockReturnValue("session-table-name");
            const output = await sessionService.saveSession(mockSessionRequestSummary);
            expect(mockDynamoDbClient.prototype.send).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: expect.objectContaining({
                        TableName: "session-table-name",
                    }),
                }),
            );
            expect(mockDynamoDbClient.prototype.send).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: expect.objectContaining({
                        Item: expect.objectContaining({
                            attemptCount: 0,
                            clientId: "test-jwt-client-id",
                            clientIpAddress: "test-client-ip-address",
                            clientSessionId: "test-journey-id",
                            createdDate: 1675382400000,
                            expiryDate: 1675382500000,
                            persistentSessionId: "test-persistent-session-id",
                            redirectUri: "test-redirect-uri",
                            state: "test-state",
                            subject: "test-sub",
                        }),
                    }),
                }),
            );

            expect(output.length).toEqual(36);
        });
    });
});
