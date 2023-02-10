import { SessionService } from "../../../src/services/session-service";
import { ConfigService } from "../../../src/common/config/config-service";
import { SSMClient} from "@aws-sdk/client-ssm";
import { DynamoDBDocument, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { InvalidAccessTokenError, SessionNotFoundError } from "../../../src/types/errors";
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
            const mockPromise = new Promise<any>((resolve) => {
                resolve({ Parameters: [] });
            });
            return jest.fn().mockImplementation(() => {
                return mockPromise;
            });
        }
        mockDynamoDbClient.prototype.send = impl();
        mockDynamoDbClient.prototype.query = impl();
    });

    describe("getSession", () => {
        it("Should return session item", async () => {
            const tableName = "sessionTable";
            const sessionVal = "myItem";
            const sessionId = "1";
            jest.spyOn(mockDynamoDbClient.prototype, 'send').mockImplementation(() => {
                return Promise.resolve({
                    Item: sessionVal
                });
            })
            jest.spyOn(mockConfigService.prototype, 'getConfigEntry').mockReturnValue(tableName);
            const output = await sessionService.getSession(sessionId);
            expect(output).toBe("myItem");
            expect(mockGetCommand).toHaveBeenCalled();
            expect(mockGetCommand).toHaveBeenCalledWith({TableName: tableName, Key: {sessionId: sessionId}});
            expect(mockDynamoDbClient.prototype.send).toHaveBeenCalled();
        });

        it("Should throw session item not found when session not found", async () => {
            expect.assertions(3);
            try {
                const tableName = "sessionTable";
                const sessionId = "1";
                jest.spyOn(mockDynamoDbClient.prototype, 'send').mockImplementation(() => {
                    return Promise.resolve({});
                })
                jest.spyOn(mockConfigService.prototype, 'getConfigEntry').mockReturnValue(tableName);
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
            const sessionItem: SessionItem = {
                sessionId: "123abc",
                authorizationCodeExpiryDate: 1,
                clientId: "",
                clientSessionId: "",
                redirectUri: "",
                accessToken: "",
                accessTokenExpiryDate: 0,
            };
            jest.spyOn(mockConfigService.prototype, 'getConfigEntry').mockReturnValue(tableName);
            expect.assertions(2);
            await sessionService.createAuthorizationCode(sessionItem);
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
            jest.spyOn(mockConfigService.prototype, 'getConfigEntry').mockReturnValue(tableName);
            jest.spyOn(mockDynamoDbClient.prototype, 'query').mockImplementation(() => {
                return Promise.resolve({ Items: ["1"] } as never);
            })
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
            jest.spyOn(mockConfigService.prototype, 'getConfigEntry').mockReturnValue(tableName);
            jest.spyOn(mockDynamoDbClient.prototype, 'query').mockImplementation(() => {
                return Promise.resolve({} as never);
            })
            expect.assertions(1);
            try {
                await sessionService.getSessionByAuthorizationCode(authCode);
            } catch (err) {
                expect(err).toBeInstanceOf(InvalidAccessTokenError);
            }
        });
    });
});