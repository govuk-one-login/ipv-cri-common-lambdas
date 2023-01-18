jest.mock("@aws-sdk/lib-dynamodb", () => {
  return {
      __esModule: true,
      ...jest.requireActual("@aws-sdk/lib-dynamodb"),
      GetCommand: jest.fn(),
      UpdateCommand: jest.fn()
  };
}); //  this is so we only mock out the GetCommand

jest.mock("../../../src/lib/dynamo-db-client");
jest.mock("../../../src/services/config-service");

import { DynamoDbClient } from "../../../src/lib/dynamo-db-client";
import { SessionService } from "../../../src/services/session-service";
import { ConfigService } from "../../../src/services/config-service";
import { SSMClient } from "@aws-sdk/client-ssm";
import { GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { InvalidAccessTokenError, SessionNotFoundError } from "../../../src/types/errors";
import { SessionItem } from "../../../src/types/session-item";
import { BearerAccessToken } from "../../../src/types/bearer-access-token";


describe("session-service", () => {
  let sessionService: SessionService;

  const configService = new ConfigService(jest.fn() as unknown as SSMClient);
  const mockDynamoDbClient = jest.mocked(DynamoDbClient);
  const mockConfigService = jest.mocked(ConfigService);
  const mockGetCommand = jest.mocked(GetCommand);
  const mockUpdateCommand = jest.mocked(UpdateCommand);

  describe("getSession", () => {

    beforeEach(() => {
      jest.resetAllMocks();
      sessionService = new SessionService(DynamoDbClient, configService);
    });

    it("Should return session item", async () => {
      const tableName = "sessionTable";
      const sessionVal = "myItem";
      const sessionId = "1";
      const mockDynamoDbResponse: any = {
        Item: sessionVal
      }

      mockDynamoDbClient.send.mockReturnValueOnce(mockDynamoDbResponse);

      mockConfigService.prototype.getSessionTableName.mockResolvedValue(tableName);
      const output = await sessionService.getSession(sessionId);
      expect(output).toBe("myItem");
      expect(mockGetCommand).toHaveBeenCalled()
      expect(mockGetCommand).toHaveBeenCalledWith({TableName: tableName, Key: { sessionId: sessionId }});
      expect(mockDynamoDbClient.send).toHaveBeenCalled();
    });

    it("Should throw session item not found when session not found", async () => {
      expect.assertions(3);
      try {
        const tableName = "sessionTable";
        const sessionId = "1";
        const mockDynamoDbResponse: any = {}

        mockDynamoDbClient.send.mockReturnValueOnce(mockDynamoDbResponse);

        mockConfigService.prototype.getSessionTableName.mockResolvedValue(tableName);
        await sessionService.getSession(sessionId);
      } catch(err) {
        expect(mockGetCommand).toHaveBeenCalled()
        expect(mockDynamoDbClient.send).toHaveBeenCalled();
        expect(err).toBeInstanceOf(SessionNotFoundError);
      }
    });
  });

  describe("createAuthorizationCode", () => {
    it("should call the update command with the a payload that includes ", async () => {
      const tableName = "sessionTable";
      mockConfigService.prototype.getSessionTableName.mockResolvedValue(tableName);

      const sessionItem: SessionItem = {
        sessionId: "123abc",
        authorizationCodeExpiryDate: 1,
        clientId: "",
        clientSessionId: "",
        redirectUri: "",
        accessToken: "",
        accessTokenExpiryDate: 0
      }

      expect.assertions(2)
      await sessionService.createAuthorizationCode(sessionItem);
      expect(mockUpdateCommand).toHaveBeenCalled();
      expect(mockUpdateCommand).toHaveBeenCalledWith(expect.objectContaining({TableName: tableName, ExpressionAttributeValues: {":authCode": sessionItem.authorizationCode, ":authCodeExpiry": sessionItem.authorizationCodeExpiryDate}}))
    });
  });

  describe("getSessionByAuthorizationCode", () => {
    it("should call dynamodb with the authorization code and tablename", async () => {
      const tableName = "sessionTable";
      const authCode = "123"

      mockConfigService.prototype.getSessionTableName.mockResolvedValue(tableName)

      const mockDynamoDbResponse = {Items: ["1"]};
      mockDynamoDbClient.query.mockResolvedValueOnce(mockDynamoDbResponse as never);

      expect.assertions(3)
      const output = await sessionService.getSessionByAuthorizationCode(authCode);
      expect(mockDynamoDbClient.query).toHaveBeenCalled();
      expect(mockDynamoDbClient.query).toHaveBeenCalledWith(expect.objectContaining({TableName: tableName, ExpressionAttributeValues: {":authorizationCode": authCode}}));
      expect(output).toBe("1")

    });

    it("should throw a Invalid Access token Error when Session not found", async () => {
      const tableName = "sessionTable";
      const authCode = "123"

      mockConfigService.prototype.getSessionTableName.mockResolvedValue(tableName)

      const mockDynamoDbResponse = {};
      mockDynamoDbClient.query.mockResolvedValueOnce(mockDynamoDbResponse as never);

      expect.assertions(1)
      try {
        await sessionService.getSessionByAuthorizationCode(authCode);
      } catch(err) {
        expect(err).toBeInstanceOf(InvalidAccessTokenError);
      }
    });
  })
});