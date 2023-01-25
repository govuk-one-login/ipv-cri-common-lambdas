import { DynamoDBDocument, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { SessionItem } from "../types/session-item";
import { randomUUID } from "crypto";
import { ConfigService } from "./config-service";

export class SessionService {
    constructor(private dynamoDbClient: DynamoDBDocument, private configService: ConfigService) {}

    public async getSession(sessionId: string | undefined): Promise<SessionItem> {
        const tableName = await this.configService.getSessionTableName();
        const getSessionCommand = new GetCommand({
            TableName: tableName,
            Key: {
                sessionId: sessionId,
            },
        });
        const result = await this.dynamoDbClient.send(getSessionCommand);
        if (!result.Item) {
            throw new Error(`Could not find session item with id: ${sessionId}`);
        }
        return result.Item as SessionItem;
    }

    public async createAuthorizationCode(sessionItem: SessionItem) {
        const tableName = await this.configService.getSessionTableName();
        sessionItem.authorizationCode = randomUUID();
        sessionItem.authorizationCodeExpiryDate = this.configService.getAuthorizationCodeExpirationEpoch();

        const updateSessionCommand = new UpdateCommand({
            TableName: tableName,
            Key: { sessionId: sessionItem.sessionId },
            UpdateExpression: "SET authorizationCode=:authCode, authorizationCodeExpiryDate=:authCodeExpiry",
            ExpressionAttributeValues: {
                ":authCode": sessionItem.authorizationCode,
                ":authCodeExpiry": sessionItem.authorizationCodeExpiryDate,
            },
        });
        await this.dynamoDbClient.send(updateSessionCommand);
    }
}
