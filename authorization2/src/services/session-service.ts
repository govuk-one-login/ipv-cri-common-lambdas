/* eslint-disable no-console */
import { DynamoDBDocument, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import {SessionItem} from "../types/session-item";
import { v4 as uuidv4 } from "uuid";

export class SessionService {
    constructor(private tableName: string | undefined, private dynamoDbClient: DynamoDBDocument) {}

    public async getSession(sessionId: string | undefined): Promise<SessionItem> {
        const getSessionCommand = new GetCommand({
            TableName: this.tableName,
            Key: {
                sessionId: sessionId,
            },
        });
        const result = await this.dynamoDbClient.send(getSessionCommand);
        if (!result.Item) {
            throw new Error(`Could not find session item with id: ${sessionId}`)
        }
        return result.Item as SessionItem;
    }

    public async createAuthorizationCode(sessionItem: SessionItem) {
        sessionItem.authorizationCode = uuidv4();
        sessionItem.authorizationCodeExpiryDate = 1; // TODO: assign from config

        const updateSessionCommand = new UpdateCommand({
            TableName: this.tableName,
            Key: { sessionId: sessionItem.sessionId },
            UpdateExpression: "SET authorizationCode=:authCode, authorizationCodeExpiryDate=:authCodeExpiry",
            ExpressionAttributeValues: {
                ":authCode": sessionItem.authorizationCode,
                ":authCodeExpiry": sessionItem.authorizationCodeExpiryDate
            }
        });
        await this.dynamoDbClient.send(updateSessionCommand);
    }
}
