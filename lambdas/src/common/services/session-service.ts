import { DynamoDBDocument, GetCommand } from "@aws-sdk/lib-dynamodb";
import { SessionItem } from "./session-item";

export class SessionService {
    constructor(private dynamoDbClient: DynamoDBDocument, private sessionTableName: string) {}

    public async getSession(sessionId: string | undefined): Promise<SessionItem> {
        const getSessionCommand = new GetCommand({
            TableName: this.sessionTableName,
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
}
