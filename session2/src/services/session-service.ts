import { DynamoDBDocument, PutCommand } from "@aws-sdk/lib-dynamodb";
import { v4 as uuidv4 } from "uuid";
import { ConfigService } from "../common/config/config-service";
import { CommonConfigKey } from "../common/config/config-keys";
import { SessionRequestSummary } from "./models/session-request-summary";

export class SessionService {
    constructor(private dynamoDbClient: DynamoDBDocument, private configService: ConfigService) {}

    public async saveSession(sessionRequest: SessionRequestSummary): Promise<string> {
        const tableName = this.configService.getConfigEntry(CommonConfigKey.SESSION_TABLE_NAME);
        const sessionExpirationEpoch = this.configService.getSessionExpirationEpoch();
        const putSessionCommand = new PutCommand({
            TableName: tableName,
            Item: {
                sessionId: uuidv4(),
                createdDate: Date.now(),
                expiryDate: sessionExpirationEpoch,
                state: sessionRequest.state,
                clientId: sessionRequest.clientId,
                redirectUri: sessionRequest.redirectUri,
                subject: sessionRequest.subject,
                persistentSessionId: sessionRequest.persistentSessionId,
                clientSessionId: sessionRequest.clientSessionId,
                clientIpAddress: sessionRequest.clientIpAddress,
                attemptCount: 0,
            },
        });
        await this.dynamoDbClient.send(putSessionCommand);
        return putSessionCommand.input.Item!.sessionId;
    }
}
