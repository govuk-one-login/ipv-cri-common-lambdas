import { DynamoDBDocument, PutCommand } from "@aws-sdk/lib-dynamodb";
import { randomUUID } from "crypto";
import { ConfigService } from "./common/config/config-service";
import { CommonConfigKey } from "./common/config/config-keys";
import { SessionRequestSummary } from "./services/models/session-request-summary";

export class SessionService {
    constructor(private dynamoDbClient: DynamoDBDocument, private config: Array<string|number>) {}

    public async saveSession(sessionRequest: SessionRequestSummary): Promise<string> {
        const [tableName, sessionExpirationEpoch] = this.config;
        //const sessionExpirationEpoch = this.configService.getSessionExpirationEpoch();
        const putSessionCommand = new PutCommand({
            TableName: tableName as string,
            Item: {
                sessionId: randomUUID(),
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
