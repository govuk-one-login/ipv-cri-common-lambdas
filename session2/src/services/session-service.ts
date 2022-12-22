import { DynamoDBDocument, GetCommand, UpdateCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { SessionItem } from "../types/session-item";
import { v4 as uuidv4 } from "uuid";
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
        sessionItem.authorizationCode = uuidv4();
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

    public async saveSession(sessionRequest) {
        const tableName = await this.configService.getSessionTableName();
        const putSessionCommand = new PutCommand({
            TableName: tableName,
            Item: {
                createdDate: Date.now(),
                expiryDate: this.configService.getSessionExpirationEpoch(),
                state: sessionRequest.state,
                clientId: sessionRequest.clientId,
                redirectUri: sessionRequest.redirectUri,
                subject: sessionRequest.subject,
                persistentSessionId: sessionRequest.persistentSessionId,
                clientSessionId: sessionRequest.clientSessionId,
                clientIpAddress: sessionRequest.clientIpAddress,
                attemptCount: 0
            },
        });
        await this.dynamoDbClient.send(putSessionCommand);
        /*
        *
        * public UUID saveSession(SessionRequest sessionRequest) {
        SessionItem sessionItem = new SessionItem();
        sessionItem.setCreatedDate(this.clock.instant().getEpochSecond());
        sessionItem.setExpiryDate(this.configurationService.getSessionExpirationEpoch());
        sessionItem.setState(sessionRequest.getState());
        sessionItem.setClientId(sessionRequest.getClientId());
        sessionItem.setRedirectUri(sessionRequest.getRedirectUri());
        sessionItem.setSubject(sessionRequest.getSubject());
        sessionItem.setPersistentSessionId(sessionRequest.getPersistentSessionId());
        sessionItem.setClientSessionId(sessionRequest.getClientSessionId());
        sessionItem.setClientIpAddress(sessionRequest.getClientIpAddress());
        sessionItem.setAttemptCount(0);
        this.setSessionItemsToLogging(sessionItem);
        this.dataStore.create(sessionItem);
        return sessionItem.getSessionId();
        * */
    }
}
