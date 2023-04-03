import { DynamoDBDocument, GetCommand, PutCommand, QueryCommandInput, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { SessionItem } from "../types/session-item";
import { BearerAccessToken } from "../types/bearer-access-token";
import { ConfigService } from "../common/config/config-service";
import { randomUUID } from "crypto";
import {
    AuthorizationCodeExpiredError,
    InvalidAccessTokenError,
    SessionExpiredError,
    SessionNotFoundError,
} from "../common/utils/errors";
import { SessionRequestSummary } from "../types/session-request-summary";
import { CommonConfigKey } from "../types/config-keys";

export class SessionService {
    constructor(private dynamoDbClient: DynamoDBDocument, private configService: ConfigService) {}

    public async getSession(sessionId: string | undefined): Promise<SessionItem> {
        const getSessionCommand = new GetCommand({
            TableName: this.getSessionTableName(),
            Key: {
                sessionId: sessionId,
            },
        });
        const result = await this.dynamoDbClient.send(getSessionCommand);
        if (!result || !result?.Item) {
            throw new SessionNotFoundError(`Could not find session item with id: ${sessionId}`);
        }
        return result.Item as SessionItem;
    }

    public async createAuthorizationCode(sessionItem: SessionItem) {
        sessionItem.authorizationCode = randomUUID();
        sessionItem.authorizationCodeExpiryDate = this.configService.getAuthorizationCodeExpirationEpoch();

        const updateSessionCommand = new UpdateCommand({
            TableName: this.getSessionTableName(),
            Key: { sessionId: sessionItem.sessionId },
            UpdateExpression: "SET authorizationCode=:authCode, authorizationCodeExpiryDate=:authCodeExpiry",
            ExpressionAttributeValues: {
                ":authCode": sessionItem.authorizationCode,
                ":authCodeExpiry": sessionItem.authorizationCodeExpiryDate,
            },
        });
        await this.dynamoDbClient.send(updateSessionCommand);
    }

    public async getSessionByAuthorizationCode(code: string | undefined): Promise<SessionItem> {
        const params: QueryCommandInput = {
            TableName: this.getSessionTableName(),
            IndexName: "authorizationCode-index",
            KeyConditionExpression: "authorizationCode = :authorizationCode",
            ExpressionAttributeValues: {
                ":authorizationCode": code,
            },
        };

        const sessionItem = await this.dynamoDbClient.query(params);

        if (!sessionItem?.Items || sessionItem?.Items?.length !== 1) {
            throw new InvalidAccessTokenError();
        }

        if (this.hasDateExpired(sessionItem.Items[0].expiryDate)) {
            throw new SessionExpiredError();
        }

        if (this.hasDateExpired(sessionItem.Items[0].authorizationCodeExpiryDate)) {
            throw new AuthorizationCodeExpiredError();
        }

        return sessionItem.Items[0] as SessionItem;
    }

    private hasDateExpired(dateToCheck: number): boolean {
        return dateToCheck < Math.floor(Date.now() / 1000);
    }

    public async createAccessTokenCode(sessionItem: SessionItem, accessToken: BearerAccessToken) {
        const updateSessionCommand = new UpdateCommand({
            TableName: this.getSessionTableName(),
            Key: { sessionId: sessionItem.sessionId },
            UpdateExpression:
                "SET accessToken=:accessTokenCode, accessTokenExpiryDate=:accessTokenExpiry REMOVE authorizationCode",
            ExpressionAttributeValues: {
                ":accessTokenCode": `${accessToken.token_type} ${accessToken.access_token}`,
                ":accessTokenExpiry": this.configService.getBearerAccessTokenExpirationEpoch(),
            },
        });
        await this.dynamoDbClient.send(updateSessionCommand);
    }

    public async saveSession(sessionRequest: SessionRequestSummary): Promise<string> {
        const sessionExpirationEpoch = this.configService.getSessionExpirationEpoch();
        const putSessionCommand = new PutCommand({
            TableName: this.configService.getConfigEntry(CommonConfigKey.SESSION_TABLE_NAME),
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
        return putSessionCommand?.input?.Item?.sessionId;
    }

    private getSessionTableName(): string {
        return this.configService.getConfigEntry(CommonConfigKey.SESSION_TABLE_NAME);
    }
}
