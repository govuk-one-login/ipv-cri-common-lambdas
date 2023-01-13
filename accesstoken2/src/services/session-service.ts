import { DynamoDBDocument, GetCommand, UpdateCommand, QueryCommandInput } from "@aws-sdk/lib-dynamodb";
import { SessionItem } from "../types/session-item";
import { BearerAccessToken } from "../types/bearer-access-token";
import { ConfigService } from "./config-service";
import { InvalidAccessTokenError } from "../types/errors";

export class SessionService {
    constructor(private dynamoDbClient: DynamoDBDocument, private configService: ConfigService) {}

    public async getSession(sessionId: string): Promise<SessionItem> {
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
        sessionItem.authorizationCode = "uuidv4()";
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

    public async getSessionByAuthorizationCode(code: string | undefined): Promise<SessionItem> {
        const tableName = await this.configService.getSessionTableName();

        const params: QueryCommandInput = {
            TableName: tableName,
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

        return sessionItem.Items[0] as SessionItem;
    }

    public async createAccessTokenCode(sessionItem: SessionItem, accessToken: BearerAccessToken) {
        const tableName = await this.configService.getSessionTableName();
        //     // Expire the authorization code immediately, as it can only be used once
        //     sessionItem.authorizationCode = '';
        //     // Set the access token
        //   sessionItem.accessToken = accessToken.access_token;
        //      // Set the access token expiry
        //   sessionItem.accessTokenExpiryDate = this.configService.getBearerAccessTokenExpirationEpoch();
        console.log(`sessionItem ${sessionItem}, accessToken ${JSON.stringify(accessToken)}`);
        const updateSessionCommand = new UpdateCommand({
            TableName: tableName,
            Key: { sessionId: sessionItem.sessionId },
            UpdateExpression:
                "SET accessToken=:accessTokenCode, accessTokenExpiryDate=:accessTokenExpiry REMOVE authorizationCode",
            ExpressionAttributeValues: {
                ":accessTokenCode": `${accessToken.token_type} ${accessToken.access_token}`,
                ":accessTokenExpiry": this.configService.getBearerAccessTokenExpirationEpoch(),
            },
        });
        console.log(`updateSessionCommand ${updateSessionCommand}`);
        await this.dynamoDbClient.send(updateSessionCommand);
    }
}
