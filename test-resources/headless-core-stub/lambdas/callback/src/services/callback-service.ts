import { QueryCommandInput } from "@aws-sdk/client-dynamodb";
import { SessionItem } from "./session-item";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { InvalidAccessTokenError, SessionExpiredError, AuthorizationCodeExpiredError } from "./errors";
import { ConfigurationHelper } from "./configuration-helper";

export class CallBackService {
    constructor(
        private readonly dynamoDbClient: DynamoDBDocument,
        private readonly configHelper: ConfigurationHelper,
    ) {}
    public async getSessionByAuthorizationCode(sessionTable: string, code: string): Promise<SessionItem> {
        const params: QueryCommandInput = {
            TableName: sessionTable,
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

    public async getToken(tokenUrl: string, params: string) {
        return await fetch(tokenUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            },
            body: params,
        });
    }

    public async issueCredential(credentialUrl: string, accessToken: string) {
        return await fetch(credentialUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${accessToken}`,
            },
        });
    }
}
