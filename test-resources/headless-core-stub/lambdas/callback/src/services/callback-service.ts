import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { SessionItem } from "./session-item";

export class CallBackService {
    constructor(private readonly dynamoDbClient = new DynamoDBClient({ region: process.env.REGION })) {}

    public async getSessionByAuthorizationCode(sessionTable: string, code: string): Promise<SessionItem> {
        const sessionItemQuery = await this.dynamoDbClient.send(
            new QueryCommand({
                TableName: sessionTable,
                IndexName: "authorizationCode-index",
                KeyConditionExpression: "authorizationCode = :authorizationCode",
                ExpressionAttributeValues: {
                    ":authorizationCode": {
                        S: code as string,
                    },
                },
            }),
        );

        if (sessionItemQuery.Count == 0 || !sessionItemQuery.Items) {
            throw new Error("No session item found for provided authorizationCode");
        }

        const sessionItem = sessionItemQuery.Items[0];

        return {
            sessionId: sessionItem?.sessionId?.S,
            clientId: sessionItem?.clientId?.S,
            authorizationCode: sessionItem?.authorizationCode?.S,
            redirectUri: sessionItem?.redirectUri?.S,
        } as SessionItem;
    }

    public async getToken(tokenUrl: string, body: string): Promise<Response> {
        return await fetch(tokenUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            },
            body: body,
        });
    }

    public async callIssueCredential(credentialUrl: string, accessToken: string): Promise<Response> {
        return await fetch(credentialUrl, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });
    }
}
