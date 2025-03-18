import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { SessionItem } from "./session-item";

const dynamoDbClient = new DynamoDBClient();

export class CallBackService {
    public async getSessionByAuthorizationCode(sessionTable: string, code: string): Promise<SessionItem> {
        const sessionItemQuery = await dynamoDbClient.send(
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
            sessionId: sessionItem.sessionId.S || "",
            clientId: sessionItem.clientId.S || "",
            authorizationCode: sessionItem.authorizationCode.S || "",
            redirectUri: sessionItem.redirectUri.S || "",
        };
    }

    public async getToken(tokenUrl: string, body: string) {
        return await fetch(tokenUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: body,
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
