import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { APIGatewayProxyResult } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";

export class CallBackService {
    constructor(
        private readonly logger: Logger,
        private readonly dynamoDbClient = new DynamoDBClient({ region: process.env.REGION }),
    ) {}

    public async invokeTokenEndpoint(tokenEndpoint: string, body: string): Promise<APIGatewayProxyResult> {
        const tokenResponse = await fetch(tokenEndpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            },
            body: body,
        });

        const status = tokenResponse.status;
        const tokenResponseBodyText = await tokenResponse.text();

        if (!tokenResponse.ok) {
            this.logger.error({
                message: "Request to token endpoint failed",
                tokenEndpoint,
                status,
                responseBody: tokenResponseBodyText,
                headers: Object.fromEntries(tokenResponse.headers.entries()),
            });
            throw new Error(`Failed with ${status} status: ${tokenResponseBodyText}`);
        }
        return { statusCode: status, body: tokenResponseBodyText };
    }

    public async invokeCredentialEndpoint(
        credentialEndpoint: string,
        accessToken: string,
    ): Promise<APIGatewayProxyResult> {
        const credentialResponse = await fetch(credentialEndpoint, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });
        const status = credentialResponse.status;
        const responseBody = await credentialResponse.text();

        if (!credentialResponse.ok) {
            this.logger.error({
                message: "Request to credential endpoint failed",
                credentialEndpoint,
                status,
                responseBody,
            });
            return { statusCode: status, body: responseBody };
        }

        this.logger.info({ message: "Successfully called /credential/issue endpoint" });
        return { statusCode: status, body: responseBody };
    }
}
