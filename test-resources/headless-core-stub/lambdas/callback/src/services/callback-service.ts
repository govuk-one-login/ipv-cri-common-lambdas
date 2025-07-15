import { APIGatewayProxyResult } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { stackOutputs } from "../../../../utils/src/stack-outputs";
import config from "../../../../utils/src/services/config";
export class CallBackService {
    constructor(private readonly logger: Logger) {}

    public async invokeTokenEndpoint(tokenEndpoint: string, body: string): Promise<APIGatewayProxyResult> {
        this.logger.info("Invoking token endpoint");
        const tokenResponse = await fetch(tokenEndpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "x-api-key": await this.getApiKey(),
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
                "x-api-key": await this.getApiKey(),
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
    private async getApiKey() {
        this.logger.info("Retrieving API key from stack outputs");
        const { ApiKey1: apiKey } = await stackOutputs(config.coreInfrastructureStackName);
        if (!apiKey) {
            throw new Error(`API key not found in ${config.coreInfrastructureStackName}`);
        }
        return apiKey;
    }
}
