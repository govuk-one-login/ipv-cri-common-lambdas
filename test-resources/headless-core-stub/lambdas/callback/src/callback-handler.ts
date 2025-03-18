import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { v4 as uuidv4 } from "uuid";
import { JWTPayload } from "jose";
import { ConfigSecretKey, ConfigurationHelper } from "./services/configuration-helper";
import { CallBackService } from "./services/callback-service";
import { PrivateJwtParams } from "./services/types";
import { buildPrivateKeyJwtParams, msToSeconds } from "./services/crypto-service";
import { ClientConfigKey } from "./services/config-keys";
import { AwsClientType, createClient } from "./services/aws-client-factory";
import { errorPayload } from "./services/errors";

const logger = new Logger();
const dynamoDbClient = createClient(AwsClientType.DYNAMO);
const configurationHelper = new ConfigurationHelper();
const callbackService = new CallBackService(dynamoDbClient, configurationHelper);

const sessionTableName = process.env.SessionTable || "common-cri-api-session";

class CallbackLambdaHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> {
        const authorizationCode = event.queryStringParameters?.authorizationCode;

        if (!authorizationCode) {
            return this.badRequestResponse("Missing authorization code");
        }

        logger.info("Received authorizationCode: " + authorizationCode);

        try {
            logger.info("Fetching session item...");
            const sessionItem = await callbackService.getSessionByAuthorizationCode(
                sessionTableName,
                authorizationCode,
            );

            logger.info("Fetching SSM parameters");
            const paramClientConfig = await configurationHelper.getParameters(sessionItem.clientId);

            const privateJwtKey = paramClientConfig[ConfigSecretKey.STUB_PRIVATE_SIGNING_KEY];
            const audience = paramClientConfig[ClientConfigKey.JWT_AUDIENCE];

            logger.info("Generating private JWT parameters...");
            const privateJwtParams = await this.generatePrivateJwtParams(
                sessionItem.clientId,
                authorizationCode,
                sessionItem.redirectUri,
                privateJwtKey,
                paramClientConfig,
            );

            const audienceApi = this.getApiAudience(audience);
            logger.info("Audience is " + audienceApi);

            const tokenEndpoint = `${audienceApi}/token-ts`;

            logger.info("Calling token endpoint " + tokenEndpoint + " with body: " + privateJwtParams);

            const tokenResponse = await callbackService.getToken(tokenEndpoint, privateJwtParams);

            if (!tokenResponse.ok) {
                const tokenResponseBody = await tokenResponse.text();
                this.logApiError(tokenEndpoint, tokenResponse.status, tokenResponseBody);
                return this.returnAPIResponse(tokenResponse.status, tokenResponseBody);
            }

            const tokenBody = await tokenResponse.json();

            const credentialEndpoint = `${audienceApi}/credential/issue`;
            logger.info("Calling " + credentialEndpoint);
            const credential = await callbackService.issueCredential(credentialEndpoint, tokenBody.access_token);
            const credentialResponseBody = await credential.text();

            if (!credential.ok) {
                this.logApiError(credentialEndpoint, credential.status, credentialResponseBody);
            }

            return this.returnAPIResponse(credential.status, credentialResponseBody);
        } catch (error) {
            return errorPayload(error as Error, logger, context.functionName);
        }
    }

    private logApiError(endpoint: string, status: number, body: string) {
        logger.info("Request to " + endpoint + " failed with status " + status + " body: " + body);
    }

    private returnAPIResponse(status: number, body: string) {
        return {
            statusCode: status,
            body: body,
        };
    }

    private async generatePrivateJwtParams(
        clientId: string,
        authorizationCode: string,
        redirectUrl: string,
        privateJwtKey: string,
        clientConfig: Record<string, string>,
    ): Promise<string> {
        const audience = clientConfig[ClientConfigKey.JWT_AUDIENCE];
        const customClaims: JWTPayload = {
            iss: clientId,
            sub: clientId,
            aud: audience,
            exp: msToSeconds(Date.now() + 5 * 60 * 1000),
            jti: uuidv4(),
        };

        const jwtParams: PrivateJwtParams = {
            customClaims,
            authorizationCode,
            redirectUrl,
            privateSigningKey: JSON.parse(privateJwtKey),
        };

        return buildPrivateKeyJwtParams(jwtParams);
    }

    private getApiAudience(audience: string): string {
        if (audience.includes("review")) {
            return audience.replace("review-", "api.review-");
        }
        return audience;
    }

    private badRequestResponse(message: string): APIGatewayProxyResult {
        return {
            statusCode: 400,
            body: JSON.stringify({ error: message }),
        };
    }
}

const handlerClass = new CallbackLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
