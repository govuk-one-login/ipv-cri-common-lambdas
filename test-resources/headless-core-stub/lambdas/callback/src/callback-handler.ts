import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { v4 as uuidv4 } from "uuid";
import { JWTPayload } from "jose";
import { ConfigurationHelper } from "./services/configuration-helper";
import { CallBackService } from "./services/callback-service";
import { buildPrivateKeyJwtParams, msToSeconds } from "./services/crypto-service";

const logger = new Logger();
const configurationHelper = new ConfigurationHelper();
const callbackService = new CallBackService();

const sessionTableName = process.env.SessionTable || "session-common-cri-api";

export class CallbackLambdaHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent, _context: Context): Promise<APIGatewayProxyResult> {
        const authorizationCode = event.queryStringParameters?.authorizationCode;

        if (!authorizationCode) {
            return this.respondWith(400, "Missing authorization code");
        }

        logger.info("Received authorizationCode: " + authorizationCode);

        try {
            logger.info("Fetching session item...");
            const sessionItem = await callbackService.getSessionByAuthorizationCode(
                sessionTableName,
                authorizationCode,
            );

            logger.info("Fetching SSM parameters");
            const ssmParameters = await configurationHelper.getParameters(sessionItem.clientId);
            const privateJwtKey = JSON.parse(ssmParameters["privateSigningKey"]);
            const audience = ssmParameters["audience"];

            logger.info("Generating private JWT parameters...");
            const privateJwtParams = await this.generatePrivateJwtParams(
                sessionItem.clientId,
                authorizationCode,
                sessionItem.redirectUri,
                privateJwtKey,
                audience,
            );

            const audienceApi = this.formatAudience(audience);
            logger.info("Audience is " + audienceApi);

            const tokenEndpoint = `${audienceApi}/token`;

            logger.info("Calling token endpoint " + tokenEndpoint + " with body: " + privateJwtParams);

            const tokenResponse = await callbackService.getToken(tokenEndpoint, privateJwtParams);

            if (!tokenResponse.ok) {
                const tokenResponseBody = await tokenResponse.text();
                this.logApiError(tokenEndpoint, tokenResponse.status, tokenResponseBody);
                return this.respondWith(tokenResponse.status, tokenResponseBody);
            }

            logger.info("Successfully called /token endpoint");

            const tokenBody = await tokenResponse.json();
            const credentialEndpoint = `${audienceApi}/credential/issue`;

            logger.info("Calling " + credentialEndpoint);

            const credential = await callbackService.issueCredential(credentialEndpoint, tokenBody.access_token);
            const credentialResponseBody = await credential.text();

            if (!credential.ok) {
                this.logApiError(credentialEndpoint, credential.status, credentialResponseBody);
            }

            logger.info("Successfully called /credential/issue endpoint");

            return this.respondWith(credential.status, credentialResponseBody);
        } catch (error: unknown) {
            const err = error as Error;
            logger.error(err.message);
            return this.respondWith(500, err.message);
        }
    }

    private async generatePrivateJwtParams(
        clientId: string,
        authorizationCode: string,
        redirectUrl: string,
        privateJwtKey: string,
        audience: string,
    ): Promise<string> {
        const customClaims: JWTPayload = {
            iss: clientId,
            sub: clientId,
            aud: audience,
            exp: msToSeconds(Date.now() + 5 * 60 * 1000),
            jti: uuidv4(),
        };

        return buildPrivateKeyJwtParams({
            customClaims,
            authorizationCode,
            redirectUrl,
            privateSigningKey: privateJwtKey,
        });
    }

    private formatAudience(audience: string): string {
        if (audience.includes("review")) {
            return audience.replace("review-", "api.review-");
        }
        return audience;
    }

    private logApiError(endpoint: string, status: number, body: string) {
        logger.info("Request to " + endpoint + " failed with status " + status + " body: " + body);
    }

    private respondWith(status: number, body: string) {
        return {
            statusCode: status,
            body: body,
        };
    }
}

const handlerClass = new CallbackLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
