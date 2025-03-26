import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { ConfigurationHelper } from "./services/configuration-helper";
import { CallBackService } from "./services/callback-service";
import { generatePrivateJwtParams } from "./services/private-key-jwt-helper";
import { JWK } from "jose";

const sessionTableName = process.env.SESSION_TABLE || "session-common-cri-api";
const configurationHelper = new ConfigurationHelper();
const callbackService = new CallBackService();
const logger = new Logger();
export class CallbackLambdaHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent, _context: Context): Promise<APIGatewayProxyResult> {
        try {
            const authorizationCode = event.queryStringParameters?.authorizationCode as string;
            logger.info({ message: "Received authorizationCode", authorizationCode });

            const sessionItem = await callbackService.getSessionByAuthorizationCode(
                sessionTableName,
                authorizationCode,
            );
            logger.info({ message: "Fetching session item...", ...sessionItem });

            const ssmParameters = await configurationHelper.getParameters(sessionItem.clientId);
            const { privateSigningKey, ...filteredParams } = ssmParameters;

            logger.info({ message: "Fetching SSM parameters", ...filteredParams });

            const privateJwtKey = JSON.parse(privateSigningKey) as JWK;
            const audience = ssmParameters["audience"];

            logger.info({ message: "Generating private JWT parameters..." });
            const privateJwtParams = await generatePrivateJwtParams(
                sessionItem.clientId,
                authorizationCode,
                sessionItem.redirectUri,
                privateJwtKey,
                audience,
            );

            const audienceApi = this.formatAudience(audience);
            logger.info({ message: "Using Audience", audienceApi });

            const tokenEndpoint = `${audienceApi}/token`;
            logger.info({ message: "Calling token endpoint", tokenEndpoint, privateJwtParams });
            const tokenResponse = await callbackService.getToken(tokenEndpoint, privateJwtParams);

            if (!tokenResponse.ok) {
                const tokenResponseBody = await tokenResponse.text();
                const status = tokenResponse.status;
                logger.error({ message: "Request to endpoint failed", tokenEndpoint, status, tokenResponseBody });
                return { statusCode: tokenResponse.status, body: tokenResponseBody };
            }

            logger.info({ message: "Successfully called /token endpoint" });
            const tokenBody = await tokenResponse.json();

            const credentialEndpoint = `${audienceApi}/credential/issue`;
            logger.info({ message: "Calling issue credential endpoint", credentialEndpoint });
            const credential = await callbackService.callIssueCredential(credentialEndpoint, tokenBody.access_token);
            const credentialResponseJwt = await credential.text();

            if (!credential.ok) {
                const endpoint = credentialEndpoint;
                const status = credential.status;
                const body = await credential.text();
                logger.error({ message: "Request to endpoint failed", endpoint, status, body });
            }
            logger.info({ message: "Successfully called /credential/issue endpoint" });

            return {
                statusCode: credential.status,
                headers: {
                    "Content-Type": "application/jwt",
                },
                body: credentialResponseJwt,
            };
        } catch (error: unknown) {
            const err = error as Error;
            const value = err.message;
            logger.error({ message: "Unknown error occurred", value });
            return { statusCode: 500, body: err.message };
        }
    }

    private formatAudience = (audience: string) =>
        audience.includes("review-") ? audience.replace("review-", "api.review-") : audience;
}

const handlerClass = new CallbackLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
