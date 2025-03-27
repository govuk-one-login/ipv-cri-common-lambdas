import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { ConfigurationHelper } from "./services/configuration-helper";
import { CallBackService } from "./services/callback-service";
import { generatePrivateJwtParams } from "./services/private-key-jwt-helper";
import { JWK } from "jose";
import { SessionItem } from "./services/session-item";

const sessionTableName = process.env.SESSION_TABLE || "session-common-cri-api";
const configurationHelper = new ConfigurationHelper();
const logger = new Logger();
const callback = new CallBackService(logger);
const CONTENT_TYPE_JWT_HEADER = { "Content-Type": "application/jwt" };
export class CallbackLambdaHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent, _context: Context): Promise<APIGatewayProxyResult> {
        try {
            const authorizationCode = event.queryStringParameters?.authorizationCode as string;
            logger.info({ message: "Received authorizationCode", authorizationCode });

            const sessionItem = await callback.getSessionByAuthorizationCode(sessionTableName, authorizationCode);
            logger.info({ message: "Fetched session item...", ...sessionItem });

            const ssmParameters = await this.fetchSSMParameters(sessionItem.clientId);
            logger.info({ message: "Generating private JWT parameters..." });
            const privateJwtParams = await this.generatePrivateJwtParams(sessionItem, authorizationCode, ssmParameters);

            const audience = ssmParameters["audience"];
            const audienceApi = this.formatAudience(audience);
            logger.info({ message: "Using Audience", audienceApi });

            const tokenEndpoint = `${audienceApi}/token`;
            logger.info({ message: "Calling token endpoint", tokenEndpoint, privateJwtParams });
            const tokenResponse = await callback.invokeTokenEndpoint(tokenEndpoint, privateJwtParams);
            logger.info({ message: "Successfully called /token endpoint" });

            const tokenBody = JSON.parse(tokenResponse.body);
            const credentialEndpoint = `${audienceApi}/credential/issue`;
            logger.info({ message: "Calling issue credential endpoint", credentialEndpoint });
            const credential = await callback.invokeCredentialEndpoint(credentialEndpoint, tokenBody.access_token);

            return { statusCode: credential.statusCode, headers: CONTENT_TYPE_JWT_HEADER, body: credential.body };
        } catch (error: unknown) {
            const err = error as Error;
            const value = err.message;
            logger.error({ message: "Error occurred", value });
            return { statusCode: 500, body: err.message };
        }
    }

    private async generatePrivateJwtParams(session: SessionItem, code: string, ssmParameters: Record<string, string>) {
        logger.info({ message: "Generating private JWT parameters", ...ssmParameters });
        return await generatePrivateJwtParams(
            session.clientId,
            code,
            session.redirectUri,
            JSON.parse(ssmParameters["privateSigningKey"]) as JWK,
            ssmParameters["audience"],
        );
    }

    private async fetchSSMParameters(clientId: string) {
        const ssmParameters = await configurationHelper.getParameters(clientId);
        const filteredParams = this.excludeFromRecord(ssmParameters, "privateSigningKey");
        logger.info({ message: "Fetched SSM parameters", ...filteredParams });
        return ssmParameters;
    }

    private excludeFromRecord = (record: Record<string, string>, excludeKey: string): Record<string, string> => {
        return Object.fromEntries(Object.entries(record).filter(([key]) => key !== excludeKey));
    };
    private formatAudience = (audience: string) =>
        audience.includes("review-") ? audience.replace("review-", "api.review-") : audience;
}

const handlerClass = new CallbackLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
