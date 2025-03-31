import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { CallBackService } from "./services/callback-service";
import { generatePrivateJwtParams } from "./services/private-key-jwt-helper";
import { JWK } from "jose";
import { SessionItem } from "./services/session-item";
import { ClientConfiguration } from "../../../utils/src/services/client-configuration";
import config from "../../../utils/src/services/config";

const { sessionTableName } = config;
const logger = new Logger({ serviceName: "CallBackService" });
const callback = new CallBackService(logger);
export class CallbackLambdaHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent, _context: Context): Promise<APIGatewayProxyResult> {
        try {
            const authorizationCode = event.queryStringParameters?.authorizationCode as string;
            logger.info({ message: "Received authorizationCode", authorizationCode });

            const sessionItem = await callback.getSessionByAuthorizationCode(sessionTableName, authorizationCode);
            const ssmParameter = await this.fetchSSMParameters(sessionItem.clientId);
            const audienceApi = this.formatAudience(ssmParameter.audience);

            const tokenEndpoint = `${audienceApi}/token`;
            const privateJwtParams = await this.generatePrivateJwtParams(sessionItem, authorizationCode, ssmParameter);
            const tokenResponse = await callback.invokeTokenEndpoint(tokenEndpoint, privateJwtParams);

            const { access_token } = JSON.parse(tokenResponse.body);
            const credentialEndpoint = `${audienceApi}/credential/issue`;
            const { statusCode, body } = await callback.invokeCredentialEndpoint(credentialEndpoint, access_token);

            return { statusCode: statusCode, headers: { "Content-Type": "application/jwt" }, body };
        } catch (error: unknown) {
            const exception = error as Error;
            logger.error("Error occurred: ", exception.message);

            return { statusCode: 500, body: exception.message };
        }
    }

    private async generatePrivateJwtParams(session: SessionItem, code: string, ssmParameters: Record<string, string>) {
        logger.info({ message: "Generating private JWT parameters" });

        return await generatePrivateJwtParams(
            session.clientId,
            code,
            session.redirectUri,
            JSON.parse(ssmParameters.privateSigningKey) as JWK,
            ssmParameters.audience,
        );
    }

    private async fetchSSMParameters(clientId: string) {
        const ssmParameters = await ClientConfiguration.getConfig(clientId);
        const filteredParams = this.excludeFromRecord(ssmParameters, "privateSigningKey");

        logger.info({ message: "Fetched SSM parameters", ...filteredParams });
        return ssmParameters;
    }

    private excludeFromRecord = (record: Record<string, string>, excludeKey: string): Record<string, string> => {
        return Object.fromEntries(Object.entries(record).filter(([key]) => key !== excludeKey));
    };
    private formatAudience = (audience: string) => {
        const audienceApi = audience.includes("review-") ? audience.replace("review-", "api.review-") : audience;

        logger.info({ message: "Using Audience", audienceApi });
        return audienceApi;
    };
}

const handlerClass = new CallbackLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
