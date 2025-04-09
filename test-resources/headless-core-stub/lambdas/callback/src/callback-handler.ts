import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { CallBackService } from "./services/callback-service";
import { generatePrivateJwtParams } from "./services/private-key-jwt-helper";
import { JWK } from "jose";
import { DEFAULT_CLIENT_ID } from "../../start/src/services/jwt-claims-set-service";
import { ClientConfiguration } from "../../../utils/src/services/client-configuration";
import { base64Decode } from "../../../utils/src/base64";

const logger = new Logger({ serviceName: "CallBackService" });
const callback = new CallBackService(logger);

export class CallbackLambdaHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent, _context: Context): Promise<APIGatewayProxyResult> {
        try {
            const authorizationCode = event.queryStringParameters?.code as string;
            logger.info({ message: "Received authorizationCode", authorizationCode });

            const clientId = (event.queryStringParameters?.client_id as string) || DEFAULT_CLIENT_ID;
            logger.info({ message: "Using client ID", clientId });

            const ssmParameters = await this.fetchSSMParameters(clientId);

            const stateBase64String = event.queryStringParameters?.state as string;
            const statePayload = this.extractFromState(stateBase64String);
            const audience = statePayload.audience || ssmParameters.audience;
            const redirectUri = statePayload.redirectUri || ssmParameters.redirectUri;

            const audienceApi = this.formatAudience(audience);
            const tokenEndpoint = `${audienceApi}/token`;

            logger.info({ message: "Generating private JWT parameters" });
            const privateJwtParams = await generatePrivateJwtParams(
                clientId,
                authorizationCode,
                redirectUri,
                JSON.parse(ssmParameters.privateSigningKey) as JWK,
                audience,
            );
            const tokenResponse = await callback.invokeTokenEndpoint(tokenEndpoint, privateJwtParams);

            const { access_token } = JSON.parse(tokenResponse.body);
            const credentialEndpoint = `${audienceApi}/credential/issue`;
            const { statusCode, body } = await callback.invokeCredentialEndpoint(credentialEndpoint, access_token);

            return { statusCode: statusCode, headers: { "Content-Type": "text/plain" }, body };
        } catch (error: unknown) {
            const exception = error as Error;
            logger.error("Error occurred: ", exception.message);

            return { statusCode: 500, body: exception.message };
        }
    }

    private extractFromState(state: string) {
        let audience;
        let redirectUri;

        if (state) {
            const statePayload = JSON.parse(base64Decode(state));
            logger.info({ message: "State payload decoded", ...statePayload });

            audience = statePayload.aud;
            redirectUri = statePayload.redirect_uri;
        }

        return { audience, redirectUri };
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
