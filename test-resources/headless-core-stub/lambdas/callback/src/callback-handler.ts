import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { CallBackService } from "./services/callback-service";
import { generatePrivateJwtParams } from "./services/private-key-jwt-helper";
import { JWK } from "jose";
import { HeadlessCoreStubError } from "../../../utils/src//errors/headless-core-stub-error";
import { handleErrorResponse } from "../../../utils/src/errors/error-response";
import { ClientConfiguration } from "../../../utils/src/services/client-configuration";
import { base64Decode } from "../../../utils/src/base64";
import { DEFAULT_CLIENT_ID } from "../../../utils/src/constants";
import { formatAudience } from "../../../utils/src/audience-formatter";

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

            const audienceApi = formatAudience(audience, logger);
            const tokenEndpoint = new URL("token", audienceApi).href;

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
            const credentialEndpoint = new URL("credential/issue", audienceApi).href;
            const { statusCode, body } = await callback.invokeCredentialEndpoint(credentialEndpoint, access_token);

            return { statusCode: statusCode, headers: { "Content-Type": "text/plain" }, body };
        } catch (error: unknown) {
            return handleErrorResponse(error, logger);
        }
    }

    private extractFromState(state: string) {
        let audience;
        let redirectUri;

        if (state) {
            try {
                const statePayload = JSON.parse(base64Decode(state));
                logger.info({ message: "State payload decoded", ...statePayload });

                audience = statePayload.aud;
                redirectUri = statePayload.redirect_uri;
            } catch (error) {
                throw new HeadlessCoreStubError("State param is not a valid JSON bas64 encoded string", 400);
            }
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
}

const handlerClass = new CallbackLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
