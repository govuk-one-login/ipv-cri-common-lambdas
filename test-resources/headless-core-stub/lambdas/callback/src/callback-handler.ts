import type { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { ConfigSecretKey, ConfigurationHelper } from "./services/configuration-helper";
import { CallBackService } from "./services/callback-service";
import { JWTPayload } from "jose";
import { v4 as uuidv4 } from "uuid";
import { PrivateJwtParams } from "./services/types";
import { buildPrivateKeyJwtParams, msToSeconds } from "./services/crypto-service";
import { ClientConfigKey } from "./services/config-keys";
import { createClient, AwsClientType } from "./services/aws-client-factory";
import { logger } from "./services/power-tool";
import { errorPayload } from "./services/errors";

export class CallbackLambdaHandler implements LambdaInterface {
    constructor(
        private readonly configurationHelper: ConfigurationHelper,
        private readonly callBackService: CallBackService,
    ) {}
    public async handler(event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> {
        try {
            const authorizationCode = event.queryStringParameters?.["authorizationCode"] as string;
            logger.info(`Receiving authorizationCode from CRI front-end ${authorizationCode}`);

            const sessionItem = await this.callBackService.getSessionByAuthorizationCode(authorizationCode);
            const paramClientConfig = await this.configurationHelper.getParameterWithClientId(sessionItem.clientId);
            const paramConfig = await configurationHelper.getParametersWithoutClientId();

            const privateJwtKey = paramConfig[ConfigSecretKey.STUB_PRIVATE_SIGNING_KEY];
            const audience = paramClientConfig[ClientConfigKey.JWT_AUDIENCE];

            logger.info("Generating privateJwtKey request");

            const privateJwtParams = await this.getPrivateJwtRequestParams(
                sessionItem.clientId,
                authorizationCode,
                sessionItem.redirectUri,
                privateJwtKey,
                paramClientConfig,
            );

            const audienceApi = audience.replace("review-", "api.review-");

            logger.info(`Calling CRI Api token endpoint using ${privateJwtParams}`);
            const token = await this.callBackService.getToken(`${audienceApi}/token`, privateJwtParams);
            logger.info(`Retrieved token: ${JSON.stringify(token)}`);

            const vcResponse = await this.callBackService.issueCredential(
                `${audienceApi}/credential/issue`,
                token.access_token,
            );

            logger.info(`Retrieved VC: ${JSON.stringify(vcResponse)}`);

            return {
                statusCode: vcResponse.status,
                body: await vcResponse.text(),
            };
        } catch (err: unknown) {
            return errorPayload(err as Error, logger, context.functionName);
        }
    }
    public async getPrivateJwtRequestParams(
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

        return await buildPrivateKeyJwtParams(jwtParams);
    }
}
const dynamoDbClient = createClient(AwsClientType.DYNAMO);
const configurationHelper = new ConfigurationHelper();
const callBackService = new CallBackService(dynamoDbClient, configurationHelper);
const handlerClass = new CallbackLambdaHandler(configurationHelper, callBackService);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
