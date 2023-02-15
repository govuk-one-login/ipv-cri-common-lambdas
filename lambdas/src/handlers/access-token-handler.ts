import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SessionService } from "../services/session-service";
import { ConfigService } from "../common/config/config-service";
import { AccessTokenRequestValidator } from "../services/token-request-validator";
import { AccessTokenService } from "../services/access-token-service";
import { JwtVerifierFactory } from "../common/security/jwt-verifier";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { SSMClient } from "@aws-sdk/client-ssm";
import { ClientConfigKey, CommonConfigKey } from "../types/config-keys";

const logger = new Logger();
const metrics = new Metrics();
const dynamoDbClient = createClient(AwsClientType.DYNAMO) as DynamoDBDocument;
const ssmClient = createClient(AwsClientType.SSM) as SSMClient;
const configService = new ConfigService(ssmClient);
const initPromise = configService.init([CommonConfigKey.SESSION_TABLE_NAME, CommonConfigKey.SESSION_TTL]);

export class AccessTokenLambda implements LambdaInterface {
    constructor(
        private readonly accessTokenService: AccessTokenService,
        private readonly sessionService: SessionService,
        private readonly requestValidator: AccessTokenRequestValidator,
    ) {}

    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        try {
            await initPromise;

            const requestPayload = this.requestValidator.validatePayload(event.body);
            const sessionItem = await this.sessionService.getSessionByAuthorizationCode(requestPayload.code);
            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });

            if (!configService.hasClientConfig(sessionItem.clientId)) {
                await this.initClientConfig(sessionItem.clientId);
            }
            const clientConfig = configService.getClientConfig(sessionItem.clientId);

            this.requestValidator.validateTokenRequestToRecord(
                requestPayload.code,
                sessionItem,
                clientConfig!.get(ClientConfigKey.JWT_REDIRECT_URI)!,
            );

            await this.requestValidator.verifyJwtSignature(
                requestPayload.client_assertion,
                sessionItem.clientId,
                clientConfig!,
            );

            const bearerAccessTokenTTL = configService.getBearerAccessTokenTtl();
            const accessTokenResponse = await this.accessTokenService.createBearerAccessToken(bearerAccessTokenTTL);
            await this.sessionService.createAccessTokenCode(sessionItem, accessTokenResponse);

            return {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse),
            };
        } catch (err: any) {
            //Todo dont want any
            logger.error({
                statusCode: err.statusCode ?? 500,
                message: err?.message,
                err: err,
            });
            return {
                statusCode: err.statusCode ?? 500,
                body: JSON.stringify({
                    message: err?.statusCode >= 500 ? "Server Error" : err.message,
                    code: err.code || null,
                    errorSummary: err.getErrorSummary(),
                }),
            };
        }
    }
    private async initClientConfig(clientId: string): Promise<void> {
        await configService.initClientConfig(clientId, [
            ClientConfigKey.JWT_AUDIENCE,
            ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
            ClientConfigKey.JWT_REDIRECT_URI,
            ClientConfigKey.JWT_SIGNING_ALGORITHM,
        ]);
    }
}

const handlerClass = new AccessTokenLambda(
    new AccessTokenService(),
    new SessionService(dynamoDbClient, configService),
    new AccessTokenRequestValidator(new JwtVerifierFactory(logger)),
);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
