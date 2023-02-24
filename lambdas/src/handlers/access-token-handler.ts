import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SessionService } from "../services/session-service";
import { ConfigService } from "../common/config/config-service";
import { AccessTokenRequestValidator } from "../services/token-request-validator";
import { JwtVerifierFactory } from "../common/security/jwt-verifier";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { SSMClient } from "@aws-sdk/client-ssm";
import { ClientConfigKey, CommonConfigKey } from "../types/config-keys";
import { BearerAccessTokenFactory } from "../services/bearer-access-token-factory";

const logger = new Logger();
const metrics = new Metrics();
const dynamoDbClient = createClient(AwsClientType.DYNAMO) as DynamoDBDocument;
const ssmClient = createClient(AwsClientType.SSM) as SSMClient;
const configService = new ConfigService(ssmClient);
const initPromise = configService.init([CommonConfigKey.SESSION_TABLE_NAME, CommonConfigKey.SESSION_TTL]);
const ACCESS_TOKEN = "accesstoken";

export class AccessTokenLambda implements LambdaInterface {
    constructor(
        private readonly bearerAccessTokenFactory: BearerAccessTokenFactory,
        private readonly sessionService: SessionService,
        private readonly requestValidator: AccessTokenRequestValidator,
    ) {}

    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        try {
            await initPromise;

            logger.info("Access Token Lambda triggered with event body", event.body as string);

            const requestPayload = this.requestValidator.validatePayload(event.body);
            const sessionItem = await this.sessionService.getSessionByAuthorizationCode(requestPayload.code);
            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });
            logger.info("Session found");

            if (!configService.hasClientConfig(sessionItem.clientId)) {
                await this.initClientConfig(sessionItem.clientId);
            }
            const clientConfig = configService.getClientConfig(sessionItem.clientId);

            this.requestValidator.validateTokenRequestToRecord(
                requestPayload.code,
                sessionItem,
                clientConfig!.get(ClientConfigKey.JWT_REDIRECT_URI)!,
            );

            logger.info("Token request validated");

            await this.requestValidator.verifyJwtSignature(
                requestPayload.client_assertion,
                sessionItem.clientId,
                clientConfig!,
            );

            logger.info("JWT signature verified");

            const accessTokenResponse = await this.bearerAccessTokenFactory.create();
            await this.sessionService.createAccessTokenCode(sessionItem, accessTokenResponse);

            logger.info("Access token created");

            metrics.addMetric(ACCESS_TOKEN, MetricUnits.Count, 1);

            return {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse),
            };
        } catch (err: any) {
            metrics.addMetric(ACCESS_TOKEN, MetricUnits.Count, 0);
            //Todo dont want any
            logger.error("Access Token Lambda error occurred", err as Error);
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
    new BearerAccessTokenFactory(configService.getBearerAccessTokenTtl()),
    new SessionService(dynamoDbClient, configService),
    new AccessTokenRequestValidator(new JwtVerifierFactory(logger)),
);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
