import middy from "@middy/core";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { SessionService } from "../services/session-service";
import { AccessTokenRequestValidator } from "../services/token-request-validator";
import { JwtVerifierFactory } from "../common/security/jwt-verifier";
import { ClientConfigKey } from "../types/config-keys";
import { BearerAccessTokenFactory } from "../services/bearer-access-token-factory";
import { errorPayload } from "../common/utils/errors";
import { SessionItem } from "../types/session-item";
import accessTokenValidatorMiddleware from "../middlewares/access-token/validate-event-payload-middleware";
import configurationInitMiddleware, { configService } from "../middlewares/config/configuration-init-middleware";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import setGovUkSigningJourneyIdMiddleware from "../middlewares/session/set-gov-uk-signing-journey-id-middleware";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import getSessionByAuthCodeMiddleware from "../middlewares/session/get-session-by-auth-code-middleware";
import { logger, metrics, tracer as _tracer } from "../common/utils/power-tool";
import { MetricUnits } from "@aws-lambda-powertools/metrics";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/lib/middleware/middy";
import { RequestPayload } from "../types/request_payload";
import getSessionById from "../middlewares/session/get-session-by-id";
import errorMiddleware from "../middlewares/error/error-middleware";
const dynamoDbClient = createClient(AwsClientType.DYNAMO) as DynamoDBDocument;

const ACCESS_TOKEN = "accesstoken";

export class AccessTokenLambda implements LambdaInterface {
    constructor(
        private readonly bearerAccessTokenFactory: BearerAccessTokenFactory,
        private readonly sessionService: SessionService,
        private readonly requestValidator: AccessTokenRequestValidator,
    ) {}
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    @_tracer.captureLambdaHandler({ captureResponse: false })
    public async handler(event: APIGatewayProxyEvent, _context: Context): Promise<APIGatewayProxyResult> {
        try {
            logger.info("Access Token Lambda triggered");
            const eventBody = event.body;
            const sessionItem = eventBody as unknown as SessionItem;
            const requestPayload = eventBody as unknown as RequestPayload;

            if (!configService.hasClientConfig(sessionItem.clientId)) {
                await this.initClientConfig(sessionItem.clientId);
            }
            const clientConfig = configService.getClientConfig(sessionItem.clientId);

            this.requestValidator.validateTokenRequestToRecord(
                requestPayload.code as string,
                sessionItem,
                clientConfig.get(ClientConfigKey.JWT_REDIRECT_URI) as string,
            );

            logger.info("Token request validated");
            await this.requestValidator.verifyJwtSignature(
                requestPayload.client_assertion,
                sessionItem.clientId,
                clientConfig as Map<string, string>,
            );
            logger.info("JWT signature verified");

            const accessTokenResponse = await this.bearerAccessTokenFactory.create();
            await this.sessionService.createAccessTokenCode(sessionItem, accessTokenResponse);

            logger.info("Access token created");
            metrics.addMetric(ACCESS_TOKEN, MetricUnits.Count, 1);
            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });

            return {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse),
            };
        } catch (err: unknown) {
            metrics.addMetric(ACCESS_TOKEN, MetricUnits.Count, 0);
            return errorPayload(err as Error, logger, "Access Token Lambda error occurred");
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
const jwtVerifierFactory = new JwtVerifierFactory(logger);
const sessionService = new SessionService(dynamoDbClient, configService);
const accessTokenValidator = new AccessTokenRequestValidator(jwtVerifierFactory);
const handlerClass = new AccessTokenLambda(
    new BearerAccessTokenFactory(configService.getBearerAccessTokenTtl()),
    sessionService,
    accessTokenValidator,
);
export const lambdaHandler = middy(handlerClass.handler.bind(handlerClass))
    .use(errorMiddleware(logger, metrics, { metric_name: ACCESS_TOKEN, message: "Access Token Lambda error occurred" }))
    .use(injectLambdaContext(logger, { clearState: true }))
    .use(configurationInitMiddleware())
    .use(
        accessTokenValidatorMiddleware({
            requestValidator: accessTokenValidator,
        }),
    )
    .use(getSessionByAuthCodeMiddleware({ sessionService: sessionService }))
    .use(getSessionById({ sessionService: sessionService }))
    .use(setGovUkSigningJourneyIdMiddleware(logger));
