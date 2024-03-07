import middy from "@middy/core";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { SessionService } from "../services/session-service";
import { AccessTokenRequestValidator } from "../services/token-request-validator";
import { JwtVerifierFactory } from "../common/security/jwt-verifier";
import { ClientConfigKey, CommonConfigKey } from "../types/config-keys";
import { BearerAccessTokenFactory } from "../services/bearer-access-token-factory";
import { errorPayload } from "../common/utils/errors";
import { SessionItem } from "../types/session-item";
import accessTokenValidatorMiddleware from "../middlewares/access-token/validate-event-payload-middleware";
import initialiseConfigMiddleware from "../middlewares/config/initialise-config-middleware";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import setGovUkSigningJourneyIdMiddleware from "../middlewares/session/set-gov-uk-signing-journey-id-middleware";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import getSessionByAuthCodeMiddleware from "../middlewares/session/get-session-by-auth-code-middleware";
import { logger, metrics, tracer as _tracer } from "../common/utils/power-tool";
import { MetricUnits } from "@aws-lambda-powertools/metrics";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/lib/middleware/middy";
import { RequestPayload } from "../types/request_payload";
import getSessionByIdMiddleware from "../middlewares/session/get-session-by-id-middleware";
import errorMiddleware from "../middlewares/error/error-middleware";
import { ConfigService } from "../common/config/config-service";
import initialiseClientConfigMiddleware from "../middlewares/config/initialise-client-config-middleware";
const dynamoDbClient = createClient(AwsClientType.DYNAMO);
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
            const clientConfig = configService.getClientConfig(sessionItem.clientId);

            this.requestValidator.validateTokenRequestToRecord(
                requestPayload.code,
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
            await this.sessionService.createAccessTokenCodeAndRemoveAuthCode(sessionItem, accessTokenResponse);

            logger.info("Access token created");
            metrics.addMetric(ACCESS_TOKEN, MetricUnits.Count, 1);

            return {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse),
            };
        } catch (err: unknown) {
            metrics.addMetric(ACCESS_TOKEN, MetricUnits.Count, 0);
            return errorPayload(err as Error, logger, "Access Token Lambda error occurred");
        }
    }
}
const ssmClient = createClient(AwsClientType.SSM);
const configService = new ConfigService(ssmClient);
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
    .use(
        initialiseConfigMiddleware({
            configService: configService,
            config_keys: [CommonConfigKey.SESSION_TABLE_NAME, CommonConfigKey.SESSION_TTL],
        }),
    )
    .use(
        accessTokenValidatorMiddleware({
            requestValidator: accessTokenValidator,
        }),
    )
    .use(getSessionByAuthCodeMiddleware({ sessionService: sessionService }))
    .use(
        initialiseClientConfigMiddleware({
            configService: configService,
            client_config_keys: [
                ClientConfigKey.JWT_AUDIENCE,
                ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
                ClientConfigKey.JWT_REDIRECT_URI,
                ClientConfigKey.JWT_SIGNING_ALGORITHM,
            ],
        }),
    )
    .use(getSessionByIdMiddleware({ sessionService: sessionService }))
    .use(setGovUkSigningJourneyIdMiddleware(logger));
