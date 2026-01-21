import middy from "@middy/core";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { SessionService } from "../services/session-service";
import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { MetricUnit } from "@aws-lambda-powertools/metrics";
import { ConfigService } from "../common/config/config-service";
import { AuthorizationRequestValidator } from "../services/auth-request-validator";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { ClientConfigKey, CommonConfigKey } from "../types/config-keys";
import { AccessDeniedError, errorPayload } from "../common/utils/errors";
import { metrics, tracer as _tracer } from "../common/utils/power-tool";
import errorMiddleware from "../middlewares/error/error-middleware";
import initialiseConfigMiddleware from "../middlewares/config/initialise-config-middleware";
import getSessionByIdMiddleware from "../middlewares/session/get-session-by-id-middleware";
import { SessionItem } from "../types/session-item";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import setGovUkSigningJourneyIdMiddleware from "../middlewares/session/set-gov-uk-signing-journey-id-middleware";
import initialiseClientConfigMiddleware from "../middlewares/config/initialise-client-config-middleware";
import setRequestedVerificationScoreMiddleware from "../middlewares/session/set-requested-verification-score-middleware";
import { SSMProvider } from "@aws-lambda-powertools/parameters/ssm";
import { initOpenTelemetry } from "../common/utils/otel-setup";
import { logger } from "@govuk-one-login/cri-logger";

initOpenTelemetry();

const dynamoDbClient = createClient(AwsClientType.DYNAMO);
const ssmClient = createClient(AwsClientType.SSM);
const configService = new ConfigService(new SSMProvider({ awsSdkV3Client: ssmClient }));
const AUTHORIZATION_SENT_METRIC = "authorization_sent";

export class AuthorizationLambda implements LambdaInterface {
    constructor(private readonly authorizationRequestValidator: AuthorizationRequestValidator) {}

    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    @_tracer.captureLambdaHandler({ captureResponse: false })
    public async handler(event: APIGatewayProxyEvent, _context: unknown): Promise<APIGatewayProxyResult> {
        try {
            logger.info("Authorisation Lambda triggered");

            const sessionItem = event.body as unknown as SessionItem;
            logger.info("Session found");
            const clientConfig = configService.getClientConfig(sessionItem.clientId);

            logger.info("Validating session");
            this.authorizationRequestValidator.validate(
                event.queryStringParameters,
                sessionItem.clientId,
                clientConfig?.get(ClientConfigKey.JWT_REDIRECT_URI) as string,
            );
            logger.info("Session validated");

            if (!sessionItem.authorizationCode) {
                throw new AccessDeniedError();
            }

            const authorizationResponse = {
                state: {
                    value: event.queryStringParameters?.["state"],
                },
                authorizationCode: {
                    value: sessionItem.authorizationCode,
                },
                redirectionURI: event.queryStringParameters?.["redirect_uri"],
            };

            logger.info("Authorisation response created");
            metrics.addMetric(AUTHORIZATION_SENT_METRIC, MetricUnit.Count, 1);

            return {
                statusCode: 200,
                body: JSON.stringify(authorizationResponse),
            };
        } catch (err: unknown) {
            metrics.addMetric(AUTHORIZATION_SENT_METRIC, MetricUnit.Count, 0);
            return errorPayload(err as Error, logger, "Authorization Lambda error occurred");
        }
    }
}
const sessionService = new SessionService(dynamoDbClient, configService);
const handlerClass = new AuthorizationLambda(new AuthorizationRequestValidator());
export const lambdaHandler = middy(handlerClass.handler.bind(handlerClass))
    .use(
        errorMiddleware(logger, metrics, {
            metric_name: AUTHORIZATION_SENT_METRIC,
            message: "Authorization Lambda error occurred",
        }),
    )
    .use(injectLambdaContext(logger, { clearState: true }))
    .use(
        initialiseConfigMiddleware({
            configService: configService,
            config_keys: [CommonConfigKey.SESSION_TABLE_NAME],
        }),
    )
    .use(getSessionByIdMiddleware({ sessionService: sessionService }))
    .use(
        initialiseClientConfigMiddleware({
            configService: configService,
            client_config_keys: [ClientConfigKey.JWT_REDIRECT_URI],
        }),
    )
    .use(setGovUkSigningJourneyIdMiddleware(logger))
    .use(setRequestedVerificationScoreMiddleware(logger));
