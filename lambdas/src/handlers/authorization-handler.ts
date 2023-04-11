import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { SessionService } from "../services/session-service";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { ConfigService } from "../common/config/config-service";
import { AuthorizationRequestValidator } from "../services/auth-request-validator";
import { getSessionId } from "../common/utils/request-utils";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { SSMClient } from "@aws-sdk/client-ssm";
import { ClientConfigKey, CommonConfigKey } from "../types/config-keys";
import { Tracer } from "@aws-lambda-powertools/tracer";
import { errorPayload } from "../common/utils/errors";

const dynamoDbClient = createClient(AwsClientType.DYNAMO) as DynamoDBDocument;
const ssmClient = createClient(AwsClientType.SSM) as SSMClient;
const logger = new Logger();
const metrics = new Metrics();
const _tracer = new Tracer({ captureHTTPsRequests: false });
const configService = new ConfigService(ssmClient);
const initPromise = configService.init([CommonConfigKey.SESSION_TABLE_NAME]);
const AUTHORIZATION_SENT_METRIC = "authorization_sent";

export class AuthorizationLambda implements LambdaInterface {
    constructor(
        private readonly sessionService: SessionService,
        private readonly authorizationRequestValidator: AuthorizationRequestValidator,
    ) {}

    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    @_tracer.captureLambdaHandler({ captureResponse: false })
    public async handler(event: APIGatewayProxyEvent, _context: unknown): Promise<APIGatewayProxyResult> {
        try {
            await initPromise;
            logger.info("Authorisation Lambda triggered");

            const sessionId = getSessionId(event);
            const sessionItem = await this.sessionService.getSession(sessionId);
            logger.info("Session found");

            if (!configService.hasClientConfig(sessionItem.clientId)) {
                await configService.initClientConfig(sessionItem.clientId, [ClientConfigKey.JWT_REDIRECT_URI]);
            }
            const clientConfig = configService.getClientConfig(sessionItem.clientId);

            logger.info("Validating session");
            this.authorizationRequestValidator.validate(
                event.queryStringParameters,
                sessionItem.clientId,
                clientConfig?.get(ClientConfigKey.JWT_REDIRECT_URI) as string,
            );
            logger.info("Session validated");
            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });

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
            metrics.addMetric(AUTHORIZATION_SENT_METRIC, MetricUnits.Count, 1);

            return {
                statusCode: 200,
                body: JSON.stringify(authorizationResponse),
            };
        } catch (err: unknown) {
            metrics.addMetric(AUTHORIZATION_SENT_METRIC, MetricUnits.Count, 0);
            return errorPayload(err as Error, logger, "Authorization Lambda error occurred");
        }
    }
}

const handlerClass = new AuthorizationLambda(
    new SessionService(dynamoDbClient, configService),
    new AuthorizationRequestValidator(),
);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
