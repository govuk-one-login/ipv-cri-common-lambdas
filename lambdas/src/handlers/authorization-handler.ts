import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { SessionService } from "../services/session-service";
import { DynamoDbClient } from "../lib/dynamo-db-client";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SsmClient } from "../lib/param-store-client";
import { ConfigService } from "../services/config-service";
import { AuthorizationRequestValidator } from "../services/auth-request-validator";

const logger = new Logger();
const metrics = new Metrics();
const configService = new ConfigService(SsmClient);
const initPromise = configService.init();
const AUTHORIZATION_SENT_METRIC = "authorization_sent";

class AuthorizationLambda implements LambdaInterface {
    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        try {
            await initPromise;

            const sessionId = event.headers["session-id"] as string;
            if (!sessionId) {
                return {
                    statusCode: 400,
                    body: "Invalid request: Missing session-id header",
                };
            }
            const sessionService = new SessionService(DynamoDbClient, configService);
            const sessionItem = await sessionService.getSession(sessionId);

            const validationResult = await new AuthorizationRequestValidator(configService).validate(
                event.queryStringParameters,
                sessionItem.clientId,
            );
            if (!validationResult.isValid) {
                const code = 1019;
                const message = "Session Validation Exception";
                return {
                    statusCode: 400,
                    body: JSON.stringify({
                        code,
                        message,
                        errorSummary: `${code}: ${message}`
                    })
                };
            }

            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });
            logger.info("found session");

            if (!sessionItem.authorizationCode) {
                await sessionService.createAuthorizationCode(sessionItem);
                logger.info("Authorization code not present. Authorization code generated successfully.");
            }

            const authorizationResponse = {
                state: {
                    value: event.queryStringParameters!["state"],
                },
                authorizationCode: {
                    value: sessionItem.authorizationCode,
                },
                redirectionURI: event.queryStringParameters!["redirect_uri"],
            };

            metrics.addMetric(AUTHORIZATION_SENT_METRIC, MetricUnits.Count, 1);

            return {
                statusCode: 200,
                body: JSON.stringify(authorizationResponse),
            };
        } catch (err: any) {
            logger.error("authorization lambda error occurred.", err);
            metrics.addMetric(AUTHORIZATION_SENT_METRIC, MetricUnits.Count, 0);
            return {
                statusCode: 500,
                body: `An error has occurred. ${JSON.stringify(err)}`,
            };
        }
    }
}

const handlerClass = new AuthorizationLambda();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
