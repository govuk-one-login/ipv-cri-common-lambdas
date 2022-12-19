import {APIGatewayProxyEvent, APIGatewayProxyResult} from "aws-lambda";
import {SessionService} from "./services/session-service";
import {DynamoDbClient} from "./lib/dynamo-db-client";
import {LambdaInterface} from '@aws-lambda-powertools/commons';
import {Metrics, MetricUnits} from "@aws-lambda-powertools/metrics";
import {Logger} from "@aws-lambda-powertools/logger";
import {SsmClient} from "./lib/param-store-client";
import {ConfigService} from "./services/config-service";

const logger = new Logger();
const metrics = new Metrics();
const configService = new ConfigService(SsmClient);
const initPromise = configService.init();

class AuthorizationLambda implements LambdaInterface {
    @logger.injectLambdaContext({clearState: true})
    @metrics.logMetrics({throwOnEmptyMetrics: false, captureColdStartMetric: true})
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {

        let response: APIGatewayProxyResult;
        try {
            await initPromise;

            const sessionId = event.headers["session-id"] as string;
            if (!sessionId) {
                response = {
                    statusCode: 400,
                    body: "Missing header: session-id is required",
                };
                return response;
            }
            const sessionService = new SessionService(configService.config.SessionTableName, DynamoDbClient);
            const sessionItem = await sessionService.getSession(sessionId);

            logger.appendKeys({"govuk_signin_journey_id": sessionItem.clientSessionId});
            logger.info("found session");

            if (!sessionItem.authorizationCode) {
                await sessionService.createAuthorizationCode(sessionItem);
                logger.info("Authorization code not present. Authorization code generated successfully.");
            }

            // @ts-ignore
            const authorizationResponse = {
                state: {
                    value: event.queryStringParameters["state"]
                },
                authorizationCode: {
                    value: sessionItem.authorizationCode
                },
                redirectionURI: event.queryStringParameters["redirect_uri"]
            };

            metrics.addMetric('authorization_sent', MetricUnits.Count, 1);

            response = {
                statusCode: 200,
                body: JSON.stringify(authorizationResponse)
            };
        } catch (err: any) {
            // eslint-disable-next-line no-console
            logger.error("authorization lambda error occurred/", err);
            response = {
                statusCode: 500,
                body: "An error has occurred. " + JSON.stringify(err),
            };
        }
        return response;
    }
}

const handlerClass = new AuthorizationLambda();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
