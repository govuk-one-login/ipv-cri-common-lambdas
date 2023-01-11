import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SessionService } from "./services/session-service";
import { DynamoDbClient } from "./lib/dynamo-db-client";
import { SsmClient } from "./lib/param-store-client";
import { ConfigService } from "./services/config-service";
import { AccessTokenRequestValidator } from "./services/token-request-validator";
import { AccessTokenService } from "./services/access-token-service";

const logger = new Logger();
const metrics = new Metrics();

const configService = new ConfigService(SsmClient);
const initPromise = configService.init();

class AccessTokenLambda implements LambdaInterface {
    constructor(private accessTokenService: AccessTokenService) {}

    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        logger.info(`AccessTokenLambda: ${JSON.stringify(event.body)}`);
        let response: APIGatewayProxyResult;
        try {
            await initPromise;

            //validate the incoming payload
            const requestPayload = event.body;
            if (!requestPayload) {
                return {
                    statusCode: 400,
                    body: `Invalid request missing body`,
                };
            }
            const accessTokenRequestValidator = new AccessTokenRequestValidator(configService);

            let validationResult = await accessTokenRequestValidator.validate(requestPayload);
            if (!validationResult.isValid) {
                return {
                    statusCode: 400,
                    body: `Invalid request: ${validationResult.errorMsg}`,
                };
            }

            const searchParams = new URLSearchParams(requestPayload);
            const sessionService = new SessionService(DynamoDbClient, configService);
            const authCode = searchParams.get("code");
            if (!authCode) {
                return {
                    statusCode: 400,
                    body: `Invalid request: ${validationResult.errorMsg}`,
                };
            }
            const sessionItem = await sessionService.getSessionByAuthorizationCode(authCode);
            if (!sessionItem) {
                return {
                    statusCode: 400,
                    body: `Invalid sessionItem`,
                };
            }

            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });
            logger.info("found session: " + JSON.stringify(sessionItem));

            validationResult = await accessTokenRequestValidator.validateTokenRequest(
                authCode,
                sessionItem,
                searchParams.get("client_assertion") as string,
            );
            // if (!validationResult.isValid) {
            //     return {
            //         statusCode: 400,
            //         body: `Invalid request: ${validationResult.errorMsg}`
            //     };
            // }
            //TODO:

            //updateSessionAccessToken(sessionItem, accessTokenResponse);
            //sessionService.updateSession(sessionItem);

            console.log("Success point");
            const bearerAccessTokenTTL = configService.getBearerAccessTokenTtl();
            console.log(`bearerAccessTokenTTL ${JSON.stringify(bearerAccessTokenTTL)}`);
            // @ts-ignore
            const accessTokenResponse = await this.accessTokenService.createBearerAccessToken(bearerAccessTokenTTL);
            console.log(`accessTokenResponse ${JSON.stringify(accessTokenResponse)}`);
            sessionService.createAccessTokenCode(sessionItem, accessTokenResponse);

            return {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse),
            };
        } catch (err) {
            // eslint-disable-next-line no-console
            logger.error(`access token lambda error occurred ${err}`);
            return {
                statusCode: 500,
                body: "An error has occurred. " + JSON.stringify(err),
            };
        }
    }
}

const handlerClass = new AccessTokenLambda(new AccessTokenService());
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
