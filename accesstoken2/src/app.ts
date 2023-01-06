import {APIGatewayProxyEvent, APIGatewayProxyResult} from "aws-lambda";
import {LambdaInterface} from '@aws-lambda-powertools/commons';
import {Metrics, MetricUnits} from "@aws-lambda-powertools/metrics";
import {Logger} from "@aws-lambda-powertools/logger";
import {SessionService} from "./services/session-service";
import {DynamoDbClient} from "./lib/dynamo-db-client";
import {SsmClient} from './lib/param-store-client';
import {ConfigService} from "./services/config-service";
import {AccessTokenRequestValidator} from './services/token-request-validator';
const logger = new Logger();
const metrics = new Metrics();

const configService = new ConfigService(SsmClient);
const initPromise = configService.init();

class AccessTokenLambda implements LambdaInterface {
    @logger.injectLambdaContext({clearState: true})
    @metrics.logMetrics({throwOnEmptyMetrics: false, captureColdStartMetric: true})
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
            body: `Invalid request missing body`
        };
    }
    const accessTokenRequestValidator =  new AccessTokenRequestValidator(configService);

    let validationResult = await accessTokenRequestValidator.validate(requestPayload);
    if (!validationResult.isValid) {
        return {
            statusCode: 400,
            body: `Invalid request: ${validationResult.errorMsg}`
        };
    }
   
    const searchParams = new URLSearchParams(requestPayload);
    const sessionService = new SessionService(DynamoDbClient, configService);
    const authCode = searchParams.get('code');
    if(!authCode){
        return {
            statusCode: 400,
            body: `Invalid request: ${validationResult.errorMsg}`
        };
    }
    const sessionItem = await sessionService.getSessionByAuthorizationCode(authCode);
    if(!sessionItem){
        return {
            statusCode: 400,
            body: `Invalid sessionItem`
        };
    }

    logger.appendKeys({"govuk_signin_journey_id": sessionItem.clientSessionId});
    logger.info("found session: "+ JSON.stringify(sessionItem) );

    validationResult = await accessTokenRequestValidator.validateTokenRequest(authCode, sessionItem, searchParams.get('client_assertion') as string);
    if (!validationResult.isValid) {
        return {
            statusCode: 400,
            body: `Invalid request: ${validationResult.errorMsg}`
        };
    }
    //TODO:
    //createToken(tokenRequest);
    //updateSessionAccessToken(sessionItem, accessTokenResponse);
    //sessionService.updateSession(sessionItem);
    console.log('Success point');
          // @ts-ignore
            const accessTokenResponse = {
                    "access_token": "new-access-token",
                    "token_type": "Bearer",
                    "expires_in": "3600",
                    "refresh_token": "string"
            };
            response = {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse)
            };
        } catch (err) {
            // eslint-disable-next-line no-console
            logger.error(`access token lambda error occurred ${err}`);
            response = {
                statusCode: 500,
                body: "An error has occurred. " + JSON.stringify(err),
            };
        }
        return response;
    }
}

const handlerClass = new AccessTokenLambda();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);