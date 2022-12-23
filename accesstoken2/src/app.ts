import {APIGatewayProxyEvent, APIGatewayProxyResult} from "aws-lambda";
import {LambdaInterface} from '@aws-lambda-powertools/commons';
import {Metrics, MetricUnits} from "@aws-lambda-powertools/metrics";
import {Logger} from "@aws-lambda-powertools/logger";
import {SessionService} from "./services/session-service";
import {DynamoDbClient} from "./lib/dynamo-db-client";
import {SsmClient} from "./lib/param-store-client";
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
        console.log("EVENT BODY===>>"+ JSON.stringify(event.body));
        let response: APIGatewayProxyResult;
        try {
            await initPromise;
            console.log('Reached AccessTokenLambda TYPESCRIPT ****************** 23');
            // const sessionId = event.headers["session-id"] as string;
            // if (!sessionId) {
            //     console.log('Reached AccessTokenLambda TYPESCRIPT ****************** 26');
            //     response = {
            //         statusCode: 400,
            //         body: "Missing header: session-id is required",
            //     };
            //     return response;
            // }

        
    //validate the incoming payload
    const validationResult = await new AccessTokenRequestValidator(configService).validate(event.body);
    if (!validationResult.isValid) {
        console.log('Reached AccessTokenLambda TYPESCRIPT ****************** 38');
        return {
            statusCode: 400,
            body: `Invalid request: ${validationResult.errorMsg}`
        };
    }

    //create token request object
    const requestParams = event.body;
    if (!event.body) {

        return {
            statusCode: 400,
            body: `Invalid request: ${validationResult.errorMsg}`
        };

       
    }
    const searchParams = new URLSearchParams(event.body);
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

    console.log('Session Item =>'+ JSON.stringify(sessionItem));

  
            // logger.appendKeys({"govuk_signin_journey_id": sessionItem.clientSessionId});
            // logger.info("found session");

            // if (!sessionItem.authorizationCode) {
            //     await sessionService.createAuthorizationCode(sessionItem);
            //     logger.info("Authorization code not present. Authorization code generated successfully.");
            // }

            // // @ts-ignore
            // const authorizationResponse = {
            //     state: {
            //         value: event.queryStringParameters["state"]
            //     },
            //     authorizationCode: {
            //         value: sessionItem.authorizationCode
            //     },
            //     redirectionURI: event.queryStringParameters["redirect_uri"]
            // };

            // metrics.addMetric('authorization_sent', MetricUnits.Count, 1);
            console.log('Reached in the result section');
            const jsonBody = {
                "access_token": "string",
                "token_type": "Bearer",
                "expires_in": "3600",
                "refresh_token": "string"
              };

            response = {
                statusCode: 200,
                body: JSON.stringify(jsonBody)
            };
        } catch (err) {
            // eslint-disable-next-line no-console
            logger.error("access token lambda error occurred/", err);
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