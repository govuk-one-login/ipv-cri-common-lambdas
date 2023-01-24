import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SessionService } from "../services/session-service";
import { DynamoDbClient } from "../lib/dynamo-db-client";
import { SsmClient } from "../lib/param-store-client";
import { ConfigService } from "../services/config-service";
import { AccessTokenRequestValidator } from "../services/token-request-validator";
import { AccessTokenService } from "../services/access-token-service";
import { JwtVerifier } from "../services/jwt-verifier";

const logger = new Logger();
const metrics = new Metrics();

const configService = new ConfigService(SsmClient);
const initPromise = configService.init();

export class AccessTokenLambda implements LambdaInterface {
    constructor(
        private accessTokenService: AccessTokenService,
        private sessionService: SessionService,
        private accessTokenValidator: AccessTokenRequestValidator,
    ) {}

    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        try {
            await initPromise;

            const requestPayload = this.accessTokenValidator.validatePayload(event.body);
            const sessionItem = await this.sessionService.getSessionByAuthorizationCode(requestPayload.code);
            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });

            this.accessTokenValidator.validateTokenRequestToRecord(requestPayload.code, sessionItem);

            const expectedAudience = await configService.getJwtAudience(sessionItem.clientId);
            await this.accessTokenValidator.verifyJwtSignature(
                Buffer.from(requestPayload.client_assertion, "utf-8"),
                sessionItem.clientId,
                expectedAudience,
            );

            const bearerAccessTokenTTL = configService.getBearerAccessTokenTtl();
            const accessTokenResponse = await this.accessTokenService.createBearerAccessToken(bearerAccessTokenTTL);
            this.sessionService.createAccessTokenCode(sessionItem, accessTokenResponse);

            return {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse),
            };
        } catch (err: any) {
            //Todo dont want any
            logger.error({
                statusCode: err.statusCode ?? 500,
                message: err?.message,
                err: err,
            });
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
}

const aService = new AccessTokenRequestValidator(configService, new JwtVerifier(configService));
const sService = new SessionService(DynamoDbClient, configService);
const handlerClass = new AccessTokenLambda(new AccessTokenService(), sService, aService);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
