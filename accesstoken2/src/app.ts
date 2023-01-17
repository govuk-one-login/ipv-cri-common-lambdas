import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SessionService } from "./services/session-service";
import { DynamoDbClient } from "./lib/dynamo-db-client";
import { SsmClient } from "./lib/param-store-client";
import { ConfigService } from "./services/config-service";
import { AccessTokenRequestValidator } from "./services/token-request-validator";
import { AccessTokenService } from "./services/access-token-service";
import { JwtVerifier } from "./services/jwt-verifier";
import { InvalidAccessTokenError, InvalidRequestError } from "./types/errors";

const logger = new Logger();
const metrics = new Metrics();

const configService = new ConfigService(SsmClient);
const initPromise = configService.init();

export class AccessTokenLambda implements LambdaInterface {
    constructor(
        private accessTokenService: AccessTokenService,
        private sessionService: SessionService,
        private accessTokenValidator: AccessTokenRequestValidator,
    ) { }

    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        try {
            await initPromise;

            // validate the incoming payload
            const requestPayload = event.body;
            if (!requestPayload) {
                throw new InvalidRequestError("Invalid request: missing body");
            }

            this.accessTokenValidator.validatePayload(requestPayload);

            const searchParams = new URLSearchParams(requestPayload);
            const authCode = searchParams.get("code") as string;
            const sessionItem = await this.sessionService.getSessionByAuthorizationCode(authCode);

            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });

            this.accessTokenValidator.validateTokenRequestToRecord(
                authCode,
                sessionItem
            );

            const expectedAudience = await configService.getJwtAudience(sessionItem.clientId);
            if (!expectedAudience) {
                throw new InvalidRequestError("audience is missing");
            }

            const client_assertion = searchParams.get("client_assertion") as string
            const jwtPayload = await this.accessTokenValidator.verifyJwtSignature(
                Buffer.from(client_assertion, "utf-8"),
                sessionItem.clientId,
                expectedAudience
            );
            if (!jwtPayload.jti) {
                throw new InvalidRequestError("jti is missing");
            }

            const bearerAccessTokenTTL = configService.getBearerAccessTokenTtl();
            const accessTokenResponse = await this.accessTokenService.createBearerAccessToken(bearerAccessTokenTTL);
            this.sessionService.createAccessTokenCode(sessionItem, accessTokenResponse);

            return {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse),
            };
        } catch (err: any) { //Todo dont want any
            logger.error({
                statusCode: err.statusCode ?? 500,
                message: err.message,
                err: err
            });

            return {
                statusCode: err.statusCode ?? 500,
                body: JSON.stringify({
                    message: err.statusCode >= 500 ? "Server error" : err.message,
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
