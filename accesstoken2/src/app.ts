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
            const requestPayload = event.body as string;
            let validationResult = await this.accessTokenValidator.validatePayload(requestPayload);
            if (!validationResult.isValid) {
                return {
                    statusCode: 400,
                    body: `Invalid request: ${validationResult.errorMsg}`,
                };
            }

            const searchParams = new URLSearchParams(requestPayload);
            const authCode = searchParams.get("code");
            const client_assertion = searchParams.get("client_assertion") as string
            if (!authCode) {
                return {
                    statusCode: 400,
                    body: `Invalid request: ${validationResult.errorMsg}`,
                };
            }

            const sessionItem = await this.sessionService.getSessionByAuthorizationCode(authCode);
            if (!sessionItem) {
                return {
                    statusCode: 400,
                    body: `Invalid sessionItem`,
                };
            }

            logger.appendKeys({ govuk_signin_journey_id: sessionItem.clientSessionId });

            validationResult = await this.accessTokenValidator.validateTokenRequestToRecord(
                authCode,
                sessionItem
            );
            const expectedAudience = await configService.getJwtAudience(sessionItem.clientId);
            if (!expectedAudience) {
                throw new Error("audience is missing");
            }
            const jwtPayload = await this.accessTokenValidator.verifyJwtSignature(
                Buffer.from(client_assertion, "utf-8"), 
                sessionItem.clientId,
                expectedAudience
            );
            if (!jwtPayload.jti) {
                throw new Error("jti is missing");
            }

            if (!validationResult.isValid) {
                // Todo: tidy up error handling
                if (validationResult.errorMsg === "Authorisation code does not match") {
                    return {
                        statusCode: 403,
                        body: JSON.stringify({
                            message: "Invalid request: Access token expired",
                            code: 1026,
                        }),
                    };
                } else {
                    return {
                        statusCode: 400,
                        body: `Invalid request: ${validationResult.errorMsg}`,
                    };
                }
            }
            const bearerAccessTokenTTL = configService.getBearerAccessTokenTtl();
            const accessTokenResponse = await this.accessTokenService.createBearerAccessToken(bearerAccessTokenTTL);
            this.sessionService.createAccessTokenCode(sessionItem, accessTokenResponse);

            return {
                statusCode: 200,
                body: JSON.stringify(accessTokenResponse),
            };
        } catch (err: any) {
            logger.error(`Access token lambda error occurred ${err}`);

            // TODO: redo error handling
            if (err.message === "Could not find session Item") {
                return {
                    statusCode: 403,
                    body: JSON.stringify({
                        message: "Access token expired",
                        code: 1026,
                        errorSummary: "1026: Access token expired",
                    }),
                };
            }

            return {
                statusCode: 500,
                body: "An error has occurred. " + JSON.stringify(err),
            };
        }
    }
}

const aService = new AccessTokenRequestValidator(configService, new JwtVerifier(configService));
const sService = new SessionService(DynamoDbClient, configService);
const handlerClass = new AccessTokenLambda(new AccessTokenService(), sService, aService);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
