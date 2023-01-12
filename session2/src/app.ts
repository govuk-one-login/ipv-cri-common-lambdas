import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SsmClient } from "./lib/param-store-client";
import { ConfigService } from "./services/config-service";
import { SessionService } from "./services/session-service";
import { JwtVerifier } from "./services/jwt-verifier";
import { JweDecrypter } from "./services/jwe-decrypter";
import { DynamoDbClient } from "./lib/dynamo-db-client";
import { PersonIdentityService } from "./services/person-identity-service";
import { SharedClaims } from "./services/shared-claims";
import { SessionRequestValidator } from "./services/session-request-validator";

const logger = new Logger();
const metrics = new Metrics();
const configService = new ConfigService(SsmClient);
const initPromise = configService.init();
const SESSION_CREATED_METRIC = "session_created";
const sessionRequestValidator = new SessionRequestValidator(configService, new JwtVerifier(configService, logger));

class SessionLambda implements LambdaInterface {
    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        try {
            await initPromise;
            const deserialisedRequestBody = JSON.parse(event.body!);
            const requestBodyClientId = deserialisedRequestBody.client_id;
            let decryptedJwt = null;
            try {
                decryptedJwt = await new JweDecrypter(configService).decryptJwe(deserialisedRequestBody.request);
            } catch (e) {
                logger.error("Invalid request - JWE decryption failed", e as Error);
                return {
                    statusCode: 400,
                    body: "Invalid request: JWE decryption failed",
                };
            }

            const jwtValidationResult = await sessionRequestValidator.validateJwt(decryptedJwt, requestBodyClientId);
            if (!jwtValidationResult.isValid) {
                return {
                    statusCode: 400,
                    body: `Invalid request: JWT validation/verification failed: ${jwtValidationResult.errorMsg}`,
                };
            }

            const jwtPayload = jwtValidationResult.validatedObject;
            const sessionService = new SessionService(DynamoDbClient, configService);
            const clientIpAddress = this.getClientIpAddress(event);
            metrics.addDimension("issuer", requestBodyClientId);
            const sessionId: string = await sessionService.saveSession({
                clientId: jwtPayload.client_id,
                redirectUri: jwtPayload.redirect_uri,
                subject: jwtPayload.sub,
                persistentSessionId: jwtPayload.persistent_session_id,
                clientSessionId: jwtPayload.govuk_signin_journey_id,
                clientIpAddress: clientIpAddress ?? null,
            });

            logger.appendKeys({ govuk_signin_journey_id: sessionId });
            logger.info("created session");

            if (jwtPayload.shared_claims) {
                await new PersonIdentityService(DynamoDbClient, configService).savePersonIdentity(
                    jwtPayload.shared_claims as SharedClaims,
                    sessionId,
                );
            }

            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 1);

            return {
                statusCode: 201,
                body: JSON.stringify({
                    session_id: sessionId,
                    state: jwtPayload.state,
                    redirect_uri: jwtPayload.redirect_uri,
                }),
            };
        } catch (err) {
            logger.error("session lambda error occurred.", err as Error);
            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 0);
            return {
                statusCode: 500,
                body: `An error has occurred. ${JSON.stringify(err)}`,
            };
        }
    }
    private getClientIpAddress(event: APIGatewayProxyEvent): string | undefined {
        if (event.headers) {
            const ipAddressHeader = "x-forwarded-for";
            const ipAddressHeaders: string[] = Object.keys(event.headers).filter(
                (header) => header.toLowerCase().trim() === ipAddressHeader,
            );
            if (ipAddressHeaders.length === 1) {
                return event.headers[ipAddressHeaders[0]];
            }
            logger.warn(`Unexpected quantity of ${ipAddressHeader} headers encountered: ${ipAddressHeaders.length}`);
        }
        return undefined;
    }
}

const handlerClass = new SessionLambda();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
