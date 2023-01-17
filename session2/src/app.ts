import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Tracer } from "@aws-lambda-powertools/tracer";
import { Logger } from "@aws-lambda-powertools/logger";
import { ConfigService } from "./services/config-service";
import { SessionService } from "./services/session-service";
import { JwtVerifier } from "./services/jwt-verifier";
import { JweDecrypter } from "./services/jwe-decrypter";
import { PersonIdentityService } from "./services/person-identity-service";
import { PersonIdentity } from "./services/person-identity";
import { SessionRequestValidator } from "./services/session-request-validator";
import { AuditService } from "./services/audit-service";
import { DynamoDbClient } from "./lib/dynamo-db-client";
import { SqsClient } from "./lib/sqs-client";
import { SsmClient } from "./lib/param-store-client";
import { AuditEventType } from "./services/audit-event";
import { SessionRequestSummary } from "./services/session-request-summary";
import { JWTPayload } from "jose";

const logger = new Logger();
const metrics = new Metrics();
const tracer = new Tracer({ captureHTTPsRequests: false });
const configService = new ConfigService(SsmClient);
const configInitPromise = configService.init();
const SESSION_CREATED_METRIC = "session_created";
const sessionRequestValidator = new SessionRequestValidator(configService, new JwtVerifier(configService, logger));

class SessionLambda implements LambdaInterface {
    @tracer.captureLambdaHandler({ captureResponse: false })
    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        try {
            await configInitPromise;
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

            const sessionRequestSummary = this.createSessionRequestSummary(jwtPayload, clientIpAddress);
            const sessionId: string = await sessionService.saveSession(sessionRequestSummary);

            logger.appendKeys({ govuk_signin_journey_id: sessionId });
            logger.info("created session");

            if (jwtPayload.shared_claims) {
                await new PersonIdentityService(DynamoDbClient, configService).savePersonIdentity(
                    jwtPayload.shared_claims as PersonIdentity,
                    sessionId,
                );
            }

            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 1);

            await this.sendAuditEvent(sessionId, sessionRequestSummary, clientIpAddress);

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
    private createSessionRequestSummary(
        jwtPayload: JWTPayload,
        clientIpAddress: string | undefined,
    ): SessionRequestSummary {
        return {
            clientId: jwtPayload["client_id"] as string,
            clientIpAddress: clientIpAddress ?? null,
            clientSessionId: jwtPayload["govuk_signin_journey_id"] as string,
            persistentSessionId: jwtPayload["persistent_session_id"] as string,
            redirectUri: jwtPayload["redirect_uri"] as string,
            state: jwtPayload["state"] as string,
            subject: jwtPayload.sub as string,
        };
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
    private async sendAuditEvent(
        sessionId: string,
        sessionRequest: SessionRequestSummary,
        clientIpAddress: string | undefined,
    ) {
        await new AuditService(configService, SqsClient).sendAuditEvent(AuditEventType.START, {
            clientIpAddress: clientIpAddress,
            sessionItem: {
                sessionId: sessionId,
                subject: sessionRequest.subject,
                persistentSessionId: sessionRequest.persistentSessionId,
                clientSessionId: sessionRequest.clientSessionId,
            },
        });
    }
}

const handlerClass = new SessionLambda();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
