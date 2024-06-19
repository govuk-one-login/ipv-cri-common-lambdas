import middy from "@middy/core";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { MetricUnits } from "@aws-lambda-powertools/metrics";
import { ClientConfigKey, CommonConfigKey, ConfigKey } from "../types/config-keys";
import { SessionService } from "../services/session-service";
import { JweDecrypter } from "../services/security/jwe-decrypter";
import { PersonIdentityService } from "../services/person-identity-service";
import { PersonIdentity } from "../types/person-identity";
import { SessionRequestValidatorFactory } from "../services/session-request-validator";
import { AuditService } from "../common/services/audit-service";
import { AuditEventType } from "../types/audit-event";
import { SessionRequestSummary } from "../types/session-request-summary";
import { JWTPayload } from "jose";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { getClientIpAddress, getEncodedDeviceInformation } from "../common/utils/request-utils";
import { errorPayload } from "../common/utils/errors";
import { logger, metrics, tracer as _tracer } from "../common/utils/power-tool";
import errorMiddleware from "../middlewares/error/error-middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/lib/middleware/middy";
import initialiseConfigMiddleware from "../middlewares/config/initialise-config-middleware";
import decryptJweMiddleware from "../middlewares/jwt/decrypt-jwe-middleware";
import initialiseClientConfigMiddleware from "../middlewares/config/initialise-client-config-middleware";
import validateJwtMiddleware from "../middlewares/jwt/validate-jwt-middleware";
import setGovUkSigningJourneyIdMiddleware from "../middlewares/session/set-gov-uk-signing-journey-id-middleware";
import { ConfigService } from "../common/config/config-service";
import { EvidenceRequest } from "../services/evidence_request";

const dynamoDbClient = createClient(AwsClientType.DYNAMO);
const sqsClient = createClient(AwsClientType.SQS);
const kmsClient = createClient(AwsClientType.KMS);
const criIdentifier = process.env.CRI_IDENTIFIER || "";
const SESSION_CREATED_METRIC = "session_created";

export class SessionLambda implements LambdaInterface {
    constructor(
        private readonly sessionService: SessionService,
        private readonly personIdentityService: PersonIdentityService,
        private readonly auditService: AuditService,
    ) {}

    @_tracer.captureLambdaHandler({ captureResponse: false })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, _context: unknown): Promise<APIGatewayProxyResult> {
        try {
            const jwtPayload = event.body as unknown as JWTPayload;

            logger.info("Session lambda triggered");
            const clientIpAddress = getClientIpAddress(event);
            const encodedDeviceInformation = getEncodedDeviceInformation(event);
            const sessionRequestSummary = this.createSessionRequestSummary(jwtPayload, clientIpAddress);
            const sessionId: string = await this.sessionService.saveSession(sessionRequestSummary);
            logger.info("Session created");

            if (jwtPayload.shared_claims) {
                await this.personIdentityService.savePersonIdentity(
                    jwtPayload.shared_claims as PersonIdentity,
                    sessionId,
                );
                logger.info("Personal identity created");
            }

            await this.sendAuditEvent(
                sessionId,
                sessionRequestSummary,
                clientIpAddress,
                encodedDeviceInformation,
                jwtPayload["evidence_requested"] as string,
            );
            metrics.addDimension("issuer", sessionRequestSummary.clientId);
            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 1);

            return {
                statusCode: 201,
                body: JSON.stringify({
                    session_id: sessionId,
                    state: jwtPayload.state,
                    redirect_uri: jwtPayload.redirect_uri,
                }),
            };
        } catch (err: unknown) {
            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 0);
            return errorPayload(err as Error, logger, "Session Lambda error occurred");
        }
    }

    private createSessionRequestSummary(jwtPayload: JWTPayload, clientIpAddress?: string): SessionRequestSummary {
        return {
            clientId: jwtPayload["client_id"] as string,
            clientIpAddress: clientIpAddress as string,
            clientSessionId: jwtPayload["govuk_signin_journey_id"] as string,
            persistentSessionId: jwtPayload["persistent_session_id"] as string,
            redirectUri: jwtPayload["redirect_uri"] as string,
            state: jwtPayload["state"] as string,
            subject: jwtPayload.sub as string,
            evidenceRequested: jwtPayload["evidence_requested"] as EvidenceRequest,
        };
    }

    private async sendAuditEvent(
        sessionId: string,
        sessionRequest: SessionRequestSummary,
        clientIpAddress?: string,
        encodedDeviceInformation?: string,
        evidenceRequested?: string,
    ) {
        await this.auditService.sendAuditEvent(AuditEventType.START, {
            clientIpAddress: clientIpAddress,
            sessionItem: {
                sessionId,
                subject: sessionRequest.subject,
                persistentSessionId: sessionRequest.persistentSessionId,
                clientSessionId: sessionRequest.clientSessionId,
            },
            ...(encodedDeviceInformation && {
                personIdentity: {
                    device_information: {
                        encoded: encodedDeviceInformation,
                    },
                },
            }),
            ...(evidenceRequested && {
                extensions: {
                    evidence: {
                        context: "identity_check",
                    },
                },
            }),
        });
    }
}
const ssmClient = createClient(AwsClientType.SSM);
const configService = new ConfigService(ssmClient);
const jweDecrypter = new JweDecrypter(kmsClient, () => configService.getConfigEntry(CommonConfigKey.DECRYPTION_KEY_ID));
const jwtValidatorFactory = new SessionRequestValidatorFactory(logger);
const handlerClass = new SessionLambda(
    new SessionService(dynamoDbClient, configService),
    new PersonIdentityService(dynamoDbClient, configService),
    new AuditService(() => configService.getAuditConfig(), sqsClient),
);
export const lambdaHandler = middy(handlerClass.handler.bind(handlerClass))
    .use(
        errorMiddleware(logger, metrics, {
            metric_name: SESSION_CREATED_METRIC,
            message: "Session Lambda error occurred",
        }),
    )
    .use(injectLambdaContext(logger, { clearState: true }))
    .use(
        initialiseConfigMiddleware({
            configService: configService,
            config_keys: [
                CommonConfigKey.SESSION_TABLE_NAME,
                CommonConfigKey.SESSION_TTL,
                CommonConfigKey.PERSON_IDENTITY_TABLE_NAME,
                CommonConfigKey.DECRYPTION_KEY_ID,
                CommonConfigKey.VC_ISSUER,
            ],
        }),
    )
    .use(decryptJweMiddleware(logger, { jweDecrypter: jweDecrypter }))
    .use(
        initialiseClientConfigMiddleware({
            configService: configService,
            client_config_keys: [
                ClientConfigKey.JWT_AUDIENCE,
                ClientConfigKey.JWT_ISSUER,
                ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
                ClientConfigKey.JWT_REDIRECT_URI,
                ClientConfigKey.JWT_SIGNING_ALGORITHM,
            ],
            client_absolute_paths: [
                { prefix: criIdentifier, suffix: ConfigKey.STRENGTH_SCORE },
                { prefix: criIdentifier, suffix: ConfigKey.CRI_EVIDENCE_PROPERTIES },
            ],
        }),
    )
    .use(validateJwtMiddleware(logger, { configService: configService, jwtValidatorFactory: jwtValidatorFactory }))
    .use(setGovUkSigningJourneyIdMiddleware(logger));
