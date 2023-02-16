import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Tracer } from "@aws-lambda-powertools/tracer";
import { Logger } from "@aws-lambda-powertools/logger";
import { ConfigService } from "../common/config/config-service";
import { ClientConfigKey, CommonConfigKey } from "../types/config-keys";
import { SessionService } from "../services/session-service";
import { JweDecrypter } from "../services/security/jwe-decrypter";
import { PersonIdentityService } from "../services/person-identity-service";
import { PersonIdentity } from "../types/person-identity";
import { SessionRequestValidatorFactory } from "../services/session-request-validator";
import { AuditService } from "../common/services/audit-service";
import { AuditEventType } from "../types/audit-event";
import { SessionRequestSummary } from "../types/session-request-summary";
import { JWTPayload } from "jose";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { SSMClient } from "@aws-sdk/client-ssm";
import { SQSClient } from "@aws-sdk/client-sqs";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { getClientIpAddress } from "../common/utils/request-utils";
import { KMSClient } from "@aws-sdk/client-kms";

const dynamoDbClient = createClient(AwsClientType.DYNAMO) as DynamoDBDocument;
const ssmClient = createClient(AwsClientType.SSM) as SSMClient;
const sqsClient = createClient(AwsClientType.SQS) as SQSClient;
const kmsClient = createClient(AwsClientType.KMS) as KMSClient;

const logger = new Logger();
const metrics = new Metrics();
const tracer = new Tracer({ captureHTTPsRequests: false });
const configService = new ConfigService(ssmClient);
const configInitPromise = configService.init([
    CommonConfigKey.SESSION_TABLE_NAME,
    CommonConfigKey.SESSION_TTL,
    CommonConfigKey.PERSON_IDENTITY_TABLE_NAME,
    CommonConfigKey.DECRYPTION_KEY_ID,
    CommonConfigKey.VC_ISSUER,
]);
const SESSION_CREATED_METRIC = "session_created";

export class SessionLambda implements LambdaInterface {
    constructor(
        private readonly sessionService: SessionService,
        private readonly personIdentityService: PersonIdentityService,
        private readonly sessionRequestValidatorFactory: SessionRequestValidatorFactory,
        private readonly jweDecrypter: JweDecrypter,
        private readonly auditService: AuditService,
    ) {}

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
                decryptedJwt = await this.jweDecrypter.decryptJwe(deserialisedRequestBody.request);
            } catch (e) {
                logger.error("Invalid request - JWE decryption failed", e as Error);
                return {
                    statusCode: 400,
                    body: "Invalid request: JWE decryption failed",
                };
            }

            if (!configService.hasClientConfig(requestBodyClientId)) {
                await this.initClientConfig(requestBodyClientId);
            }
            const criClientConfig = configService.getClientConfig(requestBodyClientId)!;

            const sessionRequestValidator = this.sessionRequestValidatorFactory.create(criClientConfig);
            const jwtValidationResult = await sessionRequestValidator.validateJwt(decryptedJwt, requestBodyClientId);
            if (!jwtValidationResult.isValid) {
                return {
                    statusCode: 400,
                    body: `Invalid request: JWT validation/verification failed: ${jwtValidationResult.errorMsg}`,
                };
            }

            const jwtPayload = jwtValidationResult.validatedObject;
            const clientIpAddress = getClientIpAddress(event);

            metrics.addDimension("issuer", requestBodyClientId);

            const sessionRequestSummary = this.createSessionRequestSummary(jwtPayload, clientIpAddress);
            const sessionId: string = await this.sessionService.saveSession(sessionRequestSummary);

            logger.appendKeys({ govuk_signin_journey_id: sessionId });
            logger.info("created session");

            if (jwtPayload.shared_claims) {
                await this.personIdentityService.savePersonIdentity(
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
            logger.error("session lambda error occurred", err as Error);
            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 0);
            return {
                statusCode: 500,
                body: `An error has occurred: ${JSON.stringify(err) == "{}" ? err : JSON.stringify(err)}`,
            };
        }
    }
    private async initClientConfig(clientId: string): Promise<void> {
        await configService.initClientConfig(clientId, [
            ClientConfigKey.JWT_AUDIENCE,
            ClientConfigKey.JWT_ISSUER,
            ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
            ClientConfigKey.JWT_REDIRECT_URI,
            ClientConfigKey.JWT_SIGNING_ALGORITHM,
        ]);
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
    private async sendAuditEvent(
        sessionId: string,
        sessionRequest: SessionRequestSummary,
        clientIpAddress: string | undefined,
    ) {
        await this.auditService.sendAuditEvent(AuditEventType.START, {
            clientIpAddress: clientIpAddress,
            sessionItem: {
                sessionId,
                subject: sessionRequest.subject,
                persistentSessionId: sessionRequest.persistentSessionId,
                clientSessionId: sessionRequest.clientSessionId,
            },
        });
    }
}

const handlerClass = new SessionLambda(
    new SessionService(dynamoDbClient, configService),
    new PersonIdentityService(dynamoDbClient, configService),
    new SessionRequestValidatorFactory(logger),
    new JweDecrypter(kmsClient, () => configService.getConfigEntry(CommonConfigKey.DECRYPTION_KEY_ID)),
    new AuditService(() => configService.getAuditConfig(), sqsClient),
);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
