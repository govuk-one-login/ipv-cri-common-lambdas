import middy from "@middy/core";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { MetricUnits } from "@aws-lambda-powertools/metrics";
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
import { SQSClient } from "@aws-sdk/client-sqs";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { getClientIpAddress } from "../common/utils/request-utils";
import { KMSClient } from "@aws-sdk/client-kms";
import { errorPayload } from "../common/utils/errors";
import { logger, metrics, tracer as _tracer } from "../common/utils/power-tool";
import errorMiddleware from "../middlewares/error/error-middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/lib/middleware/middy";
import initialiseConfigMiddleware, { configService } from "../middlewares/config/initialise-config-middleware";

const dynamoDbClient = createClient(AwsClientType.DYNAMO) as DynamoDBDocument;
const sqsClient = createClient(AwsClientType.SQS) as SQSClient;
const kmsClient = createClient(AwsClientType.KMS) as KMSClient;

const SESSION_CREATED_METRIC = "session_created";

export class SessionLambda implements LambdaInterface {
    constructor(
        private readonly sessionService: SessionService,
        private readonly personIdentityService: PersonIdentityService,
        private readonly sessionRequestValidatorFactory: SessionRequestValidatorFactory,
        private readonly jweDecrypter: JweDecrypter,
        private readonly auditService: AuditService,
    ) {}

    @_tracer.captureLambdaHandler({ captureResponse: false })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, _context: unknown): Promise<APIGatewayProxyResult> {
        try {
            const deserialisedRequestBody = JSON.parse(event.body as string);
            logger.info("Session lambda triggered");

            console.dir(deserialisedRequestBody);
            const requestBodyClientId = deserialisedRequestBody.client_id;
            const clientIpAddress = getClientIpAddress(event);

            if (!configService.hasClientConfig(requestBodyClientId)) {
                await this.initClientConfig(requestBodyClientId);
            }

            const criClientConfig = configService.getClientConfig(requestBodyClientId) as Map<string, string>;
            const sessionRequestValidator = this.sessionRequestValidatorFactory.create(criClientConfig);

            //const decryptedJwt = //await this.jweDecrypter.decryptJwe(deserialisedRequestBody.request);
            //logger.info("JWE decrypted");

            const jwtPayload = await sessionRequestValidator.validateJwt(deserialisedRequestBody as Buffer, requestBodyClientId);
            logger.info("JWT validated");

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

            await this.sendAuditEvent(sessionId, sessionRequestSummary, clientIpAddress);

            metrics.addDimension("issuer", requestBodyClientId);
            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 1);
            logger.appendKeys({ govuk_signin_journey_id: sessionRequestSummary.clientSessionId });

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
            clientIpAddress: clientIpAddress as string,
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
export const lambdaHandler = middy(handlerClass.handler.bind(handlerClass))
.use(errorMiddleware(logger, metrics, { metric_name: SESSION_CREATED_METRIC, message: "Session Lambda error occurred" }))
.use(injectLambdaContext(logger, { clearState: true }))
.use(initialiseConfigMiddleware({ config_keys: [
    CommonConfigKey.SESSION_TABLE_NAME,
    CommonConfigKey.SESSION_TTL,
    CommonConfigKey.PERSON_IDENTITY_TABLE_NAME,
    CommonConfigKey.DECRYPTION_KEY_ID,
    CommonConfigKey.VC_ISSUER,
]}));



