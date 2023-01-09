import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SsmClient } from "./lib/param-store-client";
import { ConfigService } from "./services/config-service";
import { JwtVerifier } from "./services/jwt-verifier";
import { JweDecrypter } from "./services/jwe-decrypter";
import {JWTPayload} from "jose";

const logger = new Logger();
const metrics = new Metrics();
const configService = new ConfigService(SsmClient);
const initPromise = configService.init();
const SESSION_CREATED_METRIC = "session_created";

class SessionLambda implements LambdaInterface {
    @logger.injectLambdaContext({ clearState: true })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: APIGatewayProxyEvent, context: any): Promise<APIGatewayProxyResult> {
        try {
            await initPromise;

            let parsedRequestBody;
            let errorMsg = "";
            if (!event.body) {
                errorMsg = "Missing request body";
            } else {
                parsedRequestBody = JSON.parse(event.body);

                if (!parsedRequestBody.client_id) {
                    errorMsg = "Body missing clientId field";
                } else if (!parsedRequestBody.request) {
                    errorMsg = "Body missing request field";
                }
            }

            if (errorMsg) {
                return {
                    statusCode: 400,
                    body: `Invalid request: ${errorMsg}`,
                };
            }

            /** TODO: complete implementation **/

            const decryptedJwt = await new JweDecrypter(configService).decryptJwe(parsedRequestBody.request);

            const payload = await this.verifyJwtSignature(decryptedJwt, parsedRequestBody.client_id);

            logger.info(`signature verification result: ${JSON.stringify(payload)}`);

            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 1);

            return {
                statusCode: 201,
                body: JSON.stringify({ testing: "for now" }),
            };
        } catch (err: any) {
            logger.error("session lambda error occurred.", err);
            metrics.addMetric(SESSION_CREATED_METRIC, MetricUnits.Count, 0);
            return {
                statusCode: 500,
                body: `An error has occurred. ${JSON.stringify(err)}`,
            };
        }
    }
    private async verifyJwtSignature(jwt: Buffer, clientId: string): Promise<JWTPayload> {
        const expectedIssuer = await configService.getJwtIssuer(clientId);
        const expectedAudience = await configService.getJwtAudience(clientId);
        return await new JwtVerifier(configService).verify(
            jwt,
            clientId,
            new Set([
                JwtVerifier.ClaimNames.EXPIRATION_TIME,
                JwtVerifier.ClaimNames.SUBJECT,
                JwtVerifier.ClaimNames.NOT_BEFORE,
            ]),
            new Map([
                [JwtVerifier.ClaimNames.AUDIENCE, expectedAudience],
                [JwtVerifier.ClaimNames.ISSUER, expectedIssuer],
            ]),
        );
    }
}

const handlerClass = new SessionLambda();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
