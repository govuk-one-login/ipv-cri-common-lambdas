import {KMSClient, DecryptCommand, EncryptionAlgorithmSpec} from "@aws-sdk/client-kms"
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { SessionService } from "./services/session-service";
import { DynamoDbClient } from "./lib/dynamo-db-client";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";
import { SsmClient } from "./lib/param-store-client";
import { ConfigService } from "./services/config-service";
import {compactDecrypt, CompactJWEHeaderParameters, FlattenedJWE, KeyLike} from "jose";
import {DecryptCommandInput} from "@aws-sdk/client-kms/dist-types/commands/DecryptCommand";
import {CompactDecryptResult} from "jose/dist/types/types";


const logger = new Logger();
const metrics = new Metrics();
const configService = new ConfigService(SsmClient);
const initPromise = configService.init();
const AUTHORIZATION_SENT_METRIC = "authorization_sent";


class AuthorizationLambda implements LambdaInterface {
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
                }
                else if (!parsedRequestBody.request) {
                    errorMsg = "Body missing request field";
                }
            }

            if (errorMsg) {
                return {
                    statusCode: 400,
                    body: `Invalid request: ${errorMsg}`
                };
            }

            /** TODO: complete implementation **/

            const result: CompactDecryptResult = await compactDecrypt(
                parsedRequestBody.request,
                this.getKey);

            logger.info(`decryption result: ${result.plaintext.toString()}`);

            return {
                statusCode: 201,
                body: JSON.stringify({testing: "for now"}),
            };
        } catch (err: any) {
            logger.error("authorization lambda error occurred.", err);
            metrics.addMetric(AUTHORIZATION_SENT_METRIC, MetricUnits.Count, 0);
            return {
                statusCode: 500,
                body: `An error has occurred. ${JSON.stringify(err)}`,
            };
        }
    }
    private async getKey(jweHeader: CompactJWEHeaderParameters, jwe: FlattenedJWE): Promise<Uint8Array> {

        logger.info(`jwe header: ${JSON.stringify(jweHeader)}`);

        logger.info(`jwe: ${JSON.stringify(jwe)}`);

        const client = new KMSClient({region: process.env.AWS_REGION});

        const kmsDecryptionKeyId = await configService.getKmsDecryptionKeyId();

        logger.info(`kms key id: ${kmsDecryptionKeyId}`);

        const jweEncryptedKey = jwe.encrypted_key;
        let arrayBuffer = new ArrayBuffer(jweEncryptedKey!.length);

        let encryptedKeyAsBytes = new Uint8Array(arrayBuffer);
        encryptedKeyAsBytes.forEach((val, idx) => {
            encryptedKeyAsBytes[idx] = jweEncryptedKey!.charCodeAt(idx);
        });

        const decryptCommand = new DecryptCommand({
            CiphertextBlob: encryptedKeyAsBytes,
            KeyId: kmsDecryptionKeyId,
            EncryptionAlgorithm: EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256
        });
        const response = await client.send(decryptCommand);

        logger.info(`kms resp: ${JSON.stringify(response)}`);

        return response.Plaintext!;
    }
}

const handlerClass = new AuthorizationLambda();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
