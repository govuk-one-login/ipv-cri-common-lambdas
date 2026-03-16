import { DynamoDBBatchResponse, DynamoDBStreamEvent } from "aws-lambda";
import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { AttributeValue } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { ReplicationService } from "../services/replication-service";
import { initOpenTelemetry } from "../common/utils/otel-setup";
import { logger } from "@govuk-one-login/cri-logger";
import { metrics, tracer as _tracer } from "../common/utils/power-tool";

initOpenTelemetry();

const dynamoDbClient = createClient(AwsClientType.DYNAMO);

export class DynamoDbStreamLambda implements LambdaInterface {
    constructor(private readonly replicationService: ReplicationService) {}

    @_tracer.captureLambdaHandler({ captureResponse: false })
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    public async handler(event: DynamoDBStreamEvent, _context: unknown): Promise<DynamoDBBatchResponse> {
        const batchItemFailures: DynamoDBBatchResponse["batchItemFailures"] = [];

        for (const record of event.Records) {
            try {
                const targetTable = this.replicationService.resolveTargetTable(record.eventSourceARN!);
                const eventName = record.eventName;

                if (eventName === "INSERT" || eventName === "MODIFY") {
                    const newImage = unmarshall(
                        record.dynamodb!.NewImage! as unknown as Record<string, AttributeValue>,
                    );
                    await this.replicationService.replicateItem(targetTable, newImage);
                    logger.info(`Replicated ${eventName} event to ${targetTable}`);
                } else if (eventName === "REMOVE") {
                    const keys = unmarshall(record.dynamodb!.Keys! as unknown as Record<string, AttributeValue>);
                    await this.replicationService.deleteItem(targetTable, keys);
                    logger.info(`Deleted item from ${targetTable}`);
                }
            } catch (err: unknown) {
                logger.error(`Replication error for event ${record.eventID}`, err as Error);
                batchItemFailures.push({ itemIdentifier: record.eventID! });
            }
        }

        return { batchItemFailures };
    }
}

const sourceSessionTableName = process.env.SOURCE_SESSION_TABLE_NAME || "";
const sourcePersonIdentityTableName = process.env.SOURCE_PERSON_IDENTITY_TABLE_NAME || "";
const targetSessionTableName = process.env.TARGET_SESSION_TABLE_NAME || "";
const targetPersonIdentityTableName = process.env.TARGET_PERSON_IDENTITY_TABLE_NAME || "";

const replicationService = new ReplicationService(
    dynamoDbClient,
    sourceSessionTableName,
    sourcePersonIdentityTableName,
    targetSessionTableName,
    targetPersonIdentityTableName,
);
const handlerClass = new DynamoDbStreamLambda(replicationService);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
