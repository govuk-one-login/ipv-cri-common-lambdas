import { PutItemCommand, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { Logger } from "@aws-lambda-powertools/logger";
import { SQSEvent, SQSBatchItemFailure } from "aws-lambda";

export const logger = new Logger();
export const dbClient = new DynamoDBClient({ region: process.env.REGION });

export class DequeueLambdaHandler implements LambdaInterface {
    async handler(event: SQSEvent): Promise<{ batchItemFailures: SQSBatchItemFailure[] }> {
        logger.info("Starting to process records");

        const tableName = process.env.EVENTS_TABLE_NAME;
        const batchItemFailures: SQSBatchItemFailure[] = [];

        for (const { body, messageId } of event.Records) {
            const { sessionId, eventName, timestamp } = this.getEventData(body);
            const nowInSeconds = Math.floor(Date.now() / 1000);
            const ttl = nowInSeconds + 360;

            const putItemCommand: PutItemCommand = new PutItemCommand({
                TableName: tableName,
                Item: {
                    partitionKey: { S: `SESSION#${sessionId}` },
                    sortKey: { S: `TXMA#${eventName}#${timestamp}#${messageId}` },
                    event: { S: body },
                    expiryDate: { N: ttl.toString() },
                },
            });

            try {
                await dbClient.send(putItemCommand);
                logger.info({ message: "Event successfully saved to table", tableName, sessionId, eventName });
            } catch (error) {
                batchItemFailures.push({ itemIdentifier: messageId });
                logger.error({ message: `Error writing events to DB table ${tableName}`, error });
            }
        }

        logger.info("Finished processing records");
        return { batchItemFailures };
    }

    getEventData(eventBody: string) {
        const body = JSON.parse(eventBody);
        return {
            eventName: body.event_name,
            sessionId: body.user.session_id,
            timestamp: body.timestamp,
        };
    }
}

const handlerClass = new DequeueLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
