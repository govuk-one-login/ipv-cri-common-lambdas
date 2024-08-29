import { PutItemCommand, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { Logger } from "@aws-lambda-powertools/logger";
import { SQSEvent } from "aws-lambda";

const logger = new Logger();

const dbClient = new DynamoDBClient({ region: process.env.REGION });

export class DequeueLambdaHandler implements LambdaInterface {
    async handler(event: SQSEvent): Promise<any> {
        logger.info("Starting to process records");
        // const batchFailures: BatchItemFailure[] = [];

        for await (const record of event.Records) {
            const nowInSeconds = Math.floor(Date.now() / 1000)
            const ttl = nowInSeconds + 360
            const eventData = JSON.parse(record.body);

            const putItemCommand: PutItemCommand = new PutItemCommand({
                TableName: "audit-events-test-harness-caitlin",
                Item: {
                    partitionKey: { S: `SESSION#${eventData.session_id}` },
                    sortKey: { S: `TXMA#${eventData.event_name}#${eventData.timestamp}#${record.messageId}` },
                    event: { S: record.body },
                    expiryDate: { N: ttl.toString() },
                },
            })

            try {
                await dbClient.send(putItemCommand)
                logger.info({ message: "Event successfully saved to events table", sessionId: eventData.session_id })
            } catch (error) {
                // batchFailures.push(new BatchItemFailure(record.messageId));
                logger.error({ message: "Error writing events to DB", error });
            }
        }

        logger.info("Finished processing records");
        // return { batchItemFailures: batchFailures };
    }
}

const handlerClass = new DequeueLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
