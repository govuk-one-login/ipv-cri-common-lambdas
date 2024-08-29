import type { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { Logger } from "@aws-lambda-powertools/logger";
// import { Metrics } from "@aws-lambda-powertools/metrics";
// import { Tracer } from "@aws-lambda-powertools/tracer";
import { SQSEvent } from "aws-lambda";

const logger = new Logger();
// const metrics = new Metrics();
// const tracer = new Tracer({ captureHTTPsRequests: false });

export class DequeueLambdaHandler implements LambdaInterface {
    async handler(event: SQSEvent): Promise<any> {
        logger.info("Starting to process records");
        // const batchFailures: BatchItemFailure[] = [];

        for await (const record of event.Records) {
            try {
                console.log("record", record);
                // push to DDB
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
