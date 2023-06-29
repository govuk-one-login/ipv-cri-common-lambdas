import { LambdaInterface } from "@aws-lambda-powertools/commons";
import middy from "@middy/core";
import { SQSEvent } from "aws-lambda";
import { logger, metrics, tracer as _tracer } from "../common/utils/power-tool";
import errorMiddleware from "../middlewares/error/error-middleware";

const AUDIT_EVENT_CONSUMED = "audit_event_consumed";

export class AuditEventConsumerLambda implements LambdaInterface {
    @metrics.logMetrics({ throwOnEmptyMetrics: false, captureColdStartMetric: true })
    @_tracer.captureLambdaHandler({ captureResponse: false })
    public async handler(event: SQSEvent, _context: unknown): Promise<void> {
        for (const record of event.Records) {
            logger.info("Audit event consumed:", JSON.parse(record.body));
        }
    }
}

const handlerClass = new AuditEventConsumerLambda();
export const lambdaHandler = middy(handlerClass.handler.bind(handlerClass)).use(
    errorMiddleware(logger, metrics, {
        metric_name: AUDIT_EVENT_CONSUMED,
        message: "Audit Event Consumer Lambda error occurred",
    }),
);
