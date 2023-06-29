import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import middy from "@middy/core";
import { Context, SQSEvent, SQSRecord } from "aws-lambda";
import { AuditEventConsumerLambda } from "../../../src/handlers/audit-event-consumer-handler";
import errorMiddleware from "../../../src/middlewares/error/error-middleware";

describe("audit-event-consumer-handler.ts", () => {
    const logger = jest.mocked(Logger);
    const metrics = jest.mocked(Metrics);
    let auditEventConsumerLambda: AuditEventConsumerLambda;

    let lambdaHandler: middy.MiddyfiedHandler;

    beforeEach(() => {
        auditEventConsumerLambda = new AuditEventConsumerLambda();
        lambdaHandler = middy(auditEventConsumerLambda.handler.bind(auditEventConsumerLambda)).use(
            errorMiddleware(logger.prototype, metrics.prototype, {
                metric_name: "audit_event_consumed",
                message: "Audit Event Consumer Lambda error occurred",
            }),
        );
    });

    it("should log all SQS messages in the event", async () => {
        const loggerSpy = jest.spyOn(logger.prototype, "info");
        const mockBody = {
            timestamp: 1687446254,
            event_name: "IPV_KBV_CRI_RESPONSE_RECEIVED",
            component_id: "https://review-k.build.account.gov.uk",
            user: {
                user_id: "urn:fdc:gov.uk:2022:12b83ddf-79ff-454c-a3fd-67a9f8963cdd",
                ip_address: "172.177.150.115, 10.1.60.204",
                session_id: "6492fead-283b-4fa9-b57a-6f7da8f3fbb8",
                persistent_session_id: "87bbeda2-1bd7-4e3b-8d0a-66a2adcf6908",
                govuk_signin_journey_id: "a381c877-5cb4-4579-bf96-661ec5744224",
            },
            extensions: { experianIiqResponse: { outcome: null } },
        };
        const mockEvent: SQSEvent = {
            Records: [
                {
                    messageId: "messageId",
                    receiptHandle: "receiptHandle",
                    body: JSON.stringify(mockBody),
                    messageAttributes: {},
                    md5OfBody: "string",
                    eventSource: "string",
                    eventSourceARN: "string",
                    awsRegion: "string",
                } as SQSRecord,
            ],
        };
        await lambdaHandler(mockEvent, {} as Context);
        expect(loggerSpy).toHaveBeenCalledTimes(1);
        expect(loggerSpy).toHaveBeenCalledWith("Audit event consumed", mockBody);
    });
});
