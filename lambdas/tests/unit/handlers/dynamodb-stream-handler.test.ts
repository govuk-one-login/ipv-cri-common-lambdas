import { Logger } from "@aws-lambda-powertools/logger";
import { Context, DynamoDBStreamEvent } from "aws-lambda";
import { DynamoDbStreamLambda } from "../../../src/handlers/dynamodb-stream-handler";
import { ReplicationService } from "../../../src/services/replication-service";

jest.mock("@aws-sdk/lib-dynamodb");
jest.mock("@aws-sdk/client-dynamodb");
jest.mock("@aws-lambda-powertools/metrics");
jest.mock("@aws-lambda-powertools/logger");
jest.mock("../../../src/services/replication-service");

const SOURCE_SESSION_ARN =
    "arn:aws:dynamodb:eu-west-2:123456789012:table/session-stack-a/stream/2024-01-01T00:00:00.000";
const SOURCE_PERSON_IDENTITY_ARN =
    "arn:aws:dynamodb:eu-west-2:123456789012:table/person-identity-stack-a/stream/2024-01-01T00:00:00.000";

function makeStreamEvent(records: DynamoDBStreamEvent["Records"]): DynamoDBStreamEvent {
    return { Records: records };
}

function makeRecord(overrides: {
    eventName: "INSERT" | "MODIFY" | "REMOVE";
    eventSourceARN: string;
    newImage?: Record<string, { S?: string; N?: string }>;
    keys?: Record<string, { S?: string }>;
    eventID?: string;
}): DynamoDBStreamEvent["Records"][0] {
    const record: DynamoDBStreamEvent["Records"][0] = {
        eventID: overrides.eventID || "test-event-id",
        eventName: overrides.eventName,
        eventSourceARN: overrides.eventSourceARN,
        eventVersion: "1.1",
        eventSource: "aws:dynamodb",
        awsRegion: "eu-west-2",
        dynamodb: {
            Keys: overrides.keys || { sessionId: { S: "sess-123" } },
        },
    };
    if (overrides.newImage) {
        record.dynamodb!.NewImage = overrides.newImage;
    }
    return record;
}

describe("DynamoDbStreamLambda", () => {
    let dynamoDbStreamLambda: DynamoDbStreamLambda;
    let logger: jest.MockedObjectDeep<typeof Logger>;
    let replicationService: jest.MockedObjectDeep<typeof ReplicationService>;

    beforeEach(() => {
        jest.clearAllMocks();

        logger = jest.mocked(Logger);
        replicationService = jest.mocked(ReplicationService);

        jest.spyOn(logger.prototype, "error").mockImplementation();
        jest.spyOn(logger.prototype, "info").mockImplementation();

        jest.spyOn(replicationService.prototype, "resolveTargetTable").mockReturnValue("session-stack-b");
        jest.spyOn(replicationService.prototype, "replicateItem").mockResolvedValue(undefined);
        jest.spyOn(replicationService.prototype, "deleteItem").mockResolvedValue(undefined);

        dynamoDbStreamLambda = new DynamoDbStreamLambda(replicationService.prototype);
    });

    it("should replicate INSERT events to the target table", async () => {
        const event = makeStreamEvent([
            makeRecord({
                eventName: "INSERT",
                eventSourceARN: SOURCE_SESSION_ARN,
                newImage: {
                    sessionId: { S: "sess-123" },
                    clientId: { S: "client-abc" },
                    expiryDate: { N: "1700000000" },
                },
            }),
        ]);

        const result = await dynamoDbStreamLambda.handler(event, {} as Context);

        expect(result.batchItemFailures).toHaveLength(0);
        expect(replicationService.prototype.resolveTargetTable).toHaveBeenCalledWith(SOURCE_SESSION_ARN);
        expect(replicationService.prototype.replicateItem).toHaveBeenCalledWith(
            "session-stack-b",
            expect.objectContaining({ sessionId: "sess-123" }),
        );
    });

    it("should replicate MODIFY events to the target table", async () => {
        jest.spyOn(replicationService.prototype, "resolveTargetTable").mockReturnValue("person-identity-stack-b");
        const event = makeStreamEvent([
            makeRecord({
                eventName: "MODIFY",
                eventSourceARN: SOURCE_PERSON_IDENTITY_ARN,
                newImage: { sessionId: { S: "sess-456" } },
            }),
        ]);

        const result = await dynamoDbStreamLambda.handler(event, {} as Context);

        expect(result.batchItemFailures).toHaveLength(0);
        expect(replicationService.prototype.replicateItem).toHaveBeenCalledTimes(1);
    });

    it("should delete items on REMOVE events", async () => {
        const event = makeStreamEvent([
            makeRecord({
                eventName: "REMOVE",
                eventSourceARN: SOURCE_SESSION_ARN,
                keys: { sessionId: { S: "sess-789" } },
            }),
        ]);

        const result = await dynamoDbStreamLambda.handler(event, {} as Context);

        expect(result.batchItemFailures).toHaveLength(0);
        expect(replicationService.prototype.deleteItem).toHaveBeenCalledWith(
            "session-stack-b",
            expect.objectContaining({ sessionId: "sess-789" }),
        );
    });

    it("should process multiple records in a single batch", async () => {
        const event = makeStreamEvent([
            makeRecord({
                eventName: "INSERT",
                eventSourceARN: SOURCE_SESSION_ARN,
                newImage: { sessionId: { S: "sess-1" } },
                eventID: "evt-1",
            }),
            makeRecord({
                eventName: "INSERT",
                eventSourceARN: SOURCE_PERSON_IDENTITY_ARN,
                newImage: { sessionId: { S: "sess-2" } },
                eventID: "evt-2",
            }),
            makeRecord({
                eventName: "REMOVE",
                eventSourceARN: SOURCE_SESSION_ARN,
                keys: { sessionId: { S: "sess-3" } },
                eventID: "evt-3",
            }),
        ]);

        const result = await dynamoDbStreamLambda.handler(event, {} as Context);

        expect(result.batchItemFailures).toHaveLength(0);
        expect(replicationService.prototype.replicateItem).toHaveBeenCalledTimes(2);
        expect(replicationService.prototype.deleteItem).toHaveBeenCalledTimes(1);
    });

    it("should report individual record failures without failing the batch", async () => {
        jest.spyOn(replicationService.prototype, "replicateItem")
            .mockResolvedValueOnce(undefined)
            .mockRejectedValueOnce(new Error("Throttled"))
            .mockResolvedValueOnce(undefined);

        const event = makeStreamEvent([
            makeRecord({
                eventName: "INSERT",
                eventSourceARN: SOURCE_SESSION_ARN,
                newImage: { sessionId: { S: "sess-1" } },
                eventID: "evt-1",
            }),
            makeRecord({
                eventName: "INSERT",
                eventSourceARN: SOURCE_SESSION_ARN,
                newImage: { sessionId: { S: "sess-2" } },
                eventID: "evt-2",
            }),
            makeRecord({
                eventName: "INSERT",
                eventSourceARN: SOURCE_SESSION_ARN,
                newImage: { sessionId: { S: "sess-3" } },
                eventID: "evt-3",
            }),
        ]);

        const result = await dynamoDbStreamLambda.handler(event, {} as Context);

        expect(result.batchItemFailures).toHaveLength(1);
        expect(result.batchItemFailures[0].itemIdentifier).toBe("evt-2");
        expect(replicationService.prototype.replicateItem).toHaveBeenCalledTimes(3);
    });

    it("should log errors with the event ID", async () => {
        const errorSpy = jest.spyOn(logger.prototype, "error");
        jest.spyOn(replicationService.prototype, "replicateItem").mockRejectedValueOnce(new Error("DynamoDB error"));

        const event = makeStreamEvent([
            makeRecord({
                eventName: "INSERT",
                eventSourceARN: SOURCE_SESSION_ARN,
                newImage: { sessionId: { S: "sess-1" } },
                eventID: "evt-fail",
            }),
        ]);

        await dynamoDbStreamLambda.handler(event, {} as Context);

        expect(errorSpy).toHaveBeenCalledWith("Replication error for event evt-fail", expect.any(Error));
    });
});
