import { SQSEvent } from "aws-lambda";
import { dbClient, logger, lambdaHandler } from "../src/dequeue-handler";
import { vi, it, describe, expect, afterEach } from "vitest";

vi.mock("@aws-sdk/client-dynamodb", () => ({
    DynamoDBClient: vi.fn().mockImplementation(function () {
        return {
            send: vi.fn(),
        };
    }),
    PutItemCommand: vi.fn().mockImplementation(function () {}),
}));

vi.mock("@aws-lambda-powertools/logger", () => ({
    Logger: vi.fn().mockImplementation(function () {
        return {
            info: vi.fn(),
            error: vi.fn(),
        };
    }),
}));

describe("dequeue-handler", () => {
    const body1 = JSON.stringify({
        event_name: "TEST_EVENT",
        timestamp: "12345678",
        user: {
            session_id: "sessionId1",
        },
    });
    const body2 = JSON.stringify({
        event_name: "TEST_EVENT",
        timestamp: "12345678",
        user: {
            session_id: "sessionId2",
        },
    });
    const event = {
        Records: [
            { messageId: "11111", body: body1 },
            { messageId: "22222", body: body2 },
        ],
    };

    afterEach(() => vi.resetAllMocks());

    it("Returns no batchItemFailures if all events were successfully put into the DB", async () => {
        vi.spyOn(dbClient, "send").mockReturnValueOnce();

        const result = await lambdaHandler(event as SQSEvent);
        expect(logger.info).toHaveBeenCalledWith("Starting to process records");
        expect(logger.info).toHaveBeenCalledWith({
            message: "Event successfully saved to table",
            tableName: "audit-events-table",
            sessionId: "sessionId1",
            eventName: "TEST_EVENT",
        });
        expect(logger.info).toHaveBeenCalledWith({
            message: "Event successfully saved to table",
            tableName: "audit-events-table",
            sessionId: "sessionId2",
            eventName: "TEST_EVENT",
        });
        expect(logger.info).toHaveBeenCalledWith("Finished processing records");
        expect(result).toEqual({ batchItemFailures: [] });
    });

    it("Returns batchItemFailures if events could not be put into the DB", async () => {
        const error = new Error("Failed to send to DDB");
        vi.spyOn(dbClient, "send").mockImplementationOnce(() => {
            throw error;
        });

        const result = await lambdaHandler(event as SQSEvent);
        expect(logger.error).toHaveBeenCalledWith({
            message: "Error writing events to DB table audit-events-table",
            error,
        });
        expect(logger.info).toHaveBeenCalledWith("Finished processing records");
        expect(result).toEqual({
            batchItemFailures: [{ itemIdentifier: "11111" }],
        });
    });
});
