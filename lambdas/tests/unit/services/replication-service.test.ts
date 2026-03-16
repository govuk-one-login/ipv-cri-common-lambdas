import { ReplicationService } from "../../../src/services/replication-service";
import { DynamoDBDocument, PutCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";

jest.mock("@aws-sdk/lib-dynamodb", () => {
    return {
        __esModule: true,
        ...jest.requireActual("@aws-sdk/lib-dynamodb"),
        PutCommand: jest.fn(),
        DeleteCommand: jest.fn(),
    };
});

describe("replication-service", () => {
    let replicationService: ReplicationService;

    const mockDynamoDbClient = jest.mocked(DynamoDBDocument);
    const mockPutCommand = jest.mocked(PutCommand);
    const mockDeleteCommand = jest.mocked(DeleteCommand);

    beforeEach(() => {
        jest.resetAllMocks();
        replicationService = new ReplicationService(
            mockDynamoDbClient.prototype,
            "session-stack-a",
            "person-identity-stack-a",
            "session-stack-b",
            "person-identity-stack-b",
        );
        const impl = () => {
            const mockPromise = new Promise<unknown>((resolve) => {
                resolve({});
            });
            return jest.fn().mockImplementation(() => {
                return mockPromise;
            });
        };
        mockDynamoDbClient.prototype.send = impl();
    });

    describe("resolveTargetTable", () => {
        it("should resolve session table ARN to the target session table", () => {
            const arn = "arn:aws:dynamodb:eu-west-2:123456789012:table/session-stack-a/stream/2024-01-01T00:00:00.000";

            const result = replicationService.resolveTargetTable(arn);

            expect(result).toBe("session-stack-b");
        });

        it("should resolve person identity table ARN to the target person identity table", () => {
            const arn =
                "arn:aws:dynamodb:eu-west-2:123456789012:table/person-identity-stack-a/stream/2024-01-01T00:00:00.000";

            const result = replicationService.resolveTargetTable(arn);

            expect(result).toBe("person-identity-stack-b");
        });

        it("should throw an error for an unknown source table", () => {
            const arn = "arn:aws:dynamodb:eu-west-2:123456789012:table/unknown-table/stream/2024-01-01T00:00:00.000";

            expect(() => replicationService.resolveTargetTable(arn)).toThrow(
                "Unknown source table: unknown-table. Expected 'session-stack-a' or 'person-identity-stack-a'.",
            );
        });
    });

    describe("replicateItem", () => {
        it("should put the item into the target table", async () => {
            const targetTable = "session-stack-b";
            const item = { sessionId: "sess-123", clientId: "client-abc", expiryDate: 1700000000 };

            await replicationService.replicateItem(targetTable, item);

            expect(mockPutCommand).toHaveBeenCalledWith({
                TableName: targetTable,
                Item: item,
            });
            expect(mockDynamoDbClient.prototype.send).toHaveBeenCalledTimes(1);
        });
    });

    describe("deleteItem", () => {
        it("should delete the item from the target table", async () => {
            const targetTable = "session-stack-b";
            const key = { sessionId: "sess-789" };

            await replicationService.deleteItem(targetTable, key);

            expect(mockDeleteCommand).toHaveBeenCalledWith({
                TableName: targetTable,
                Key: key,
            });
            expect(mockDynamoDbClient.prototype.send).toHaveBeenCalledTimes(1);
        });
    });
});
