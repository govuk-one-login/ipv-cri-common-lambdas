import { ReplicationService } from "../../../src/services/replication-service";
import { DynamoDBDocument, PutCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@aws-sdk/lib-dynamodb", async () => {
    const actual = await vi.importActual<typeof import("@aws-sdk/lib-dynamodb")>("@aws-sdk/lib-dynamodb");
    return {
        __esModule: true,
        ...actual,
        PutCommand: vi.fn(),
        DeleteCommand: vi.fn(),
    };
});

describe("replication-service", () => {
    let replicationService: ReplicationService;

    const mockDynamoDbClient = vi.mocked(DynamoDBDocument);
    const mockPutCommand = vi.mocked(PutCommand);
    const mockDeleteCommand = vi.mocked(DeleteCommand);

    beforeEach(() => {
        vi.resetAllMocks();
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
            return vi.fn().mockImplementation(() => {
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
