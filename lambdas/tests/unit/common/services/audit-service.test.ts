import { SendMessageCommand, SQSClient } from "@aws-sdk/client-sqs";
import { AuditService } from "../../../../src/common/services/audit-service";
import { AuditEventContext, AuditEventType } from "../../../../src/types/audit-event";

jest.mock("@aws-sdk/client-sqs", () => {
    return {
        __esModule: true,
        ...jest.requireActual("@aws-sdk/client-sqs"),
        SendMessageCommand: jest.fn(),
        SQSClient: {
            prototype: {
                send: jest.fn(),
            },
        },
    };
}); //  this is so we only mock out the SendMessageCommand

describe("AuditService", () => {
    let auditService: AuditService;
    const mockGetAuditConfig = jest.fn();

    const mockSqsClient = jest.mocked(SQSClient);
    const mockSendMessageCommand = jest.mocked(SendMessageCommand);

    const mockEventType = AuditEventType.START;
    const mockContext = {
        sessionItem: {
            sessionId: "test-session-id",
            subject: "test-subject",
            persistentSessionId: "test-client-session-id",
            clientSessionId: "test-client-session-id",
        },
        clientIpAddress: undefined,
    } as AuditEventContext;

    beforeEach(() => {
        jest.clearAllMocks();

        mockGetAuditConfig.mockImplementation(() => {
            return {
                queueUrl: "test-url",
                auditEventNamePrefix: "TEST_PREFIX",
                issuer: "test-issuer",
            };
        });

        jest.spyOn(global.Date, "now").mockReturnValueOnce(1681147957473);

        auditService = new AuditService(mockGetAuditConfig, mockSqsClient.prototype);
    });

    it("should request the audit config if necessary", async () => {
        await auditService.sendAuditEvent(mockEventType, mockContext);
        expect(mockGetAuditConfig).toHaveBeenCalledTimes(1);
    });

    it("should error without an event type", async () => {
        await expect(auditService.sendAuditEvent(undefined as unknown as AuditEventType, mockContext)).rejects.toThrow(
            "Audit event type not specified",
        );
    });

    it("should successfully send the audit event", async () => {
        await auditService.sendAuditEvent(mockEventType, mockContext);

        expect(mockSendMessageCommand).toBeCalledWith({
            MessageBody: JSON.stringify({
                component_id: "test-issuer",
                event_name: `TEST_PREFIX_START`,
                extensions: undefined,
                restricted: undefined,
                timestamp: 1681147957,
                user: {
                    govuk_signin_journey_id: "test-client-session-id",
                    ip_address: undefined,
                    persistent_session_id: "test-client-session-id",
                    session_id: "test-session-id",
                    user_id: "test-subject",
                },
            }),
            QueueUrl: "test-url",
        });

        expect(mockSqsClient.prototype.send).toBeCalledTimes(1);
    });

    it("should handle missing session configuration", async () => {
        const newMockContext = {
            sessionItem: {},
            clientIpAddress: undefined,
        } as AuditEventContext;
        await auditService.sendAuditEvent(mockEventType, newMockContext);

        expect(mockSendMessageCommand).toBeCalledWith({
            MessageBody: JSON.stringify({
                component_id: "test-issuer",
                event_name: `TEST_PREFIX_START`,
                extensions: undefined,
                restricted: undefined,
                timestamp: 1681147957,
                user: {
                    govuk_signin_journey_id: undefined,
                    ip_address: undefined,
                    persistent_session_id: undefined,
                    session_id: undefined,
                    user_id: undefined,
                },
            }),
            QueueUrl: "test-url",
        });

        expect(mockSqsClient.prototype.send).toBeCalledTimes(1);
    });
});
