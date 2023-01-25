import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { AuditEvent, AuditEventContext, AuditEventSession, AuditEventType, AuditEventUser } from "../../types/common/audit-event";
import { CriAuditConfig } from "../../types/cri-audit-config";

export class AuditService {
    private auditConfig: CriAuditConfig | undefined;
    constructor(private readonly getAuditConfig: () => CriAuditConfig, private readonly sqsClient: SQSClient) {}

    public async sendAuditEvent(eventType: AuditEventType, context: AuditEventContext) {
        if (!this.auditConfig) {
            this.auditConfig = this.getAuditConfig();
        }
        const auditEvent = this.createAuditEvent(eventType, context);
        await this.sendAuditEventToQueue(auditEvent);
    }

    private createAuditEvent(eventType: AuditEventType, context: AuditEventContext): AuditEvent {
        if (!eventType) {
            throw new Error("Audit event type not specified");
        }
        const auditEventUser: AuditEventUser = this.createAuditEventUser(context.sessionItem, context.clientIpAddress);
        return {
            component_id: this.auditConfig!.issuer,
            event_name: `${this.auditConfig!.auditEventNamePrefix}_${eventType}`,
            extensions: context?.extensions ?? undefined,
            restricted: context?.personIdentity ?? undefined,
            timestamp: Date.now(),
            user: auditEventUser,
        };
    }

    private createAuditEventUser(sessionItem: AuditEventSession, clientIpAddress: string | undefined): AuditEventUser {
        return {
            govuk_signin_journey_id: sessionItem?.clientSessionId ?? undefined,
            ip_address: clientIpAddress,
            persistent_session_id: sessionItem?.persistentSessionId ?? undefined,
            session_id: sessionItem?.sessionId ?? undefined,
            user_id: sessionItem?.subject ?? undefined,
        };
    }

    private async sendAuditEventToQueue(auditEvent: AuditEvent) {
        const sendMsgCommand = new SendMessageCommand({
            MessageBody: JSON.stringify(auditEvent),
            QueueUrl: this.auditConfig!.queueUrl,
        });
        await this.sqsClient.send(sendMsgCommand);
    }
}
