import { ConfigService } from "./config-service";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { AuditEvent, AuditEventContext, AuditEventSession, AuditEventType, AuditEventUser } from "./audit-event";

export class AuditService {
    private readonly queueUrl: string;
    private readonly auditEventNamePrefix: string;
    private readonly issuer: string;
    constructor(private readonly configService: ConfigService, private readonly sqsClient: SQSClient) {
        this.queueUrl = this.configService.getSqsQueueUrl();
        this.auditEventNamePrefix = this.configService.getAuditEventNamePrefix();
        this.issuer = this.configService.getVerifiableCredentialIssuer();
    }

    public async sendAuditEvent(eventType: AuditEventType, context: AuditEventContext) {
        const auditEvent = this.createAuditEvent(eventType, context);
        await this.sendAuditEventToQueue(auditEvent);
    }

    private createAuditEvent(eventType: AuditEventType, context: AuditEventContext): AuditEvent {
        if (!eventType) {
            throw new Error("Audit event type not specified");
        }
        const auditEventUser: AuditEventUser = this.createAuditEventUser(context.sessionItem, context.clientIpAddress);
        return {
            component_id: this.issuer,
            event_name: `${this.auditEventNamePrefix}_${eventType}`,
            extensions: context && context.extensions ? context.extensions : undefined,
            restricted: context && context.personIdentity ? context.personIdentity : undefined,
            timestamp: Date.now(),
            user: auditEventUser,
        };
    }

    private createAuditEventUser(sessionItem: AuditEventSession, clientIpAddress: string | undefined): AuditEventUser {
        return {
            govuk_signin_journey_id:
                sessionItem && sessionItem.clientSessionId ? sessionItem.clientSessionId : undefined,
            ip_address: clientIpAddress,
            persistent_session_id:
                sessionItem && sessionItem.persistentSessionId ? sessionItem.persistentSessionId : undefined,
            session_id: sessionItem && sessionItem.sessionId ? sessionItem.sessionId : undefined,
            user_id: sessionItem && sessionItem.subject ? sessionItem.subject : undefined,
        };
    }

    private async sendAuditEventToQueue(auditEvent: AuditEvent) {
        const sendMsgCommand = new SendMessageCommand({
            MessageBody: JSON.stringify(auditEvent),
            QueueUrl: this.queueUrl,
        });
        await this.sqsClient.send(sendMsgCommand);
    }
}
