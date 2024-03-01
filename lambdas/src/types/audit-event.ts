import { PersonIdentity } from "./person-identity";

export enum AuditEventType {
    START = "START", // Before a session is written to the Session table
    REQUEST_RECEIVED = "REQUEST_RECEIVED", // A non-common request has been received
    REQUEST_SENT = "REQUEST_SENT", // When a third party call is started
    VC_ISSUED = "VC_ISSUED", // When the final VC is created in the issue credential lambda
    THIRD_PARTY_REQUEST_ENDED = "THIRD_PARTY_REQUEST_ENDED", // When a third party requests are ended
    END = "END", // When VC credentials are being returned - final event
}

export interface AuditEventSession {
    sessionId: string;
    subject: string;
    persistentSessionId: string;
    clientSessionId: string;
}

export interface AuditEventContext {
    sessionItem: AuditEventSession;
    personIdentity?: PersonIdentity;
    extensions?: unknown;
    clientIpAddress: string | undefined;
}

export interface AuditEventUser {
    user_id?: string;
    ip_address?: string;
    session_id?: string;
    persistent_session_id?: string;
    govuk_signin_journey_id?: string;
}

export interface AuditEvent {
    timestamp: number;
    event_timestamp_ms: number;
    event_name: string;
    component_id: string;
    restricted?: PersonIdentity;
    user: AuditEventUser;
    extensions?: unknown;
}
