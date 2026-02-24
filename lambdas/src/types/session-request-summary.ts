import { EvidenceRequest } from "../schemas/evidence-request.schema";

export interface SessionRequestSummary {
    clientId: string;
    redirectUri: string;
    subject: string;
    persistentSessionId: string;
    clientSessionId: string;
    clientIpAddress: string | null;
    state: string;
    evidenceRequested?: EvidenceRequest;
    context?: string;
}
