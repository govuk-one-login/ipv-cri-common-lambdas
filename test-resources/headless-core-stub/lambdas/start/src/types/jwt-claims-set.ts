import { EvidenceRequestedClass, PersonExtendedMatchingClass } from "@govuk-one-login/data-vocab/credentials";

export type JWTClaimsSet = {
    iss: string;
    sub: string;
    aud: string;
    iat: number;
    exp: number;
    nbf: number;
    response_type: string;
    client_id: string;
    redirect_uri: string;
    state: string;
    govuk_signin_journey_id: string;
    shared_claims?: PersonExtendedMatchingClass;
    evidence_requested?: EvidenceRequestedClass;
    context?: string;
};
