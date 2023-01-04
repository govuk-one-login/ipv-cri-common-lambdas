export type SessionItem = {
    sessionId: string;
    clientId: string;
    clientSessionId: string;
    authorizationCode: string;
    authorizationCodeExpiryDate: number;
    redirectUri: string;
};