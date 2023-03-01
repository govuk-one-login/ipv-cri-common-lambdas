export interface SessionItem {
    expiryDate?: number;
    sessionId: string;
    clientId: string;
    clientSessionId: string;
    authorizationCode?: string;
    authorizationCodeExpiryDate: number;
    redirectUri: string;
    accessToken: string;
    accessTokenExpiryDate: number;
}
