import { ValidationResult } from "../types/validation-result";
import { ConfigService } from "./config-service";
import { JwtVerifier } from "./jwt-verifier";
import { JWTPayload } from "jose";

export class SessionRequestValidator {
    constructor(private configService: ConfigService, private jwtVerifier: JwtVerifier) {}
    async validateJwt(jwt: Buffer, requestBodyClientId: string): Promise<ValidationResult> {
        const expectedRedirectUri = await this.configService.getJwtRedirectUri(requestBodyClientId);
        const payload = await this.verifyJwtSignature(jwt, requestBodyClientId);
        let errorMsg = null;
        if (!payload) {
            errorMsg = `JWT verification failure`;
        } else if (payload.client_id !== requestBodyClientId) {
            errorMsg = `Mismatched client_id in request body (${requestBodyClientId}) & jwt (${payload.client_id})`;
        } else if (!expectedRedirectUri) {
            errorMsg = `Unable to retrieve redirect URI for client_id: ${requestBodyClientId}`;
        } else if (expectedRedirectUri !== payload.redirect_uri) {
            errorMsg = `redirect uri ${payload.redirect_uri} does not match configuration uri ${expectedRedirectUri}`;
        }

        return { isValid: !errorMsg, errorMsg: errorMsg, validatedObject: payload };
    }
    private async verifyJwtSignature(jwt: Buffer, clientId: string): Promise<JWTPayload | null> {
        const expectedIssuer = await this.configService.getJwtIssuer(clientId);
        const expectedAudience = await this.configService.getJwtAudience(clientId);
        return this.jwtVerifier.verify(
            jwt,
            clientId,
            new Set([
                JwtVerifier.ClaimNames.EXPIRATION_TIME,
                JwtVerifier.ClaimNames.SUBJECT,
                JwtVerifier.ClaimNames.NOT_BEFORE,
            ]),
            new Map([
                [JwtVerifier.ClaimNames.AUDIENCE, expectedAudience],
                [JwtVerifier.ClaimNames.ISSUER, expectedIssuer],
            ]),
        );
    }
}
