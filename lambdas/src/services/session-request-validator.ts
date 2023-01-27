import { ValidationResult } from "../types/validation-result";
import { JwtVerifier } from "../common/security/jwt-verifier";
import { JWTPayload } from "jose";
import { SessionRequestValidationConfig } from "../types/session-request-validation-config";
import { ClientConfigKey } from "../common/config/config-keys";
import { Logger } from "@aws-lambda-powertools/logger";

export class SessionRequestValidator {
    constructor(private validationConfig: SessionRequestValidationConfig, private jwtVerifier: JwtVerifier) {}
    async validateJwt(jwt: Buffer, requestBodyClientId: string): Promise<ValidationResult> {
        const expectedRedirectUri = this.validationConfig.expectedJwtRedirectUri;
        const payload = await this.verifyJwtSignature(jwt);
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
    private async verifyJwtSignature(jwt: Buffer): Promise<JWTPayload | null> {
        const expectedIssuer = this.validationConfig.expectedJwtIssuer;
        const expectedAudience = this.validationConfig.expectedJwtAudience;
        return await this.jwtVerifier.verify(
            jwt,
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

export class SessionRequestValidatorFactory {
    constructor(private readonly logger: Logger) {}
    public create(criClientConfig: Map<string, string>): SessionRequestValidator {
        return new SessionRequestValidator(
            {
                expectedJwtRedirectUri: criClientConfig.get(ClientConfigKey.JWT_REDIRECT_URI)!,
                expectedJwtIssuer: criClientConfig.get(ClientConfigKey.JWT_ISSUER)!,
                expectedJwtAudience: criClientConfig.get(ClientConfigKey.JWT_AUDIENCE)!,
            },
            new JwtVerifier(
                {
                    jwtSigningAlgorithm: criClientConfig.get(ClientConfigKey.JWT_SIGNING_ALGORITHM)!,
                    publicSigningJwk: criClientConfig.get(ClientConfigKey.JWT_PUBLIC_SIGNING_KEY)!,
                },
                this.logger,
            ),
        );
    }
}
