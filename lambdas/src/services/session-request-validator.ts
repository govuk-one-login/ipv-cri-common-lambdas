import { JwtVerifier } from "../common/security/jwt-verifier";
import { JWTPayload } from "jose";
import { SessionRequestValidationConfig } from "../types/session-request-validation-config";
import { ClientConfigKey } from "../types/config-keys";
import { Logger } from "@aws-lambda-powertools/logger";
import { SessionValidationError } from "../common/utils/errors";

export class SessionRequestValidator {
    constructor(private validationConfig: SessionRequestValidationConfig, private jwtVerifier: JwtVerifier) {}
    async validateJwt(jwt: Buffer, requestBodyClientId: string): Promise<JWTPayload> {
        const expectedRedirectUri = this.validationConfig.expectedJwtRedirectUri;

        const payload = await this.verifyJwtSignature(jwt);
        if (!payload) {
            throw new SessionValidationError(
                "Session Validation Exception",
                "Invalid request: JWT validation/verification failed: JWT verification failure",
            );
        }

        const scope = payload["scope"] as string;
        const state = payload["state"] as string;

        if (payload.client_id !== requestBodyClientId) {
            throw new SessionValidationError(
                "Session Validation Exception",
                `Invalid request: JWT validation/verification failed: Mismatched client_id in request body (${requestBodyClientId}) & jwt (${payload.client_id})`,
            );
        } else if (!expectedRedirectUri) {
            throw new SessionValidationError(
                "Session Validation Exception",
                `Invalid request: JWT validation/verification failed: Unable to retrieve redirect URI for client_id: ${requestBodyClientId}`,
            );
        } else if (expectedRedirectUri !== payload.redirect_uri) {
            throw new SessionValidationError(
                "Session Validation Exception",
                `Invalid request: JWT validation/verification failed: Redirect uri ${payload.redirect_uri} does not match configuration uri ${expectedRedirectUri}`,
            );
            //uncomment once core add the scope into claims
            //} else if (!payload.scope || !scope.toLowerCase().includes("openid")) {
            //    throw new SessionValidationError("Session Validation Exception", "Invalid scope parameter");
        } else if (!state) {
            throw new SessionValidationError("Session Validation Exception", "Invalid state parameter");
        }

        return payload;
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
                JwtVerifier.ClaimNames.STATE,
                //JwtVerifier.ClaimNames.SCOPE, //uncomment once core add the scope into claims
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
                expectedJwtRedirectUri: criClientConfig.get(ClientConfigKey.JWT_REDIRECT_URI) as string,
                expectedJwtIssuer: criClientConfig.get(ClientConfigKey.JWT_ISSUER) as string,
                expectedJwtAudience: criClientConfig.get(ClientConfigKey.JWT_AUDIENCE) as string,
            },
            new JwtVerifier(
                {
                    jwtSigningAlgorithm: criClientConfig.get(ClientConfigKey.JWT_SIGNING_ALGORITHM) as string,
                    publicSigningJwk: criClientConfig.get(ClientConfigKey.JWT_PUBLIC_SIGNING_KEY) as string,
                },
                this.logger,
            ),
        );
    }
}
