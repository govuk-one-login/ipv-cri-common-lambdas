import { JwtVerifier } from "../common/security/jwt-verifier";
import { JWTPayload, errors } from "jose";
import { SessionRequestValidationConfig } from "../types/session-request-validation-config";
import { ClientConfigKey } from "../types/config-keys";
import { Logger } from "@aws-lambda-powertools/logger";
import { SessionValidationError } from "../common/utils/errors";
import { EvidenceRequestSchema } from "../schemas/evidence-request.schema";

export class SessionRequestValidator {
    constructor(
        private readonly validationConfig: SessionRequestValidationConfig,
        private readonly jwtVerifier: JwtVerifier,
    ) {}
    async validateJwt(jwt: Buffer, requestBodyClientId: string): Promise<JWTPayload> {
        const expectedRedirectUri = this.validationConfig.expectedJwtRedirectUri;

        const payload = await this.verifyJwtSignature(jwt);

        const state = payload["state"] as string;

        if (payload["evidence_requested"] !== undefined) {
            this.validateEvidenceRequested(payload["evidence_requested"]);
        }

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
        } else if (!state) {
            throw new SessionValidationError("Session Validation Exception", "Invalid state parameter");
        }

        return payload;
    }

    private validateEvidenceRequested(evidenceRequestedRaw: unknown): void {
        const result = EvidenceRequestSchema.safeParse(evidenceRequestedRaw);
        if (!result.success) {
            const errors = result.error.issues.map((issue) => `${issue.path.join(".")} - ${issue.message}`).join(", ");
            throw new SessionValidationError("Session Validation Exception", `Invalid request: ${errors}`);
        }
    }

    private async verifyJwtSignature(jwt: Buffer): Promise<JWTPayload> {
        const expectedIssuer = this.validationConfig.expectedJwtIssuer;
        const expectedAudience = this.validationConfig.expectedJwtAudience;
        try {
            return await this.jwtVerifier.verify(
                jwt,
                new Set([
                    JwtVerifier.ClaimNames.EXPIRATION_TIME,
                    JwtVerifier.ClaimNames.SUBJECT,
                    JwtVerifier.ClaimNames.NOT_BEFORE,
                    JwtVerifier.ClaimNames.STATE,
                ]),
                new Map([
                    [JwtVerifier.ClaimNames.AUDIENCE, expectedAudience],
                    [JwtVerifier.ClaimNames.ISSUER, expectedIssuer],
                ]),
            );
        } catch (error) {
            const errorDetails = error instanceof errors.JOSEError ? error.code : "JWT verification failure";
            throw new SessionValidationError(
                "Session Validation Exception",
                `Invalid request: JWT validation/verification failed: ${errorDetails}`,
            );
        }
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
                    jwksEndpoint: criClientConfig.get(ClientConfigKey.JWKS_ENDPOINT) as string,
                },
                this.logger,
            ),
        );
    }
}
