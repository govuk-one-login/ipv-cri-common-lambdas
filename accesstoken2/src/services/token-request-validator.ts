import { ValidationResult } from "../types/validation-result";
import { ConfigService } from "./config-service";
import { SessionItem } from "../types/session-item";
import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerifier } from "./jwt-verifier";
import { JWTPayload } from "jose";
import { InvalidAccessTokenError, InvalidRequestError } from "../types/errors";

const logger = new Logger();

export class AccessTokenRequestValidator {
    constructor(private configService: ConfigService, private jwtVerifier: JwtVerifier) { }

    public validatePayload(tokenRequestBody: string): void {
        const searchParams = new URLSearchParams(tokenRequestBody);
        const grant_type = searchParams.get("grant_type");
        const redirectUri = searchParams.get("redirect_uri");
        const code = searchParams.get("code");
        const client_assertion_type = searchParams.get("client_assertion_type");
        const client_assertion = searchParams.get("client_assertion");

        if (!code) {
            throw new InvalidRequestError("Invalid request: Missing code parameter");
        }
        if (!redirectUri) {
            throw new InvalidRequestError("Invalid request: Missing redirectUri parameter");
        }
        if (!grant_type || grant_type !== "authorization_code") {
            throw new InvalidRequestError("Invalid grant_type parameter");
        }
        if (
            !client_assertion_type ||
            client_assertion_type !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ) {
            throw new InvalidRequestError("Invalid client_assertion_type parameter");
        }
        // TODO: Need to validate if client_assertion is a valid JWT string, perhaps code from Session Service can be used later on.
        if (!client_assertion) {
            throw new InvalidRequestError("Invalid client_assertion parameter");
        }
    }

    public validateTokenRequestToRecord(
        authCode: string | null,
        sessionItem: SessionItem,
    ): void {

        if (authCode !== sessionItem.authorizationCode) {
            throw new InvalidAccessTokenError();
        }

        const configRedirectUri = this.configService.getRedirectUri(sessionItem.clientId);
        if (configRedirectUri !== sessionItem.redirectUri) {
            throw new InvalidRequestError(`Invalid request: redirect uri ${sessionItem.redirectUri} does not match configuration uri ${configRedirectUri}`)
        }
    }

    public async verifyJwtSignature(jwt: Buffer, clientId: string, audience: string): Promise<JWTPayload> {
        return await this.jwtVerifier.verify(
            jwt,
            clientId,
            new Set([
                JwtVerifier.ClaimNames.EXPIRATION_TIME,
                JwtVerifier.ClaimNames.SUBJECT,
                JwtVerifier.ClaimNames.ISSUER,
                JwtVerifier.ClaimNames.AUDIENCE,
                JwtVerifier.ClaimNames.JWT_ID,
            ]),
            new Map([
                [JwtVerifier.ClaimNames.AUDIENCE, audience],
                [JwtVerifier.ClaimNames.SUBJECT, clientId],
                [JwtVerifier.ClaimNames.ISSUER, clientId],
            ]),
        );
    }
}
