import { ConfigService } from "../common/config-service";
import { SessionItem } from "../../types/session-item";
import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerifier } from "../common/jwt-verifier-service";
import { InvalidAccessTokenError, InvalidPayloadError, InvalidRequestError } from "../../types/errors";
import { RequestPayload } from "../../types/request_payload";

const logger = new Logger();

export class AccessTokenRequestValidator {
    constructor(private configService: ConfigService, private jwtVerifier: JwtVerifier) {}

    public validatePayload(tokenRequestBody: string | null): RequestPayload {
        if (!tokenRequestBody) throw new InvalidRequestError("Invalid request: missing body");

        const searchParams = new URLSearchParams(tokenRequestBody);
        const code = searchParams.get("code");
        const redirectUri = searchParams.get("redirect_uri");
        const client_assertion = searchParams.get("client_assertion");
        const client_assertion_type = searchParams.get("client_assertion_type");
        const grant_type = searchParams.get("grant_type");

        if (!redirectUri) throw new InvalidRequestError("Invalid request: Missing redirectUri parameter");
        if (!code) throw new InvalidRequestError("Invalid request: Missing code parameter");
        if (!client_assertion) throw new InvalidRequestError("Invalid client_assertion parameter");

        if (!grant_type || grant_type !== "authorization_code") {
            throw new InvalidRequestError("Invalid grant_type parameter");
        }
        if (
            !client_assertion_type ||
            client_assertion_type !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ) {
            throw new InvalidRequestError("Invalid grant_type parameter");
        }

        return { grant_type, code, redirectUri, client_assertion_type, client_assertion };
    }

    public validateTokenRequestToRecord(authCode: string, sessionItem: SessionItem) {
        if (!sessionItem) return new InvalidPayloadError("Invalid sessionItem");
        if (authCode !== sessionItem.authorizationCode) throw new InvalidAccessTokenError();

        const configRedirectUri = this.configService.getRedirectUri(sessionItem.clientId);
        if (configRedirectUri !== sessionItem.redirectUri) {
            throw new InvalidRequestError(
                `Invalid request: redirect uri ${sessionItem.redirectUri} does not match configuration uri ${configRedirectUri}`,
            );
        }
    }

    public async verifyJwtSignature(jwt: Buffer, clientId: string, audience: string): Promise<void> {
        if (!audience) throw new InvalidRequestError("audience is missing");

        const jwtPayload = await this.jwtVerifier.verify(
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

        if (!jwtPayload.jti) throw new InvalidRequestError("jti is missing");
    }
}
