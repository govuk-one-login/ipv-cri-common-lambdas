import { SessionItem } from "../types/session-item";
import { InvalidAccessTokenError, InvalidPayloadError, InvalidRequestError } from "../common/utils/errors";
import { RequestPayload } from "../types/request_payload";
import { JwtVerifier, JwtVerifierFactory } from "../common/security/jwt-verifier";
import { ClientConfigKey } from "../types/config-keys";

export class AccessTokenRequestValidator {
    public constructor(private readonly jwtVerifierFactory: JwtVerifierFactory) {}

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

    public validateTokenRequestToRecord(authCode: string, sessionItem: SessionItem, expectedRedirectUri: string) {
        if (!sessionItem) return new InvalidPayloadError("Invalid sessionItem");
        if (authCode !== sessionItem.authorizationCode) throw new InvalidAccessTokenError();

        if (expectedRedirectUri !== sessionItem.redirectUri) {
            throw new InvalidRequestError(
                `Invalid request: redirect uri ${sessionItem.redirectUri} does not match configuration uri ${expectedRedirectUri}`,
            );
        }
    }
    public async verifyJwtSignature(jwt: string, clientId: string, clientConfig: Map<string, string>): Promise<void> {
        const jwtVerifier = this.jwtVerifierFactory.create(
            clientConfig.get(ClientConfigKey.JWT_SIGNING_ALGORITHM) as string,
            clientConfig.get(ClientConfigKey.JWT_PUBLIC_SIGNING_KEY) as string,
        );

        const jwtPayload = await jwtVerifier.verify(
            Buffer.from(jwt, "utf-8"),
            new Set([
                JwtVerifier.ClaimNames.EXPIRATION_TIME,
                JwtVerifier.ClaimNames.SUBJECT,
                JwtVerifier.ClaimNames.ISSUER,
                JwtVerifier.ClaimNames.AUDIENCE,
                JwtVerifier.ClaimNames.JWT_ID,
            ]),
            new Map([
                [JwtVerifier.ClaimNames.AUDIENCE, clientConfig.get(ClientConfigKey.JWT_AUDIENCE) as string],
                [JwtVerifier.ClaimNames.SUBJECT, clientId],
                [JwtVerifier.ClaimNames.ISSUER, clientId],
            ]),
        );
        if (!jwtPayload) {
            throw new InvalidRequestError("JWT signature verification failed");
        }
    }
}
