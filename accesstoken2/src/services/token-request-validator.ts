import { ValidationResult } from "../types/validation-result";
import { ConfigService } from "./config-service";
import { SessionItem } from "../types/session-item";
import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerifier } from "./jwt-verifier";

const logger = new Logger();

export class AccessTokenRequestValidator {
    constructor(private configService: ConfigService) {}

    async validate(tokenRequestBody: string | null): Promise<ValidationResult> {
        if (!tokenRequestBody) {
            return { isValid: false, errorMsg: "Missing request body parameters" };
        }

        const searchParams = new URLSearchParams(tokenRequestBody);
        const grant_type = searchParams.get("grant_type");
        const redirectUri = searchParams.get("redirect_uri");
        const code = searchParams.get("code");
        const client_assertion_type = searchParams.get("client_assertion_type");
        const client_assertion = searchParams.get("client_assertion");

        let errorMsg = null;

        if (!code) {
            errorMsg = "Missing code parameter";
        }
        if (!redirectUri) {
            errorMsg = "Missing redirectUri parameter";
        }
        if (!grant_type || grant_type !== "authorization_code") {
            errorMsg = "Invalid grant_type parameter";
        }
        if (
            !client_assertion_type ||
            client_assertion_type !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ) {
            errorMsg = "Invalid client_assertion_type parameter";
        }
        // TODO: Need to validate if client_assertion is a valid JWT string, perhaps code from Session Service can be used later on.
        if (!client_assertion) {
            errorMsg = "Invalid client_assertion parameter";
        }

        return { isValid: !errorMsg, errorMsg: errorMsg };
    }

    async validateTokenRequest(
        authCode: string | null,
        sessionItem: SessionItem,
        jwt: string,
    ): Promise<ValidationResult> {
        let errorMsg = null;

        console.log(`AccessTokenRequestValidator.jwt with: ${jwt}`);
        if (authCode !== sessionItem.authorizationCode) {
            errorMsg = "1026 : Access token expired";
        }
        const configRedirectUri = this.configService.getRedirectUri(sessionItem.clientId);
        if (configRedirectUri !== sessionItem.redirectUri) {
            errorMsg = `redirect uri ${sessionItem.redirectUri} does not match configuration uri ${configRedirectUri}`;
        }

        const payload = await new JwtVerifier(this.configService).verify(jwt, sessionItem.clientId);

        return { isValid: !errorMsg, errorMsg: errorMsg };
    }
}
