import { APIGatewayProxyEventQueryStringParameters } from "aws-lambda/trigger/api-gateway-proxy";
import { ValidationResult } from "../types/validation-result";

export class AuthorizationRequestValidator {
    validate(
        queryStringParams: APIGatewayProxyEventQueryStringParameters | null,
        sessionClientId: string,
        expectedRedirectUri: string,
    ): ValidationResult {
        if (!queryStringParams) {
            return { isValid: false, errorMsg: "Missing querystring parameters" };
        }

        const clientId = queryStringParams["client_id"];
        const redirectUri = queryStringParams["redirect_uri"];
        const responseType = queryStringParams["response_type"];
        let errorMsg = null;
        if (!clientId) {
            errorMsg = "Missing client_id parameter";
        } else if (!redirectUri) {
            errorMsg = "Missing redirect_uri parameter";
        } else if (!responseType) {
            errorMsg = "Missing response_type parameter";
        } else if (clientId !== sessionClientId) {
            errorMsg = "Invalid client_id parameter";
        } else if (redirectUri !== expectedRedirectUri) {
            errorMsg = "Invalid redirect_uri parameter";
        }

        return { isValid: !errorMsg, errorMsg: errorMsg };
    }
}
