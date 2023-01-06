import { APIGatewayProxyEventQueryStringParameters } from "aws-lambda/trigger/api-gateway-proxy";
import { ValidationResult } from "../types/validation-result";
import { ConfigService } from "./config-service";

export class SessionRequestValidator {
    constructor(private configService: ConfigService) {}
    async validate(
        queryStringParams: APIGatewayProxyEventQueryStringParameters | null,
        sessionClientId: string,
    ): Promise<ValidationResult> {
        if (!queryStringParams) {
            return { isValid: false, errorMsg: "Missing querystring parameters" };
        }

        const clientId = queryStringParams["client_id"];
        const redirectUri = queryStringParams["redirect_uri"];
        const responseType = queryStringParams["response_type"];
        let errorMsg = null;
        if (!clientId) {
            errorMsg = "Missing client_id parameter";
        }
        if (!redirectUri) {
            errorMsg = "Missing redirect_uri parameter";
        }
        if (!responseType) {
            errorMsg = "Missing response_type parameter";
        }
        if (clientId !== sessionClientId) {
            errorMsg = "Invalid client_id parameter";
        }

        return { isValid: !errorMsg, errorMsg: errorMsg };
    }
}
