import { APIGatewayProxyEventHeaders } from "aws-lambda";
import { IncomingHttpHeaders } from "http";
type AuthRequest = {
    code: string;
    client_assertion_type: string;
    grant_type: string;
    redirect_uri: string;
    client_assertion: string;
};

export const convertBodyToAuthRequest = (body: { [key: string]: string }): AuthRequest => {
    const params = new URLSearchParams(body);
    const formDataString = params.toString();
    const jsonString = decodeURIComponent(formDataString);
    return JSON.parse(jsonString);
};

export const urlEncodeAuthRequest = (jsonObject: AuthRequest): string => {
    return Object.entries(jsonObject)
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        .join("&");
};

export const convertHttpHeadersToAPIGatewayHeaders = (
    incomingHeaders: IncomingHttpHeaders,
): APIGatewayProxyEventHeaders => {
    const apiGatewayHeaders: APIGatewayProxyEventHeaders = {};
    for (const [key, value] of Object.entries(incomingHeaders)) {
        if (value) {
            apiGatewayHeaders[key] = Array.isArray(value) ? value.join(", ") : value.toString();
        }
    }
    return apiGatewayHeaders;
};
