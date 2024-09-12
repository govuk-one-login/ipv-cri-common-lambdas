import { APIGatewayProxyEventHeaders } from "aws-lambda";
import { IncomingHttpHeaders } from "http";

const convertUrlEncodedRequestBodyToString = (body: { [key: string]: string }): string =>
    new URLSearchParams(body).toString();

const convertHttpHeadersToAPIGatewayHeaders = (incomingHeaders: IncomingHttpHeaders): APIGatewayProxyEventHeaders => {
    const apiGatewayHeaders: APIGatewayProxyEventHeaders = {};

    for (const [key, value] of Object.entries(incomingHeaders)) {
        if (value) {
            apiGatewayHeaders[key] = Array.isArray(value) ? value.join(", ") : value.toString();
        }
    }

    return apiGatewayHeaders;
};

export { convertHttpHeadersToAPIGatewayHeaders, convertUrlEncodedRequestBodyToString };
