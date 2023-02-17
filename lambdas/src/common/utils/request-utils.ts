import { APIGatewayProxyEvent } from "aws-lambda";
import { InvalidRequestError } from "../../types/errors";

const getHeaderValue = (event: APIGatewayProxyEvent, desiredHeader: string) => {
    const matchingHeaders: string[] = Object.keys(event?.headers ?? {}).filter(
        (header) => header.toLowerCase().trim() === desiredHeader,
    );
    if (matchingHeaders.length > 1) {
        throw new Error(`Unexpected quantity of ${desiredHeader} headers encountered: ${matchingHeaders.length}`);
    } else if (matchingHeaders.length === 1) {
        return event.headers[matchingHeaders[0]];
    }
    return undefined;
};

export const getClientIpAddress = (event: APIGatewayProxyEvent) => {
    return getHeaderValue(event, "x-forwarded-for");
};
export const getSessionId = (event: APIGatewayProxyEvent) => {
    const sessionIdHeader = getHeaderValue(event, "session-id");
    if (!sessionIdHeader) {
        throw new InvalidRequestError("Invalid request: Missing session-id header");
    }
    return sessionIdHeader;
};
