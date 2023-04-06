import { APIGatewayProxyEvent } from "aws-lambda";
import { InvalidRequestError } from "./errors";

const getHeaderValue = (event: APIGatewayProxyEvent, desiredHeader: string) => {
    // https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    const matchingHeaders: string[] = Object.keys(event?.multiValueHeaders ?? {}).filter(
        (header) => header.toLowerCase().trim() === desiredHeader,
    );
    const matchingHeadersLength =
        matchingHeaders[0] && (event?.multiValueHeaders[matchingHeaders[0]]?.length as number);
    if (+matchingHeadersLength > 1) {
        throw new InvalidRequestError(
            `Unexpected quantity of ${desiredHeader} headers encountered: ${matchingHeadersLength}`,
        );
    } else {
        const matchingHeader: string = Object.keys(event?.headers ?? {}).find(
            (header) => header.toLowerCase().trim() === desiredHeader,
        ) as string;
        return matchingHeader && event.headers[matchingHeader];
    }
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
