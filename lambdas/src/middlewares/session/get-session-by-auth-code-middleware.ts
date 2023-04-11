import { MiddlewareObj, Request } from "@middy/core";
import { APIGatewayProxyEvent } from "aws-lambda";
import { SessionService } from "../../services/session-service";
import { RequestPayload } from "../../types/request_payload";

const defaults = {};

const getSessionByAuthCodeMiddleware = (opts: { sessionService: SessionService }): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        const requestPayload = request.event.body as RequestPayload;
        const sessionItem = await options.sessionService.getSessionByAuthorizationCode(requestPayload.code);
        request.event = {
            body: {
                ...sessionItem,
                ...requestPayload,
            },
        } as unknown as APIGatewayProxyEvent;
        await request.event;
    };

    return {
        before,
    };
};

export default getSessionByAuthCodeMiddleware;
