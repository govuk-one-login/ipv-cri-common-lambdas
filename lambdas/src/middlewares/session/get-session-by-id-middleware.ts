import { MiddlewareObj, Request } from "@middy/core";
import { SessionService } from "../../services/session-service";
import { getSessionId } from "../../common/utils/request-utils";

const defaults = {};

const getSessionByIdMiddleware = (opts: { sessionService: SessionService }): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        const event = request.event;
        const sessionId = event?.body?.sessionId || getSessionId(event);
        const sessionItem = await options.sessionService.getSession(sessionId);
        request.event = {
            ...request.event,
            body: {
                ...sessionItem,
                ...event.body,
            },
        };
        await request.event;
    };

    return {
        before,
    };
};

export default getSessionByIdMiddleware;
