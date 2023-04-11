import { MiddlewareObj, Request } from "@middy/core";
import { SessionService } from "../../services/session-service";
import { RequestPayload } from "../../types/request_payload";
import { SessionItem } from "../../types/session-item";

const defaults = {};

const getSessionById = (opts: { sessionService: SessionService }): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        const event_body = request.event.body as SessionItem & RequestPayload;
        const sessionItem = await options.sessionService.getSession(event_body.sessionId);
        request.event = {
            ...request.event,
            body: {
                ...sessionItem,
                ...event_body,
            },
        };
        await request.event;
    };

    return {
        before,
    };
};

export default getSessionById;
