import { MiddlewareObj, Request } from "@middy/core";
import { APIGatewayProxyEvent } from "aws-lambda";
import { AccessTokenRequestValidator } from "../../services/token-request-validator";

const defaults = {};

const validateEventPayloadMiddleware = (opts: { requestValidator: AccessTokenRequestValidator }): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        const event = request.event as APIGatewayProxyEvent;

        request.event = {
            body: options.requestValidator.validatePayload(event.body),
        } as unknown as APIGatewayProxyEvent;

        await request.event;
    };

    return {
        before,
    };
};

export default validateEventPayloadMiddleware;
