import { Request, Response, NextFunction } from "express";
import { APIGatewayProxyEvent } from "aws-lambda";
import { createEventRequest } from "../utils/event-request-factory";
import {
    convertHttpHeadersToAPIGatewayHeaders,
    convertBodyToAuthRequest,
    urlEncodeAuthRequest,
} from "../utils/incoming-request-converters";

export const prepareEventMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const jsonBody = convertBodyToAuthRequest(req.body);
    const event: APIGatewayProxyEvent = createEventRequest({
        body: urlEncodeAuthRequest(jsonBody),
        headers: convertHttpHeadersToAPIGatewayHeaders(req.headers),
    });
    res.locals.event = event;
    res.locals.json = jsonBody;
    res.locals.componentId = req.headers["component-id"];

    next();
};
