import { Request, Response, NextFunction } from "express";
import { APIGatewayProxyEvent } from "aws-lambda";
import { createEventRequest } from "../utils/event-request-factory";
import {
    convertHttpHeadersToAPIGatewayHeaders,
    convertUrlEncodedRequestBodyToString,
} from "../utils/incoming-request-converters";

export const prepareEventMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const event: APIGatewayProxyEvent = createEventRequest({
        body: convertUrlEncodedRequestBodyToString(req.body),
        headers: convertHttpHeadersToAPIGatewayHeaders(req.headers),
    });
    res.locals.event = event;

    next();
};
