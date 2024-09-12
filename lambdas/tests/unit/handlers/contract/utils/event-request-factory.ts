import {
    APIGatewayProxyEvent,
    APIGatewayEventRequestContextWithAuthorizer,
    APIGatewayEventDefaultAuthorizerContext,
} from "aws-lambda";

export const createEventRequest = (overrides?: Partial<APIGatewayProxyEvent>): APIGatewayProxyEvent =>
    ({
        body: "",
        requestContext: {} as APIGatewayEventRequestContextWithAuthorizer<APIGatewayEventDefaultAuthorizerContext>,
        headers: {},
        ...overrides,
    }) as APIGatewayProxyEvent;
