import {
    APIGatewayProxyEvent,
    APIGatewayEventRequestContextWithAuthorizer,
    APIGatewayEventDefaultAuthorizerContext,
} from "aws-lambda";

export const createEventRequest = (overrides?: Partial<APIGatewayProxyEvent>): APIGatewayProxyEvent =>
    ({
        requestContext: {} as APIGatewayEventRequestContextWithAuthorizer<APIGatewayEventDefaultAuthorizerContext>,
        ...overrides,
    }) as APIGatewayProxyEvent;
