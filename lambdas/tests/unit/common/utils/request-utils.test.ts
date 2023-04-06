import { APIGatewayProxyEvent, APIGatewayProxyEventHeaders } from "aws-lambda";
import { getClientIpAddress, getSessionId } from "../../../../src/common/utils/request-utils";
import { InvalidRequestError } from "../../../../src/common/utils/errors";

describe("request-utils", () => {
    describe("getClientIpAddress", () => {
        test("returns the value of x-forwarded-for header", () => {
            const result = getClientIpAddress({
                headers: {
                    "x-forwarded-for": "192.168.1.1",
                },
            } as unknown as APIGatewayProxyEvent);
            expect(result).toBe("192.168.1.1");
        });
        test("returns the value of x-forwarded-for when corresponding event header is uppercase", () => {
            const result = getClientIpAddress({
                headers: {
                    "X-FORWARDED-FOR": "192.168.1.1",
                },
            } as unknown as APIGatewayProxyEvent);
            expect(result).toBe("192.168.1.1");
        });
        test("return undefined if x-forwarded-for header is not present", () => {
            const result = getClientIpAddress({
                headers: {},
            } as unknown as APIGatewayProxyEvent);
            expect(result).toBeUndefined;
        });
        test("returns undefined, if another header is present instead of x-forwarded-for", () => {
            const result = getClientIpAddress({
                headers: {
                    forwarded: "12345",
                },
            } as unknown as APIGatewayProxyEvent);
            expect(result).toBeUndefined;
        });
    });
    describe("getSessionId", () => {
        test("returns the value of session-id header", () => {
            const result = getSessionId({
                headers: {
                    "session-id": "12345",
                },
            } as unknown as APIGatewayProxyEvent);
            expect(result).toBe("12345");
        });
        test("returns the value of session-id header when corresponding event header is uppercase", () => {
            const result = getSessionId({
                headers: {
                    "SESSION-ID": "12345",
                },
            } as unknown as APIGatewayProxyEvent);
            expect(result).toBe("12345");
        });
        test("returns undefined, if session-id header is not present", () => {
            const result = getSessionId({
                headers: {
                    "session-id": "12345",
                },
            } as unknown as APIGatewayProxyEvent);
            expect(result).toBeUndefined;
        });
        test("returns undefined, if another header is present instead of session-id", () => {
            expect(() =>
                getSessionId({
                    headers: {
                        session: "18345",
                    },
                } as unknown as APIGatewayProxyEvent),
            ).toThrow("Invalid request: Missing session-id header");
        });
    });
    describe("matching headers", () => {
        test("getSessionId throws an error if there are multiple session-id headers", () => {
            const event: Partial<APIGatewayProxyEvent> = {
                multiValueHeaders: {
                    "session-id": ["123", "456"],
                },
            } as unknown as APIGatewayProxyEventHeaders;

            expect(() => getSessionId(event as APIGatewayProxyEvent)).toThrow(
                new InvalidRequestError("Unexpected quantity of session-id headers encountered: 2"),
            );
        });
    });
});
