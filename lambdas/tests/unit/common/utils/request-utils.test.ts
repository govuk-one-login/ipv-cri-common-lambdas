import { jest } from "@jest/globals";
import { APIGatewayProxyEvent } from "aws-lambda";
import { getClientIpAddress, getSessionId } from "../../../../src/common/utils/request-utils";
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
            expect(()=> getSessionId({
                headers: {
                    session: "18345",
                },
            } as unknown as APIGatewayProxyEvent)).toThrow("Invalid request: Missing session-id header");
        });
    });
    describe("matching headers", () => {
        test("throws if there are multiple session-id headers", () => {
            jest.spyOn(global.Object, "keys").mockReturnValueOnce(["session-id", "session-id"]);
            const event = {
                headers: {} as unknown,
            } as unknown as APIGatewayProxyEvent;
            expect(() => getSessionId(event)).toThrow;
        });
    });
});
