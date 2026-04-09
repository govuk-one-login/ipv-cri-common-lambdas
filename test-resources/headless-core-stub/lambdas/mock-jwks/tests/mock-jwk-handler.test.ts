import { JSONWebKeySet } from "jose";
import { MockJwkHandler } from "../src/mock-jwk-handler";
import * as JWKS from "../src/services/cache-jwk";
import { APIGatewayProxyEvent, Context } from "aws-lambda";
import { expect, describe, MockInstance, vi } from "vitest";

const mockJwksEmpty = {
    jwks: { keys: [] } as JSONWebKeySet,
};

const mockJwksNonEmpty = {
    jwks: { keys: [{ kid: "key-1" }] } as JSONWebKeySet,
};
describe("MockJwkHandler", () => {
    let generateJWKSSpy: MockInstance;
    beforeEach(() => {
        generateJWKSSpy = vi.spyOn(JWKS, "generateJWKS").mockResolvedValueOnce(mockJwksEmpty);
    });

    afterEach(async () => vi.clearAllMocks());
    it("returns 404 when JWKS is empty", async () => {
        generateJWKSSpy = vi.spyOn(JWKS, "generateJWKS").mockResolvedValueOnce(mockJwksNonEmpty);

        const event = {
            httpMethod: "GET",
            path: "/.well-known/jwks.json",
        } as unknown as APIGatewayProxyEvent;

        const handler = new MockJwkHandler();
        const result = await handler.handler(event, {} as Context);

        expect(generateJWKSSpy).toHaveBeenCalled();
        expect(result.statusCode).toBe(404);
        expect(JSON.parse(result.body)).toEqual({ error: "JWKS not found" });
    });
    it("returns JWKS on /.well-known/jwks.json path", async () => {
        const event = {
            httpMethod: "GET",
            path: "/.well-known/jwks.json",
        } as unknown as APIGatewayProxyEvent;

        const handler = new MockJwkHandler();
        const result = await handler.handler(event, {} as Context);

        expect(result.statusCode).toBe(200);
        expect(JSON.parse(result.body)).toEqual({ keys: [{ kid: "key-1" }] });
        expect(generateJWKSSpy).toHaveBeenCalled();
    });
});
