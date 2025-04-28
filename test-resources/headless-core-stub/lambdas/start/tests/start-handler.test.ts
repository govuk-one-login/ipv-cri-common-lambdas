import { clearCaches } from "@aws-lambda-powertools/parameters";
import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { APIGatewayProxyEvent } from "aws-lambda/trigger/api-gateway-proxy";
import { mockClient } from "aws-sdk-client-mock";
import { generateKeyPairSync } from "crypto";
import { StartLambdaHandler } from "../src/start-handler";
import { TestData } from "../../../utils/tests/test-data";
import { Context } from "aws-lambda";
import { ClientConfiguration } from "../../../utils/src/services/client-configuration";

const mockKMSClient = mockClient(KMSClient);
let getParametersSpy: jest.SpyInstance;
describe("start-handler", () => {
    process.env.DECRYPTION_KEY_ID = "abc123";

    beforeEach(() => {
        getParametersSpy = jest.spyOn(ClientConfiguration, "getConfig").mockResolvedValueOnce({
            redirectUri: "https://localhost/callback",
            audience: "https://localhost",
            issuer: "https://localhost",
            privateSigningKey: JSON.stringify(TestData.privateSigningKey),
        });

        const { publicKey } = generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: "spki",
                format: "der",
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "der",
            },
        });

        mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: Buffer.from(publicKey) });
    });

    afterEach(() => {
        mockKMSClient.reset();
        clearCaches();
    });

    it("returns 200 when body is empty", async () => {
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: JSON.stringify({}),
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event, {} as Context);
        const body = JSON.parse(result.body);

        expect(result.statusCode).toEqual(200);
        expect(body.client_id).toEqual("ipv-core-stub-aws-headless");
        expect(getParametersSpy).toHaveBeenCalledWith(body.client_id);
        expect(body.request).toMatch(
            /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
        );
    });

    it("returns 200 when body is null", async () => {
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: null,
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event, {} as Context);
        const body = JSON.parse(result.body);

        expect(result.statusCode).toEqual(200);
        expect(body.client_id).toEqual("ipv-core-stub-aws-headless");
        expect(body.request).toMatch(
            /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
        );
    });

    it("returns 200 when body is fully populated with overrides", async () => {
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: JSON.stringify(TestData.jwtClaimsSet),
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event, {} as Context);
        const body = JSON.parse(result.body);

        expect(result.statusCode).toEqual(200);
        expect(body.client_id).toEqual("ipv-core-stub-aws-headless");
        expect(body.request).toMatch(
            /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
        );
    });

    it("returns 200 when body has an overridden client_id", async () => {
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: JSON.stringify({ client_id: "mock-client-id" }),
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event, {} as Context);
        const body = JSON.parse(result.body);

        expect(result.statusCode).toEqual(200);
        expect(body.client_id).toEqual("mock-client-id");
        expect(getParametersSpy).toHaveBeenCalledWith(body.client_id);
        expect(body.request).toMatch(
            /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
        );
    });

    it("returns 400 when claims set fails validation - aud is not a valid uri", async () => {
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: JSON.stringify({
                aud: "invalid",
            }),
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event, {} as Context);

        expect(result).toEqual({
            body: '{"message":"Claims set failed validation: /aud - must match format \\"uri\\""}',
            statusCode: 400,
        });
    });

    it("returns 400 when body is not valid json", async () => {
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: "{",
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event, {} as Context);

        expect(result).toEqual({
            body: '{"message":"Body is not valid JSON"}',
            statusCode: 400,
        });
    });
});
