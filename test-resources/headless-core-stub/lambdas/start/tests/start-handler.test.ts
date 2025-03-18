import { clearCaches } from "@aws-lambda-powertools/parameters";
import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { APIGatewayProxyEvent } from "aws-lambda/trigger/api-gateway-proxy";
import { mockClient } from "aws-sdk-client-mock";
import { generateKeyPairSync } from "crypto";
import { StartLambdaHandler } from "../src/start-handler";
import { TestData } from "./test-data";

describe("start-handler", () => {
    process.env.DECRYPTION_KEY_ID = "abc123";
    const mockSSMClient = mockClient(SSMClient);
    const mockKMSClient = mockClient(KMSClient);

    beforeEach(() => {
        mockSSMClient
            .on(GetParameterCommand, {
                Name: "/common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/issuer",
            })
            .resolvesOnce({ Parameter: { Value: "https://localhost.com" } });
        mockSSMClient
            .on(GetParameterCommand, {
                Name: "/common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/redirectUri",
            })
            .resolvesOnce({ Parameter: { Value: "https://localhost.com/callback" } });
        mockSSMClient
            .on(GetParameterCommand, {
                Name: "/test-resources/ipv-core-stub-aws-headless/privateSigningKey",
            })
            .resolvesOnce({ Parameter: { Value: JSON.stringify(TestData.privateSigningKey) } });

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
        mockSSMClient.reset();
        mockKMSClient.reset();
        clearCaches();
    });

    it("returns 200", async () => {
        expect(true);
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: JSON.stringify({
                aud: "https://localhost.com",
            }),
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event);
        expect(result.statusCode).toEqual(200);
        const body = JSON.parse(result.body);
        expect(body.client_id).toEqual("ipv-core-stub-aws-headless");
        expect(body.request).toMatch(
            /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
        );
    });

    it("returns 400 when no aud field is in the body", async () => {
        expect(true);
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: JSON.stringify({}),
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event);
        expect(result).toEqual({
            body: '{"message":"Missing required body field: aud (audience) not present"}',
            statusCode: 400,
        });
    });

    it("returns 400 when aud is not a valid uri", async () => {
        expect(true);
        const startLambdaHandler = new StartLambdaHandler();
        const event = {
            body: JSON.stringify({
                aud: "invalid",
            }),
        } as unknown as APIGatewayProxyEvent;

        const result = await startLambdaHandler.handler(event);
        expect(result).toEqual({ body: '{"message":"Claims set failed validation"}', statusCode: 400 });
    });
});
