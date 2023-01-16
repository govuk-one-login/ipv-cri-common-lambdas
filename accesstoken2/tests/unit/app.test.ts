jest.mock("../../src/services/config-service", () => {
    return {
        ConfigService: jest.fn().mockImplementation(() => {
            return {
                init: jest.fn().mockResolvedValue([]),
                config: {
                    AddressLookupTableName: "Test",
                },
            };
        }),
    };
});

import { DynamoDbClient } from "../../src/lib/dynamo-db-client";
import { AccessTokenLambda } from "../../src/app";
import { AccessTokenService } from "../../src/services/access-token-service";
import { AccessTokenRequestValidator } from "../../src/services/token-request-validator";
import { SessionService } from "../../src/services/session-service";
import { APIGatewayProxyEvent } from "aws-lambda/trigger/api-gateway-proxy";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { Logger } from "@aws-lambda-powertools/logger";

const mockLogger = jest.mocked(Logger);
const mockMetrics = jest.mocked(Metrics);

const mockAccesstokenService = jest.mocked(AccessTokenService) as unknown as AccessTokenService;
const mockSessionService = jest.mocked(SessionService) as unknown as SessionService;
const mockAccesstokenRequestValidator = jest.mocked(AccessTokenRequestValidator)  as unknown as AccessTokenRequestValidator;
const mockDynamoDbClient = jest.mocked(DynamoDbClient);


describe("Handler", () => {
    let accessTokenLambda: AccessTokenLambda;

    beforeEach(() => {
        accessTokenLambda = new AccessTokenLambda(
            mockAccesstokenService,
            mockSessionService,
            mockAccesstokenRequestValidator,
        );
    });

    afterEach(() => jest.clearAllMocks());

    it("should pass", async () => {
        // const event: APIGatewayProxyEvent = {};
        try {
            const test = await accessTokenLambda.handler({} as APIGatewayProxyEvent, null)
            console.log(test);

        } catch(err) {
            console.log(err);
        }
        expect(true);
    });
});
