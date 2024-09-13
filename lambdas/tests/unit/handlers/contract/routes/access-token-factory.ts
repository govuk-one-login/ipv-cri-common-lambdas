import { SSMProvider } from "@aws-lambda-powertools/parameters/ssm";
import { ConfigService } from "../../../../../src/common/config/config-service";
import { JwtVerifierFactory } from "../../../../../src/common/security/jwt-verifier";
import { logger } from "../../../../../src/common/utils/power-tool";
import { AccessTokenLambda } from "../../../../../src/handlers/access-token-handler";
import { SessionService } from "../../../../../src/services/session-service";
import { AccessTokenRequestValidator } from "../../../../../src/services/token-request-validator";
import { SessionItem } from "../../../../../src/types/session-item";
import { MockSSMProvider } from "../mocks/mock-ssm-provider";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { BearerAccessTokenFactory } from "../../../../../src/services/bearer-access-token-factory";
import { MockDynamoDBDocument } from "../mocks/mock-dynamo-db-document";

export const CreateAccessTokenLambda = (mockSSMProvider: MockSSMProvider, redirectUri: string) => {
    const configService = new ConfigService(mockSSMProvider as unknown as SSMProvider);

    const msToSeconds = (ms: number) => Math.round(ms / 1000);
    const twoDaysOffset = 2 * 60 * 60 * 24;

    const sessionItemInDbBeforeTokenRequest: SessionItem = {
        sessionId: "a-session-id",
        clientId: "ipv-core",
        clientSessionId: "clientSessionId",
        redirectUri: redirectUri,
        accessToken: "accesstoken",
        authorizationCode: "dummyAuthCode",
        expiryDate: msToSeconds(Date.now()) + twoDaysOffset,
        authorizationCodeExpiryDate: msToSeconds(Date.now()) + twoDaysOffset,
        accessTokenExpiryDate: msToSeconds(Date.now()) + twoDaysOffset,
    };

    const mockDynamoDbClient = new MockDynamoDBDocument({
        '{"sessionId": "a-session-id"}': sessionItemInDbBeforeTokenRequest,
    });

    const accessTokenValidator = new AccessTokenRequestValidator(new JwtVerifierFactory(logger));
    const mockVerifySignature = async (_: string, __: string, ___: Map<string, string>) => Promise.resolve();
    accessTokenValidator.verifyJwtSignature = mockVerifySignature;

    return new AccessTokenLambda(
        configService,
        new BearerAccessTokenFactory(configService.getBearerAccessTokenTtl()),
        new SessionService(mockDynamoDbClient as unknown as DynamoDBDocument, configService),
        accessTokenValidator,
    );
};
