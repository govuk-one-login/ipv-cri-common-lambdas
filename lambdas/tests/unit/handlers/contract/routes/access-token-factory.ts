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
import { ClientConfigKey, CommonConfigKey } from "../../../../../src/types/config-keys";

const parameterPathPrefix = process.env.AWS_STACK_NAME || "";
const { JWT_AUDIENCE, JWT_PUBLIC_SIGNING_KEY, JWT_REDIRECT_URI, JWT_SIGNING_ALGORITHM, JWKS_ENDPOINT } =
    ClientConfigKey;
const { SESSION_TABLE_NAME, SESSION_TTL } = CommonConfigKey;

export const CreateAccessTokenLambda = (redirectUri: string, componentId: string) => {
    const msToSeconds = (ms: number) => Math.round(ms / 1000);
    const twoDaysOffset = 2 * 60 * 60 * 24;

    const sessionItemStateInDbBeforeTokenRequest: SessionItem = {
        sessionId: "a-session-id",
        clientId: "ipv-core",
        clientSessionId: "clientSessionId",
        redirectUri,
        accessToken: "accesstoken",
        authorizationCode: "dummyAuthCode",
        expiryDate: msToSeconds(Date.now()) + twoDaysOffset,
        authorizationCodeExpiryDate: msToSeconds(Date.now()) + twoDaysOffset,
        accessTokenExpiryDate: msToSeconds(Date.now()) + twoDaysOffset,
    };

    const configService = new ConfigService(
        new MockSSMProvider({
            [`/${parameterPathPrefix}/${SESSION_TABLE_NAME}`]: "SessionTable",
            [`/${parameterPathPrefix}/${SESSION_TTL}`]: "10",
            [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWT_SIGNING_ALGORITHM}`]: "ES256",
            [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWT_REDIRECT_URI}`]: redirectUri,
            [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWT_AUDIENCE}`]: componentId,
            [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWT_PUBLIC_SIGNING_KEY}`]: "mock_public_key",
            [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWKS_ENDPOINT}`]:
                "http://localhost/.well-known/jwks.json",
        }) as unknown as SSMProvider,
    );

    const mockDynamoDbClient = new MockDynamoDBDocument({
        '{"sessionId": "a-session-id"}': sessionItemStateInDbBeforeTokenRequest,
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
