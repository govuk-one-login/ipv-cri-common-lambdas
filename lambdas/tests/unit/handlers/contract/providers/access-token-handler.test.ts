import { ConfigService } from "../../../../../src/common/config/config-service";
import { logger, metrics, tracer as _tracer } from "../../../../../src/common/utils/power-tool";
import { JwtVerifierFactory } from "../../../../../src/common/security/jwt-verifier";
import { MockDynamoDBDocument } from "../mocks/mock-dynamo-db-document";
import { SessionService } from "../../../../../src/services/session-service";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { AccessTokenRequestValidator } from "../../../../../src/services/token-request-validator";
import { BearerAccessTokenFactory } from "../../../../../src/services/bearer-access-token-factory";
import { AccessTokenLambda } from "../../../../../src/handlers/access-token-handler";
import { injectLambdaContext } from "@aws-lambda-powertools/logger";
import middy from "@middy/core";
import initialiseClientConfigMiddleware from "../../../../../src/middlewares/config/initialise-client-config-middleware";
import initialiseConfigMiddleware from "../../../../../src/middlewares/config/initialise-config-middleware";
import getSessionByAuthCodeMiddleware from "../../../../../src/middlewares/session/get-session-by-auth-code-middleware";
import getSessionByIdMiddleware from "../../../../../src/middlewares/session/get-session-by-id-middleware";
import setGovUkSigningJourneyIdMiddleware from "../../../../../src/middlewares/session/set-gov-uk-signing-journey-id-middleware";
import setRequestedVerificationScoreMiddleware from "../../../../../src/middlewares/session/set-requested-verification-score-middleware";
import accessTokenValidatorMiddleware from "../../../../../src/middlewares/access-token/validate-event-payload-middleware";
import errorMiddleware from "../../../../../src/middlewares/error/error-middleware";

import { CommonConfigKey, ClientConfigKey } from "../../../../../src/types/config-keys";
import { APIGatewayProxyEvent, Context } from "aws-lambda";
import { SSMProvider } from "@aws-lambda-powertools/parameters/ssm";
import { MockSSMProvider } from "../mocks/mock-ssm-provider";
import { SessionItem } from "../../../../../src/types/session-item";

describe("access-token-handler.ts", () => {
    let sessionService: SessionService;
    let handler: middy.MiddyfiedHandler;
    let accessTokenLambda: AccessTokenLambda;

    const clientId = "ipv-core";
    const ACCESS_TOKEN = "accesstoken";
    const redirectUri = "https://identity.staging.account.gov.uk/credential-issuer/callback?id=kbv";
    const audience = "dummyExperianKbvComponentId";
    const publicKey =
        "eyJrdHkiOiJFQyIsImQiOiJPWHQwUDA1WnNRY0s3ZVl1c2dJUHNxWmRhQkNJSmlXNGltd1V0bmFBdGhVIiwiY3J2IjoiUC0yNTYiLCJ4IjoiRTlaenVPb3FjVlU0cFZCOXJwbVR6ZXpqeU9QUmxPbVBHSkhLaThSU2xJTSIsInkiOiJLbFRNWnRoSFpVa1l6NUFsZVRROGpmZjBUSmlTM3EyT0I5TDVGdzR4QTA0In0=";
    const clientAssertion =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlFeHBlcmlhbktidkNvbXBvbmVudElkIiwiZXhwIjo0MDcwOTA5NzAwLCJqdGkiOiJTY25GNGRHWHRoWllYU181azg1T2JFb1NVMDRXLUgzcWFfcDZucHYyWlVZIn0.aJOEpvnBRpaptv_2T7L5aCzhTdvlNaGNh3uwuK1f5cC9he9izuIr60s2_Y6-DIPEWLE0_L6ckgdIsy9G7yj8jA";

    const mockSSMProvider = new MockSSMProvider({
        "/di-ipv-cri-common-lambdas/SessionTableName": "SessionTable",
        "/di-ipv-cri-common-lambdas/SessionTtl": "10",
        "/di-ipv-cri-common-lambdas/clients/ipv-core/jwtAuthentication/issuer": "ipv-core",
        "/di-ipv-cri-common-lambdas/clients/ipv-core/jwtAuthentication/authenticationAlg": "ES256",
        "/di-ipv-cri-common-lambdas/clients/ipv-core/jwtAuthentication/redirectUri": redirectUri,
        "/di-ipv-cri-common-lambdas/clients/ipv-core/jwtAuthentication/audience": audience,
        "/di-ipv-cri-common-lambdas/clients/ipv-core/jwtAuthentication/publicSigningJwkBase64": publicKey, //pragma: allowlist secret
    });
    const mockVerifySignature = async (_: string, __: string, ___: Map<string, string>) => Promise.resolve();
    const msToSeconds = (ms: number) => Math.round(ms / 1000);
    const twoDaysOffset = 2 * 60 * 60 * 24;

    const sessionItem: SessionItem = {
        sessionId: "code",
        clientId,
        clientSessionId: "clientSessionId",
        redirectUri: redirectUri,
        accessToken: ACCESS_TOKEN,
        authorizationCode: "dummyAuthCode",
        expiryDate: msToSeconds(Date.now()) + twoDaysOffset,
        authorizationCodeExpiryDate: msToSeconds(Date.now()) + twoDaysOffset,
        accessTokenExpiryDate: msToSeconds(Date.now()) + twoDaysOffset,
    };

    const configService = new ConfigService(mockSSMProvider as unknown as SSMProvider);
    const jwtVerifierFactory = new JwtVerifierFactory(logger);
    const accessTokenValidator = new AccessTokenRequestValidator(jwtVerifierFactory);

    accessTokenValidator.verifyJwtSignature = mockVerifySignature;

    beforeEach(() => {
        const mockDynamoDbClient = new MockDynamoDBDocument({
            '{"sessionId": "code"}': sessionItem,
        });
        sessionService = new SessionService(mockDynamoDbClient as unknown as DynamoDBDocument, configService);

        accessTokenLambda = new AccessTokenLambda(
            configService,
            new BearerAccessTokenFactory(10),
            sessionService,
            accessTokenValidator,
        );

        handler = middy(accessTokenLambda.handler.bind(accessTokenLambda))
            .use(
                errorMiddleware(logger, metrics, {
                    metric_name: ACCESS_TOKEN,
                    message: "Access Token Lambda error occurred",
                }),
            )
            .use(injectLambdaContext(logger, { clearState: true }))
            .use(
                initialiseConfigMiddleware({
                    configService: configService,
                    config_keys: [CommonConfigKey.SESSION_TABLE_NAME, CommonConfigKey.SESSION_TTL],
                }),
            )
            .use(
                accessTokenValidatorMiddleware({
                    requestValidator: accessTokenValidator,
                }),
            )
            .use(getSessionByAuthCodeMiddleware({ sessionService: sessionService }))
            .use(
                initialiseClientConfigMiddleware({
                    configService: configService,
                    client_config_keys: [
                        ClientConfigKey.JWT_AUDIENCE,
                        ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
                        ClientConfigKey.JWT_REDIRECT_URI,
                        ClientConfigKey.JWT_SIGNING_ALGORITHM,
                    ],
                }),
            )
            .use(getSessionByIdMiddleware({ sessionService: sessionService }))
            .use(setGovUkSigningJourneyIdMiddleware(logger))
            .use(setRequestedVerificationScoreMiddleware(logger));
    });
    it("should return 200 Ok with valid access token", async () => {
        const request = {
            code: "dummyAuthCode",
            issuer: "ipv-core",
            audience: audience,
            redirect_uri: redirectUri,
            grant_type: "authorization_code",
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: clientAssertion,
        };
        const response = await handler(
            {
                body: request,
            } as unknown as APIGatewayProxyEvent,
            {} as Context,
        );
        expect(response).toEqual({
            body: expect.stringMatching(/{"access_token":".+","token_type":"Bearer","expires_in":10}/),
            statusCode: 200,
        });
    });
    it("should return 403 access denied with invalid access token", async () => {
        const request = {
            code: "dummyInvalidAuthCode",
            issuer: "ipv-core",
            audience: audience,
            redirect_uri: redirectUri,
            grant_type: "authorization_code",
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion:
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlFeHBlcmlhbktidkNvbXBvbmVudElkIiwiZXhwIjo0MDcwOTA5NzAwLCJqdGkiOiJTY25GNGRHWHRoWllYU181azg1T2JFb1NVMDRXLUgzcWFfcDZucHYyWlVZIn0.aJOEpvnBRpaptv_2T7L5aCzhTdvlNaGNh3uwuK1f5cC9he9izuIr60s2_Y6-DIPEWLE0_L6ckgdIsy9G7yj8jA",
        };
        const response = await handler(
            {
                body: request,
            } as unknown as APIGatewayProxyEvent,
            {} as Context,
        );
        expect(response).toEqual({
            body: '{"message":"Access token expired","code":1026,"errorSummary":"1026: Access token expired"}',
            statusCode: 403,
        });
    });
});
