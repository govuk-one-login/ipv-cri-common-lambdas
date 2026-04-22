import middy from "@middy/core";
import { beforeEach, describe, expect, it, vi, type MockInstance, type MockedObject } from "vitest";

import { Logger } from "@aws-lambda-powertools/logger";
import { APIGatewayProxyEvent, APIGatewayProxyEventHeaders, Context } from "aws-lambda";
import { ClientConfigKey, CommonConfigKey } from "../../../src/types/config-keys";
import { ConfigService } from "../../../src/common/config/config-service";
import { PersonIdentity } from "../../../src/types/person-identity";
import { SessionLambda } from "../../../src/handlers/session-handler";
import { PersonIdentityService } from "../../../src/services/person-identity-service";
import { JweDecrypter } from "../../../src/services/security/jwe-decrypter";
import {
    SessionRequestValidator,
    SessionRequestValidatorFactory,
} from "../../../src/services/session-request-validator";
import { SessionService } from "../../../src/services/session-service";
import { GenericServerError, SessionValidationError } from "../../../src/common/utils/errors";
import { JWTPayload } from "jose";
import initialiseConfigMiddleware from "../../../src/middlewares/config/initialise-config-middleware";
import errorMiddleware from "../../../src/middlewares/error/error-middleware";
import decryptJweMiddleware from "../../../src/middlewares/jwt/decrypt-jwe-middleware";
import validateJwtMiddleware from "../../../src/middlewares/jwt/validate-jwt-middleware";
import setGovUkSigningJourneyIdMiddleware from "../../../src/middlewares/session/set-gov-uk-signing-journey-id-middleware";
import initialiseClientConfigMiddleware from "../../../src/middlewares/config/initialise-client-config-middleware";
import setRequestedVerificationScoreMiddleware from "../../../src/middlewares/session/set-requested-verification-score-middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { buildAndSendAuditEvent } from "@govuk-one-login/cri-audit";
import { CriAuditConfig } from "../../../src/types/cri-audit-config";
import { SessionItem, UnixMillisecondsTimestamp, UnixSecondsTimestamp } from "@govuk-one-login/cri-types";
import { captureMetric, metrics } from "@govuk-one-login/cri-metrics";

vi.mock("@aws-sdk/lib-dynamodb");
vi.mock("@aws-sdk/client-ssm");
vi.mock("@aws-sdk/client-sqs");
vi.mock("@aws-sdk/client-kms");
vi.mock("@govuk-one-login/cri-metrics", () => ({
    metrics: {
        addDimension: vi.fn(),
        publishStoredMetrics: vi.fn(),
        logMetrics: vi.fn(),
    },
    captureMetric: vi.fn(),
}));
vi.mock("@govuk-one-login/cri-logger", () => ({
    logger: {
        info: vi.fn(),
        error: vi.fn(),
        clearBuffer: vi.fn(),
        resetKeys: vi.fn(),
        refreshSampleRateCalculation: vi.fn(),
        addContext: vi.fn(),
        logEventIfEnabled: vi.fn(),
        appendKeys: vi.fn(),
    },
}));
vi.mock("@aws-lambda-powertools/logger");
vi.mock("../../../src/common/config/config-service");
vi.mock("../../../src/services/session-request-validator");
vi.mock("@govuk-one-login/cri-audit");

const SESSION_CREATED_METRIC = "session_created";

describe("SessionLambda", () => {
    let sessionLambda: SessionLambda;
    let lambdaHandler: middy.MiddyfiedHandler;
    let errorSpy: MockInstance;
    let logger: MockedObject<typeof Logger>;
    let personIdentityService: MockedObject<typeof PersonIdentityService>;
    let jweDecrypter: MockedObject<typeof JweDecrypter>;
    let configService: MockedObject<typeof ConfigService>;
    let sessionService: MockedObject<typeof SessionService>;
    let sessionRequestValidator: MockedObject<typeof SessionRequestValidator>;
    let sessionRequestValidatorFactory: MockedObject<typeof SessionRequestValidatorFactory>;
    const metricsSpy = vi.mocked(captureMetric);

    const mockAuditConfig: CriAuditConfig = {
        queueUrl: "cool-queuez.com",
        issuer: "https://check-hmrc-time.account.gov.uk",
        auditEventNamePrefix: "IPV_CRI",
    };
    const START_AUDIT_EVENT = `${mockAuditConfig.auditEventNamePrefix}_START`;

    const mockSessionItem = {
        sessionId: "test-session-id",
        subject: "test-sub",
        persistentSessionId: "test-persistent-session-id",
        clientSessionId: "test-journey-id",
        clientIpAddress: "test-client-ip-address",
        clientId: "test-client-id",
        attemptCount: 0,
        createdDate: 1 as UnixMillisecondsTimestamp,
        expiryDate: 2 as UnixSecondsTimestamp,
        redirectUri: "test-redirect-uri",
        state: "test-state",
    };

    const mockPerson: PersonIdentity = {
        name: [
            {
                nameParts: [
                    {
                        type: "firstName",
                        value: "Jane",
                    },
                    {
                        type: "lastName",
                        value: "Doe",
                    },
                ],
            },
        ],
        birthDate: [
            {
                value: "2023-01-01",
            },
        ],
        address: [
            {
                uprn: 0,
                organisationName: "N/A",
                departmentName: "N/A",
                subBuildingName: "N/A",
                buildingNumber: "1",
                buildingName: "N/A",
                dependentStreetName: "N/A",
                streetName: "Test Street",
                doubleDependentAddressLocality: "N/A",
                dependentAddressLocality: "N/A",
                addressLocality: "N/A",
                postalCode: "AA1 1AA",
                addressCountry: "UK",
                validFrom: "2022-01",
                validUntil: "2023-01",
            },
        ],
    };

    const mockPersonWithSocialSecurityRecord: PersonIdentity = { ...mockPerson };
    mockPersonWithSocialSecurityRecord.socialSecurityRecord = [
        {
            personalNumber: "AA000003D",
        },
    ];

    const mockMap = new Map<string, string>();

    const mockEvent = {
        body: JSON.stringify({
            client_id: "test-client-id",
            request: "jwe-request",
        }),
        headers: {
            ["x-forwarded-for"]: "test-client-ip-address",
        } as APIGatewayProxyEventHeaders,
    } as APIGatewayProxyEvent;

    beforeEach(() => {
        vi.clearAllMocks();
        mockMap.set("test-client-id", "test-config-value");

        logger = vi.mocked(Logger);
        personIdentityService = vi.mocked(PersonIdentityService);
        jweDecrypter = vi.mocked(JweDecrypter);
        configService = vi.mocked(ConfigService);
        sessionService = vi.mocked(SessionService);
        sessionRequestValidator = vi.mocked(SessionRequestValidator);
        sessionRequestValidatorFactory = vi.mocked(SessionRequestValidatorFactory);

        errorSpy = vi.spyOn(logger.prototype, "error");
        vi.spyOn(logger.prototype, "info");

        sessionLambda = new SessionLambda(sessionService.prototype, personIdentityService.prototype);

        lambdaHandler = middy(sessionLambda.handler.bind(sessionLambda))
            .use(
                errorMiddleware(logger.prototype, {
                    metric_name: SESSION_CREATED_METRIC,
                    message: "Session Lambda error occurred",
                }),
            )
            .use(injectLambdaContext(logger.prototype, { clearState: true }))
            .use(
                initialiseConfigMiddleware({
                    configService: configService.prototype,
                    config_keys: [
                        CommonConfigKey.SESSION_TABLE_NAME,
                        CommonConfigKey.SESSION_TTL,
                        CommonConfigKey.PERSON_IDENTITY_TABLE_NAME,
                        CommonConfigKey.DECRYPTION_KEY_ID,
                        CommonConfigKey.VC_ISSUER,
                    ],
                }),
            )
            .use(decryptJweMiddleware(logger.prototype, { jweDecrypter: jweDecrypter.prototype }))
            .use(
                initialiseClientConfigMiddleware({
                    configService: configService.prototype,
                    client_config_keys: [
                        ClientConfigKey.JWT_AUDIENCE,
                        ClientConfigKey.JWT_ISSUER,
                        ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
                        ClientConfigKey.JWT_REDIRECT_URI,
                        ClientConfigKey.JWT_SIGNING_ALGORITHM,
                        ClientConfigKey.JWKS_ENDPOINT,
                    ],
                }),
            )
            .use(
                validateJwtMiddleware(logger.prototype, {
                    configService: configService.prototype,
                    jwtValidatorFactory: sessionRequestValidatorFactory.prototype,
                }),
            )
            .use(setGovUkSigningJourneyIdMiddleware(logger.prototype))
            .use(setRequestedVerificationScoreMiddleware(logger.prototype));

        vi.spyOn(jweDecrypter.prototype, "decryptJwe").mockResolvedValue(Buffer.from("test-data"));
        vi.spyOn(personIdentityService.prototype, "savePersonIdentity").mockResolvedValue("");
        vi.spyOn(configService.prototype, "init").mockImplementation(() => new Promise<void>((res) => res()));
        vi.spyOn(configService.prototype, "getClientConfig").mockReturnValue(mockMap);
        vi.spyOn(configService.prototype, "getAuditConfig").mockReturnValue(mockAuditConfig);
        vi.spyOn(sessionService.prototype, "saveSession").mockReturnValue(
            new Promise<SessionItem>((res) => res(mockSessionItem)),
        );
        vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
            new Promise<JWTPayload>((res) =>
                res({
                    client_id: "test-client-id",
                    govuk_signin_journey_id: "test-journey-id",
                    persistent_session_id: "test-persistent-session-id",
                    redirect_uri: "test-redirect-uri",
                    state: "test-state",
                    sub: "test-sub",
                    shared_claims: mockPerson,
                } as JWTPayload),
            ),
        );
        vi.spyOn(sessionRequestValidatorFactory.prototype, "create").mockReturnValue(sessionRequestValidator.prototype);
    });

    it("should decrypt the JWE", async () => {
        await lambdaHandler(mockEvent, {} as Context);

        expect(jweDecrypter.prototype.decryptJwe).toHaveBeenCalledWith("jwe-request");
    });

    it("should error on JWE decryption fail", async () => {
        vi.spyOn(jweDecrypter.prototype, "decryptJwe").mockRejectedValueOnce(
            new SessionValidationError(
                "Session Validation Exception",
                "Invalid request: JWT validation/verification failed: failure",
            ),
        );
        const result = await lambdaHandler(mockEvent, {} as Context);

        expect(result.statusCode).toBe(400);
        expect(result.body).toContain("1019: Session Validation Exception");

        expect(errorSpy).toHaveBeenCalledWith(
            "Session Lambda error occurred: 1019: Session Validation Exception - Invalid request: JWT validation/verification failed: failure",
            expect.any(SessionValidationError),
        );
        expect(metricsSpy).toHaveBeenCalledWith("jwt_verification_failed");
    });

    it("should initialise the client config if unavailable", async () => {
        vi.spyOn(configService.prototype, "hasClientConfig").mockReturnValue(false);

        await lambdaHandler(mockEvent, {} as Context);

        expect(configService.prototype.initClientConfig).toHaveBeenCalledWith("test-client-id", [
            ClientConfigKey.JWT_AUDIENCE,
            ClientConfigKey.JWT_ISSUER,
            ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
            ClientConfigKey.JWT_REDIRECT_URI,
            ClientConfigKey.JWT_SIGNING_ALGORITHM,
            ClientConfigKey.JWKS_ENDPOINT,
        ]);
    });

    it("should get the client config", async () => {
        await lambdaHandler(mockEvent, {} as Context);

        expect(configService.prototype.getClientConfig).toHaveBeenCalledWith("test-client-id");
    });

    it("should validate the JWT", async () => {
        await lambdaHandler(mockEvent, {} as Context);

        expect(sessionRequestValidatorFactory.prototype.create).toHaveBeenCalledWith(mockMap);
        expect(sessionRequestValidator.prototype.validateJwt).toHaveBeenCalledWith(
            Buffer.from("test-data"),
            "test-client-id",
        );
    });

    it("should error on JWT validation fail", async () => {
        vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockRejectedValueOnce(
            new SessionValidationError(
                "Session Validation Exception",
                "Invalid request: JWT validation/verification failed: failure",
            ),
        );

        const result = await lambdaHandler(mockEvent, {} as Context);
        expect(result.statusCode).toBe(400);
        expect(result.body).toContain("1019: Session Validation Exception");
        expect(metricsSpy).toHaveBeenCalledWith("jwt_verification_failed");
        expect(metricsSpy).not.toHaveBeenCalledWith("jwt_expired");
    });

    it("should error on JWT validation fail and send expired metirc", async () => {
        vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockRejectedValueOnce(
            new SessionValidationError(
                "Session Validation Exception",
                "Invalid request: JWT validation/verification failed: ERR_JWT_EXPIRED",
            ),
        );

        const result = await lambdaHandler(mockEvent, {} as Context);
        expect(result.statusCode).toBe(400);
        expect(result.body).toContain("1019: Session Validation Exception");
        expect(metricsSpy).toHaveBeenCalledWith("jwt_expired");
        expect(metricsSpy).not.toHaveBeenCalledWith("jwt_verification_failed");
    });

    it("should save the session details", async () => {
        const spy = vi.spyOn(sessionService.prototype, "saveSession");
        await lambdaHandler(mockEvent, {} as Context);

        const expectedSessionRequestSummary = {
            clientId: "test-client-id",
            clientIpAddress: "test-client-ip-address",
            clientSessionId: "test-journey-id",
            persistentSessionId: "test-persistent-session-id",
            redirectUri: "test-redirect-uri",
            state: "test-state",
            subject: "test-sub",
        };
        expect(spy).toHaveBeenCalledWith(expectedSessionRequestSummary);
    });

    it("should save the personal identity information", async () => {
        const spy = vi.spyOn(personIdentityService.prototype, "savePersonIdentity");
        await lambdaHandler(mockEvent, {} as Context);

        expect(spy).toHaveBeenCalledWith(mockPerson, "test-session-id");
    });

    it("should not save the personal identity information is no shared claims are available", async () => {
        vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
            new Promise<JWTPayload>((res) =>
                res({
                    client_id: "test-client-id",
                    govuk_signin_journey_id: "test-journey-id",
                    persistent_session_id: "test-persistent-session-id",
                    redirect_uri: "test-redirect-uri",
                    state: "test-state",
                    sub: "test-sub",
                } as JWTPayload),
            ),
        );

        const spy = vi.spyOn(personIdentityService.prototype, "savePersonIdentity");
        await lambdaHandler(mockEvent, {} as Context);

        expect(spy).not.toHaveBeenCalled();
    });

    it("should send the audit event", async () => {
        await lambdaHandler(mockEvent, {} as Context);

        expect(buildAndSendAuditEvent).toHaveBeenCalledWith(
            mockAuditConfig.queueUrl,
            START_AUDIT_EVENT,
            mockAuditConfig.issuer,
            mockSessionItem,
            {},
        );
    });

    it("should send the audit event with context evidence", async () => {
        const mockSessionItemWithContext = { ...mockSessionItem, context: "test-context" };
        vi.spyOn(sessionService.prototype, "saveSession").mockResolvedValue(mockSessionItemWithContext);

        await lambdaHandler(mockEvent, {} as Context);

        expect(buildAndSendAuditEvent).toHaveBeenCalledWith(
            mockAuditConfig.queueUrl,
            START_AUDIT_EVENT,
            mockAuditConfig.issuer,
            mockSessionItemWithContext,
            {
                extensions: {
                    evidence: [{ context: "test-context" }],
                },
            },
        );
    });

    it("should send the audit event", async () => {
        await lambdaHandler(mockEvent, {} as Context);
        vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
            new Promise<JWTPayload>((res) =>
                res({
                    client_id: "test-client-id",
                    govuk_signin_journey_id: "test-journey-id",
                    persistent_session_id: "test-persistent-session-id",
                    redirect_uri: "test-redirect-uri",
                    state: "test-state",
                    sub: "test-sub",
                    shared_claims: mockPerson,
                    evidence_requested: {
                        scoringPolicy: "gpg45",
                        strengthScore: 1,
                    },
                } as JWTPayload),
            ),
        );
        expect(buildAndSendAuditEvent).toHaveBeenCalledWith(
            mockAuditConfig.queueUrl,
            START_AUDIT_EVENT,
            mockAuditConfig.issuer,
            mockSessionItem,
            {},
        );
    });

    it("should send the audit event with device_information if it exists", async () => {
        await lambdaHandler(
            { ...mockEvent, headers: { ...mockEvent.headers, "txma-audit-encoded": "encodedHeader" } },
            {} as Context,
        );

        expect(buildAndSendAuditEvent).toHaveBeenCalledWith(
            mockAuditConfig.queueUrl,
            START_AUDIT_EVENT,
            mockAuditConfig.issuer,
            mockSessionItem,
            {
                restricted: {
                    device_information: {
                        encoded: "encodedHeader",
                    },
                },
            },
        );
    });

    it("should successfully register the metrics", async () => {
        const dimensionSpy = vi.mocked(metrics.addDimension);
        await lambdaHandler(mockEvent, {} as Context);
        expect(dimensionSpy).toHaveBeenCalledWith("issuer", "test-client-id");
        expect(metricsSpy).toHaveBeenCalledWith("session_created");
    });

    it("should successfully start the session", async () => {
        const result = await lambdaHandler(mockEvent, {} as Context);
        expect(JSON.parse(result.body)).toEqual({
            session_id: "test-session-id",
            state: "test-state",
            redirect_uri: "test-redirect-uri",
        });
        expect(result.statusCode).toBe(201);
    });

    it("should catch and return any errors", async () => {
        vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockRejectedValue(new GenericServerError());

        const result = await lambdaHandler(mockEvent, {} as Context);
        expect(errorSpy).toHaveBeenCalledWith(
            "Session Lambda error occurred: 1025: Request failed due to a server error",
            new GenericServerError(),
        );
        expect(result.statusCode).toBe(500);
        expect(result.body).toContain("1025: Request failed due to a server error");
    });

    describe("SessionLambda has evidenceRequested", () => {
        const previousCriIdentifier = process.env.CRI_IDENTIFIER as string;
        beforeEach(() => {
            process.env.CRI_IDENTIFIER = "di-ipv-cri-check-hmrc-api";

            lambdaHandler = middy(sessionLambda.handler.bind(sessionLambda))
                .use(
                    errorMiddleware(logger.prototype, {
                        metric_name: SESSION_CREATED_METRIC,
                        message: "Session Lambda error occurred",
                    }),
                )
                .use(injectLambdaContext(logger.prototype, { clearState: true }))
                .use(
                    initialiseConfigMiddleware({
                        configService: configService.prototype,
                        config_keys: [
                            CommonConfigKey.SESSION_TABLE_NAME,
                            CommonConfigKey.SESSION_TTL,
                            CommonConfigKey.PERSON_IDENTITY_TABLE_NAME,
                            CommonConfigKey.DECRYPTION_KEY_ID,
                            CommonConfigKey.VC_ISSUER,
                        ],
                    }),
                )
                .use(decryptJweMiddleware(logger.prototype, { jweDecrypter: jweDecrypter.prototype }))
                .use(
                    initialiseClientConfigMiddleware({
                        configService: configService.prototype,
                        client_config_keys: [
                            ClientConfigKey.JWT_AUDIENCE,
                            ClientConfigKey.JWT_ISSUER,
                            ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
                            ClientConfigKey.JWT_REDIRECT_URI,
                            ClientConfigKey.JWT_SIGNING_ALGORITHM,
                            ClientConfigKey.JWKS_ENDPOINT,
                        ],
                    }),
                )
                .use(
                    validateJwtMiddleware(logger.prototype, {
                        configService: configService.prototype,
                        jwtValidatorFactory: sessionRequestValidatorFactory.prototype,
                    }),
                )
                .use(setGovUkSigningJourneyIdMiddleware(logger.prototype))
                .use(setRequestedVerificationScoreMiddleware(logger.prototype));
            process.env.CRI_IDENTIFIER = previousCriIdentifier;
            vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
                new Promise<JWTPayload>((res) =>
                    res({
                        client_id: "test-client-id",
                        govuk_signin_journey_id: "test-journey-id",
                        persistent_session_id: "test-persistent-session-id",
                        redirect_uri: "test-redirect-uri",
                        state: "test-state",
                        sub: "test-sub",
                        shared_claims: mockPersonWithSocialSecurityRecord,
                        evidence_requested: {
                            scoringPolicy: "gpg45",
                            strengthScore: 2,
                            verificationScore: 2,
                        },
                    } as JWTPayload),
                ),
            );
        });

        it("should save to the session with socialSecurityRecord included", async () => {
            const saveSpy = vi.spyOn(personIdentityService.prototype, "savePersonIdentity");

            process.env.CRI_IDENTIFIER = "ipv-cri-kbv-hmrc-api";

            await lambdaHandler(mockEvent, {} as Context);

            expect(saveSpy).toHaveBeenCalledWith(
                {
                    address: [
                        {
                            addressCountry: "UK",
                            addressLocality: "N/A",
                            buildingName: "N/A",
                            buildingNumber: "1",
                            departmentName: "N/A",
                            dependentAddressLocality: "N/A",
                            dependentStreetName: "N/A",
                            doubleDependentAddressLocality: "N/A",
                            organisationName: "N/A",
                            postalCode: "AA1 1AA",
                            streetName: "Test Street",
                            subBuildingName: "N/A",
                            uprn: 0,
                            validFrom: "2022-01",
                            validUntil: "2023-01",
                        },
                    ],
                    birthDate: [
                        {
                            value: "2023-01-01",
                        },
                    ],
                    name: [
                        {
                            nameParts: [
                                {
                                    type: "firstName",
                                    value: "Jane",
                                },
                                {
                                    type: "lastName",
                                    value: "Doe",
                                },
                            ],
                        },
                    ],
                    socialSecurityRecord: [
                        {
                            personalNumber: "AA000003D",
                        },
                    ],
                },
                "test-session-id",
            );
        });

        it("should save the session details without the context field", async () => {
            vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
                new Promise<JWTPayload>((res) =>
                    res({
                        client_id: "test-client-id",
                        govuk_signin_journey_id: "test-journey-id",
                        persistent_session_id: "test-persistent-session-id",
                        redirect_uri: "test-redirect-uri",
                        state: "test-state",
                        sub: "test-sub",
                        shared_claims: mockPersonWithSocialSecurityRecord,
                        evidence_requested: {
                            scoringPolicy: "gpg45",
                            strengthScore: 2,
                            verificationScore: 2,
                        },
                    } as JWTPayload),
                ),
            );
            const spySaveSession = vi.spyOn(sessionService.prototype, "saveSession");

            await lambdaHandler(mockEvent, {} as Context);

            const expectedSessionRequestSummary = {
                clientId: "test-client-id",
                clientIpAddress: "test-client-ip-address",
                clientSessionId: "test-journey-id",
                persistentSessionId: "test-persistent-session-id",
                redirectUri: "test-redirect-uri",
                state: "test-state",
                subject: "test-sub",
                evidenceRequested: {
                    scoringPolicy: "gpg45",
                    strengthScore: 2,
                    verificationScore: 2,
                },
            };
            expect(spySaveSession).toHaveBeenCalledWith(expectedSessionRequestSummary);

            expect(buildAndSendAuditEvent).toHaveBeenCalledWith(
                mockAuditConfig.queueUrl,
                START_AUDIT_EVENT,
                mockAuditConfig.issuer,
                mockSessionItem,
                {},
            );
        });
    });

    describe("SessionLambda has evidenceRequested with missing socialSecurityRecord", () => {
        const previousCriIdentifier = process.env.CRI_IDENTIFIER as string;
        beforeEach(() => {
            process.env.CRI_IDENTIFIER = "di-ipv-cri-check-hmrc-api";

            lambdaHandler = middy(sessionLambda.handler.bind(sessionLambda))
                .use(
                    errorMiddleware(logger.prototype, {
                        metric_name: SESSION_CREATED_METRIC,
                        message: "Session Lambda error occurred",
                    }),
                )
                .use(injectLambdaContext(logger.prototype, { clearState: true }))
                .use(
                    initialiseConfigMiddleware({
                        configService: configService.prototype,
                        config_keys: [
                            CommonConfigKey.SESSION_TABLE_NAME,
                            CommonConfigKey.SESSION_TTL,
                            CommonConfigKey.PERSON_IDENTITY_TABLE_NAME,
                            CommonConfigKey.DECRYPTION_KEY_ID,
                            CommonConfigKey.VC_ISSUER,
                        ],
                    }),
                )
                .use(decryptJweMiddleware(logger.prototype, { jweDecrypter: jweDecrypter.prototype }))
                .use(
                    initialiseClientConfigMiddleware({
                        configService: configService.prototype,
                        client_config_keys: [
                            ClientConfigKey.JWT_AUDIENCE,
                            ClientConfigKey.JWT_ISSUER,
                            ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
                            ClientConfigKey.JWT_REDIRECT_URI,
                            ClientConfigKey.JWKS_ENDPOINT,
                            ClientConfigKey.JWT_SIGNING_ALGORITHM,
                        ],
                    }),
                )
                .use(
                    validateJwtMiddleware(logger.prototype, {
                        configService: configService.prototype,
                        jwtValidatorFactory: sessionRequestValidatorFactory.prototype,
                    }),
                )
                .use(setGovUkSigningJourneyIdMiddleware(logger.prototype))
                .use(setRequestedVerificationScoreMiddleware(logger.prototype));
            process.env.CRI_IDENTIFIER = previousCriIdentifier;
            vi.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
                new Promise<JWTPayload>((res) =>
                    res({
                        client_id: "test-client-id",
                        govuk_signin_journey_id: "test-journey-id",
                        persistent_session_id: "test-persistent-session-id",
                        redirect_uri: "test-redirect-uri",
                        state: "test-state",
                        sub: "test-sub",
                        shared_claims: mockPerson,
                        evidence_requested: {
                            scoringPolicy: "gpg45",
                            strengthScore: 2,
                        },
                    } as JWTPayload),
                ),
            );
        });
        it("should save to the session with no socialSecurityRecord included", async () => {
            const saveSpy = vi.spyOn(personIdentityService.prototype, "savePersonIdentity");

            process.env.CRI_IDENTIFIER = "ipv-cri-kbv-hmrc-api";

            await lambdaHandler(mockEvent, {} as Context);

            expect(saveSpy).toHaveBeenCalledWith(
                {
                    address: [
                        {
                            addressCountry: "UK",
                            addressLocality: "N/A",
                            buildingName: "N/A",
                            buildingNumber: "1",
                            departmentName: "N/A",
                            dependentAddressLocality: "N/A",
                            dependentStreetName: "N/A",
                            doubleDependentAddressLocality: "N/A",
                            organisationName: "N/A",
                            postalCode: "AA1 1AA",
                            streetName: "Test Street",
                            subBuildingName: "N/A",
                            uprn: 0,
                            validFrom: "2022-01",
                            validUntil: "2023-01",
                        },
                    ],
                    birthDate: [
                        {
                            value: "2023-01-01",
                        },
                    ],
                    name: [
                        {
                            nameParts: [
                                {
                                    type: "firstName",
                                    value: "Jane",
                                },
                                {
                                    type: "lastName",
                                    value: "Doe",
                                },
                            ],
                        },
                    ],
                },
                "test-session-id",
            );
        });
    });

    it("should return a 500 error from the handlers catch block", async () => {
        const spy = vi.spyOn(sessionService.prototype, "saveSession");
        spy.mockRejectedValue(new Error("Error"));

        const result = await lambdaHandler(mockEvent, {} as Context);

        expect(result.statusCode).toBe(500);
        expect(result.body).toBe('{"message":"Server Error"}');

        expect(metricsSpy).toHaveBeenCalledWith("session_created", 0);
    });
});
