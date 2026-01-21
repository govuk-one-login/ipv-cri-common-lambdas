import middy from "@middy/core";

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { APIGatewayProxyEvent, APIGatewayProxyEventHeaders, Context } from "aws-lambda";
import { ClientConfigKey, CommonConfigKey, ConfigKey } from "../../../src/types/config-keys";
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

jest.mock("@aws-sdk/lib-dynamodb");
jest.mock("@aws-sdk/client-ssm");
jest.mock("@aws-sdk/client-sqs");
jest.mock("@aws-sdk/client-kms");
jest.mock("@aws-lambda-powertools/metrics");
jest.mock("@aws-lambda-powertools/logger");
jest.mock("../../../src/common/config/config-service");
jest.mock("../../../src/services/session-request-validator");
jest.mock("@govuk-one-login/cri-audit");

const SESSION_CREATED_METRIC = "session_created";

describe("SessionLambda", () => {
    let sessionLambda: SessionLambda;
    let lambdaHandler: middy.MiddyfiedHandler;
    let errorSpy: jest.SpyInstance<unknown, never, unknown>;
    let logger: jest.MockedObjectDeep<typeof Logger>;
    let metrics: jest.MockedObjectDeep<typeof Metrics>;
    let personIdentityService: jest.MockedObjectDeep<typeof PersonIdentityService>;
    let jweDecrypter: jest.MockedObjectDeep<typeof JweDecrypter>;
    let configService: jest.MockedObjectDeep<typeof ConfigService>;
    let sessionService: jest.MockedObjectDeep<typeof SessionService>;
    let sessionRequestValidator: jest.MockedObjectDeep<typeof SessionRequestValidator>;
    let sessionRequestValidatorFactory: jest.MockedObjectDeep<typeof SessionRequestValidatorFactory>;

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
        jest.clearAllMocks();
        mockMap.set("test-client-id", "test-config-value");

        logger = jest.mocked(Logger);
        metrics = jest.mocked(Metrics);
        personIdentityService = jest.mocked(PersonIdentityService);
        jweDecrypter = jest.mocked(JweDecrypter);
        configService = jest.mocked(ConfigService);
        sessionService = jest.mocked(SessionService);
        sessionRequestValidator = jest.mocked(SessionRequestValidator);
        sessionRequestValidatorFactory = jest.mocked(SessionRequestValidatorFactory);

        errorSpy = jest.spyOn(logger.prototype, "error").mockImplementation();
        jest.spyOn(logger.prototype, "info").mockImplementation();

        sessionLambda = new SessionLambda(sessionService.prototype, personIdentityService.prototype, mockAuditConfig);

        lambdaHandler = middy(sessionLambda.handler.bind(sessionLambda))
            .use(
                errorMiddleware(logger.prototype, metrics.prototype, {
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

        jest.spyOn(jweDecrypter.prototype, "decryptJwe").mockResolvedValue(Buffer.from("test-data"));
        jest.spyOn(personIdentityService.prototype, "savePersonIdentity").mockImplementation();
        jest.spyOn(configService.prototype, "init").mockImplementation(() => new Promise<void>((res) => res()));
        jest.spyOn(configService.prototype, "getClientConfig").mockReturnValue(mockMap);
        jest.spyOn(configService.prototype, "getAuditConfig").mockReturnValue(mockAuditConfig);
        jest.spyOn(sessionService.prototype, "saveSession").mockReturnValue(
            new Promise<SessionItem>((res) => res(mockSessionItem)),
        );
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
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
        jest.spyOn(sessionRequestValidatorFactory.prototype, "create").mockReturnValue(
            sessionRequestValidator.prototype,
        );
    });

    it("should decrypt the JWE", async () => {
        await lambdaHandler(mockEvent, {} as Context);

        expect(jweDecrypter.prototype.decryptJwe).toHaveBeenCalledWith("jwe-request");
    });

    it("should error on JWE decryption fail", async () => {
        const metricSpy = jest.spyOn(metrics.prototype, "addMetric");
        jest.spyOn(jweDecrypter.prototype, "decryptJwe").mockRejectedValueOnce(
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
        expect(metricSpy).toHaveBeenCalledWith("jwt_verification_failed", MetricUnit.Count, 1);
    });

    it("should initialise the client config if unavailable", async () => {
        jest.spyOn(configService.prototype, "hasClientConfig").mockReturnValue(false);

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
        const metricSpy = jest.spyOn(metrics.prototype, "addMetric");
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockRejectedValueOnce(
            new SessionValidationError(
                "Session Validation Exception",
                "Invalid request: JWT validation/verification failed: failure",
            ),
        );

        const result = await lambdaHandler(mockEvent, {} as Context);
        expect(result.statusCode).toBe(400);
        expect(result.body).toContain("1019: Session Validation Exception");
        expect(metricSpy).toHaveBeenCalledWith("jwt_verification_failed", MetricUnit.Count, 1);
        expect(metricSpy).not.toHaveBeenCalledWith("jwt_expired", MetricUnit.Count, 1);
    });

    it("should error on JWT validation fail and send expired metirc", async () => {
        const metricSpy = jest.spyOn(metrics.prototype, "addMetric");
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockRejectedValueOnce(
            new SessionValidationError(
                "Session Validation Exception",
                "Invalid request: JWT validation/verification failed: ERR_JWT_EXPIRED",
            ),
        );

        const result = await lambdaHandler(mockEvent, {} as Context);
        expect(result.statusCode).toBe(400);
        expect(result.body).toContain("1019: Session Validation Exception");
        expect(metricSpy).toHaveBeenCalledWith("jwt_expired", MetricUnit.Count, 1);
        expect(metricSpy).not.toHaveBeenCalledWith("jwt_verification_failed", MetricUnit.Count, 1);
    });

    it("should save the session details", async () => {
        const spy = jest.spyOn(sessionService.prototype, "saveSession");
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
        const spy = jest.spyOn(personIdentityService.prototype, "savePersonIdentity");
        await lambdaHandler(mockEvent, {} as Context);

        expect(spy).toHaveBeenCalledWith(mockPerson, "test-session-id");
    });

    it("should not save the personal identity information is no shared claims are available", async () => {
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
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

        const spy = jest.spyOn(personIdentityService.prototype, "savePersonIdentity");
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

    it("should send the audit event", async () => {
        await lambdaHandler(mockEvent, {} as Context);
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
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
                    personIdentity: {
                        device_information: {
                            encoded: "encodedHeader",
                        },
                    },
                },
            },
        );
    });

    it("should successfully register the metrics", async () => {
        const dimensionSpy = jest.spyOn(metrics.prototype, "addDimension");
        const metricSpy = jest.spyOn(metrics.prototype, "addMetric");
        await lambdaHandler(mockEvent, {} as Context);
        expect(dimensionSpy).toHaveBeenCalledWith("issuer", "test-client-id");
        expect(metricSpy).toHaveBeenCalledWith("session_created", MetricUnit.Count, 1);
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
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockRejectedValue(new GenericServerError());

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
                    errorMiddleware(logger.prototype, metrics.prototype, {
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
                        client_absolute_paths: [
                            { prefix: previousCriIdentifier, suffix: ConfigKey.CRI_EVIDENCE_PROPERTIES },
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
            jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
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
            const saveSpy = jest.spyOn(personIdentityService.prototype, "savePersonIdentity");

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
            jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
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
            const spySaveSession = jest.spyOn(sessionService.prototype, "saveSession");

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
                    errorMiddleware(logger.prototype, metrics.prototype, {
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
                        client_absolute_paths: [
                            { prefix: previousCriIdentifier, suffix: ConfigKey.CRI_EVIDENCE_PROPERTIES },
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
            jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
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
            const saveSpy = jest.spyOn(personIdentityService.prototype, "savePersonIdentity");

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
        const metricSpy = jest.spyOn(metrics.prototype, "addMetric");
        const spy = jest.spyOn(sessionService.prototype, "saveSession");
        spy.mockRejectedValue(new Error("Error"));

        const result = await lambdaHandler(mockEvent, {} as Context);

        expect(result.statusCode).toBe(500);
        expect(result.body).toBe('{"message":"Server Error"}');

        expect(metricSpy).toHaveBeenCalledWith("session_created", MetricUnit.Count, 0);
    });
});
