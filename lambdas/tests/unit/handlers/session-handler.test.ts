import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { APIGatewayProxyEvent, APIGatewayProxyEventHeaders } from "aws-lambda";
import { ClientConfigKey } from "../../../src/types/config-keys";
import { ConfigService } from "../../../src/common/config/config-service";
import { AuditService } from "../../../src/common/services/audit-service";
import { AuditEventType } from "../../../src/types/audit-event";
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

jest.mock("@aws-sdk/lib-dynamodb");
jest.mock("@aws-sdk/client-ssm");
jest.mock("@aws-sdk/client-sqs");
jest.mock("@aws-sdk/client-kms");
jest.mock("@aws-lambda-powertools/metrics");
jest.mock("../../../src/common/config/config-service");
jest.mock("../../../src/services/session-request-validator");

describe("SessionLambda", () => {
    let sessionLambda: SessionLambda;

    const personIdentityService = jest.mocked(PersonIdentityService);
    const jweDecrypter = jest.mocked(JweDecrypter);
    const auditService = jest.mocked(AuditService);
    const logger = jest.mocked(Logger);
    const metrics = jest.mocked(Metrics);
    const configService = jest.mocked(ConfigService);
    const sessionService = jest.mocked(SessionService);
    const sessionRequestValidator = jest.mocked(SessionRequestValidator);
    const sessionRequestValidatorFactory = jest.mocked(SessionRequestValidatorFactory);

    const errorSpy = jest.spyOn(logger.prototype, "error").mockImplementation();
    jest.spyOn(logger.prototype, "info").mockImplementation();

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

    const mockMap = new Map<string, string>();
    mockMap.set("test-client-id", "test-config-value");

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

        sessionLambda = new SessionLambda(
            sessionService.prototype,
            personIdentityService.prototype,
            sessionRequestValidatorFactory.prototype,
            jweDecrypter.prototype,
            auditService.prototype,
        );

        jest.spyOn(jweDecrypter.prototype, "decryptJwe").mockResolvedValue(Buffer.from("test-data"));
        jest.spyOn(personIdentityService.prototype, "savePersonIdentity").mockImplementation();
        jest.spyOn(auditService.prototype, "sendAuditEvent").mockImplementation();
        jest.spyOn(configService.prototype, "init").mockImplementation(() => new Promise<void>((res) => res()));
        jest.spyOn(configService.prototype, "getClientConfig").mockReturnValue(mockMap);
        jest.spyOn(sessionService.prototype, "saveSession").mockReturnValue(
            new Promise<string>((res) => res("test-session-id")),
        );
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
            new Promise<JWTPayload>((res) =>
                res({
                    client_id: "test-jwt-client-id",
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
        await sessionLambda.handler(mockEvent, {});

        expect(jweDecrypter.prototype.decryptJwe).toHaveBeenCalledWith("jwe-request");
    });

    it("should error on JWE decryption fail", async () => {
        jest.spyOn(jweDecrypter.prototype, "decryptJwe").mockRejectedValueOnce(
            new SessionValidationError(
                "Session Validation Exception",
                "Invalid request: JWT validation/verification failed: failure",
            ),
        );
        const result = await sessionLambda.handler(mockEvent, {});

        expect(result.statusCode).toBe(400);
        expect(result.body).toContain("1019: Session Validation Exception");

        expect(errorSpy).toHaveBeenCalledWith(
            "Session Lambda error occurred: 1019: Session Validation Exception - Invalid request: JWT validation/verification failed: failure",
            expect.any(SessionValidationError),
        );
    });

    it("should initialise the client config if unavailable", async () => {
        jest.spyOn(configService.prototype, "hasClientConfig").mockReturnValue(false);

        await sessionLambda.handler(mockEvent, {});

        expect(configService.prototype.initClientConfig).toHaveBeenCalledWith("test-client-id", [
            ClientConfigKey.JWT_AUDIENCE,
            ClientConfigKey.JWT_ISSUER,
            ClientConfigKey.JWT_PUBLIC_SIGNING_KEY,
            ClientConfigKey.JWT_REDIRECT_URI,
            ClientConfigKey.JWT_SIGNING_ALGORITHM,
        ]);
    });

    it("should get the client config", async () => {
        await sessionLambda.handler(mockEvent, {});

        expect(configService.prototype.getClientConfig).toHaveBeenCalledWith("test-client-id");
    });

    it("should validate the JWT", async () => {
        await sessionLambda.handler(mockEvent, {});

        expect(sessionRequestValidatorFactory.prototype.create).toHaveBeenCalledWith(mockMap);
        expect(sessionRequestValidator.prototype.validateJwt).toHaveBeenCalledWith(
            Buffer.from("test-data"),
            "test-client-id",
        );
    });

    it("should error on JWT validation fail", async () => {
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockRejectedValueOnce(
            new SessionValidationError(
                "Session Validation Exception",
                "Invalid request: JWT validation/verification failed: failure",
            ),
        );

        const result = await sessionLambda.handler(mockEvent, {});
        expect(result.statusCode).toBe(400);
        expect(result.body).toContain("1019: Session Validation Exception");
    });

    it("should save the session details", async () => {
        const spy = jest.spyOn(sessionService.prototype, "saveSession");
        await sessionLambda.handler(mockEvent, {});

        const expectedSessionRequestSummary = {
            clientId: "test-jwt-client-id",
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
        await sessionLambda.handler(mockEvent, {});

        expect(spy).toHaveBeenCalledWith(mockPerson, "test-session-id");
    });

    it("should not save the personal identity information is no shared claims are available", async () => {
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockReturnValue(
            new Promise<JWTPayload>((res) =>
                res({
                    client_id: "test-jwt-client-id",
                    govuk_signin_journey_id: "test-journey-id",
                    persistent_session_id: "test-persistent-session-id",
                    redirect_uri: "test-redirect-uri",
                    state: "test-state",
                    sub: "test-sub",
                } as JWTPayload),
            ),
        );

        const spy = jest.spyOn(personIdentityService.prototype, "savePersonIdentity");
        await sessionLambda.handler(mockEvent, {});

        expect(spy).not.toHaveBeenCalled();
    });

    it("should send the audit event", async () => {
        const spy = jest.spyOn(auditService.prototype, "sendAuditEvent");
        await sessionLambda.handler(mockEvent, {});

        expect(spy).toHaveBeenCalledWith(AuditEventType.START, {
            clientIpAddress: "test-client-ip-address",
            sessionItem: {
                sessionId: "test-session-id",
                subject: "test-sub",
                persistentSessionId: "test-persistent-session-id",
                clientSessionId: "test-journey-id",
            },
        });
    });

    it("should successfully register the metrics", async () => {
        const dimensionSpy = jest.spyOn(metrics.prototype, "addDimension");
        const metricSpy = jest.spyOn(metrics.prototype, "addMetric");
        await sessionLambda.handler(mockEvent, {});
        expect(dimensionSpy).toHaveBeenCalledWith("issuer", "test-client-id");
        expect(metricSpy).toHaveBeenCalledWith("session_created", MetricUnits.Count, 1);
    });

    it("should successfully start the session", async () => {
        const result = await sessionLambda.handler(mockEvent, {});
        expect(JSON.parse(result.body)).toEqual({
            session_id: "test-session-id",
            state: "test-state",
            redirect_uri: "test-redirect-uri",
        });
        expect(result.statusCode).toBe(201);
    });

    it("should catch and return any errors", async () => {
        jest.spyOn(sessionRequestValidator.prototype, "validateJwt").mockRejectedValue(new GenericServerError());

        const result = await sessionLambda.handler(mockEvent, {});
        expect(errorSpy).toHaveBeenCalledWith(
            "Session Lambda error occurred: 1025: Request failed due to a server error",
            new GenericServerError(),
        );
        expect(result.statusCode).toBe(500);
        expect(result.body).toContain("1025: Request failed due to a server error");
    });
});
