import { Logger } from "@aws-lambda-powertools/logger";
import { JWTPayload } from "jose";
import { JwtVerifier } from "../../../src/common/security/jwt-verifier";
import {
    SessionRequestValidator,
    SessionRequestValidatorFactory,
} from "../../../src/services/session-request-validator";
import { ClientConfigKey } from "../../../src/types/config-keys";
import { PersonIdentity } from "../../../src/types/person-identity";
import { SessionRequestValidationConfig } from "../../../src/types/session-request-validation-config";

describe("session-request-validator.ts", () => {
    const logger = new Logger();
    const mockMap = new Map<string, string>();
    mockMap.set("session-id", "test-session-id");
    const personIdentity = jest.mocked({} as PersonIdentity);
    const jwtVerifier = jest.mocked(JwtVerifier);

    describe("SessionRequestValidator", () => {
        let sessionRequestValidatorFactory: SessionRequestValidatorFactory;
        let sessionRequestValidator: SessionRequestValidator;

        beforeEach(() => {
            sessionRequestValidatorFactory = new SessionRequestValidatorFactory(logger);
            sessionRequestValidator = sessionRequestValidatorFactory.create(mockMap);
        });

        it("should return an error on JWT verification failure", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(Promise.resolve(null));

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id"),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details: "Invalid request: JWT validation/verification failed: JWT verification failure",
                }),
            );
        });

        it("should return anerror on mismatched client ID", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: "payload-client-id",
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id"),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details:
                        "Invalid request: JWT validation/verification failed: Mismatched client_id in request body (request-client-id) & jwt (payload-client-id)",
                }),
            );
        });

        it("should return an error on failure to retrieve redirect URI", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: "request-client-id",
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id"),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details:
                        "Invalid request: JWT validation/verification failed: Unable to retrieve redirect URI for client_id: request-client-id",
                }),
            );
        });

        it("should return an error on mismatched redirect URI", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: "request-client-id",
                    redirect_uri: "wrong-redirect-uri",
                    shared_claims: personIdentity,
                } as JWTPayload),
            );
            mockMap.set(ClientConfigKey.JWT_REDIRECT_URI, "redirect-uri");
            sessionRequestValidator = sessionRequestValidatorFactory.create(mockMap);

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id"),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details:
                        "Invalid request: JWT validation/verification failed: Redirect uri wrong-redirect-uri does not match configuration uri redirect-uri",
                }),
            );
        });

        it("should successfully validate the jwt", async () => {
            const scope = "openid";
            const state = "state";
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: "request-client-id",
                    redirect_uri: "redirect-uri",
                    scope: scope,
                    state: state,
                    shared_claims: personIdentity,
                } as JWTPayload),
            );
            mockMap.set(ClientConfigKey.JWT_REDIRECT_URI, "redirect-uri");
            sessionRequestValidator = sessionRequestValidatorFactory.create(mockMap);

            const response = await sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id");
            expect(response).toEqual({
                client_id: "request-client-id",
                redirect_uri: "redirect-uri",
                scope: scope,
                state: state,
                shared_claims: personIdentity,
            });
        });
    });

    describe("sessionRequestValidator", () => {
        let sessionRequestValidator: SessionRequestValidator;
        let sessionRequestValidationConfig: SessionRequestValidationConfig;
        const jwtVerifier = jest.mocked(JwtVerifier);

        beforeEach(() => {
            sessionRequestValidationConfig = {
                expectedJwtRedirectUri: "redirect-uri",
            } as SessionRequestValidationConfig;

            sessionRequestValidator = new SessionRequestValidator(
                sessionRequestValidationConfig,
                jwtVerifier.prototype,
            );
        });

        it("should pass when jwt body is correct", async () => {
            const client_id = "request-client-id";

            const jwtPayload = {
                client_id: client_id,
                redirect_uri: "redirect-uri",
                scope: "openid",
                state: "state",
                shared_claims: personIdentity,
            } as JWTPayload;

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(Promise.resolve(jwtPayload));

            const payload = (await sessionRequestValidator.validateJwt(
                Buffer.from("test-jwt"),
                client_id,
            )) as JWTPayload;

            await expect(payload).toEqual(jwtPayload);
        });

        it("should fail to validate the jwt if scope is not openid", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const scope = "test";
            const state = "state";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    scope: scope,
                    state: state,
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () =>
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details: "Invalid scope parameter",
                }),
            );
        });

        it("should fail to validate the jwt if scope is missing", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () =>
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details: "Invalid scope parameter",
                }),
            );
        });

        it("should fail to validate the jwt if state is missing", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const scope = "openid";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    scope: scope,
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () =>
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details: "Invalid state parameter",
                }),
            );
        });
    });

    describe("SessionRequestValidatorFactory", () => {
        let sessionRequestValidatorFactory: SessionRequestValidatorFactory;
        jest.mocked(SessionRequestValidator);
        jest.mocked(JwtVerifier);

        beforeEach(() => {
            sessionRequestValidatorFactory = new SessionRequestValidatorFactory(logger);
        });

        it("should create a session request validator", () => {
            const output = sessionRequestValidatorFactory.create(mockMap);
            expect(output).toBeInstanceOf(SessionRequestValidator);
        });
    });
});
