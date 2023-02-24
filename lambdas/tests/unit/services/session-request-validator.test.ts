import { Logger } from "@aws-lambda-powertools/logger";
import { JWTPayload } from "jose";
import { JwtVerifier } from "../../../src/common/security/jwt-verifier";
import {
    SessionRequestValidator,
    SessionRequestValidatorFactory,
} from "../../../src/services/session-request-validator";
import { ClientConfigKey } from "../../../src/types/config-keys";
import { PersonIdentity } from "../../../src/types/person-identity";

describe("session-request-validator.ts", () => {
    const logger = new Logger();
    const mockMap = new Map<string, string>();
    mockMap.set("session-id", "test-session-id");
    const personIdentity = jest.mocked({} as PersonIdentity);

    describe("SessionRequestValidator", () => {
        let sessionRequestValidatorFactory: SessionRequestValidatorFactory;
        let sessionRequestValidator: SessionRequestValidator;
        const jwtVerifier = jest.mocked(JwtVerifier);

        beforeEach(() => {
            sessionRequestValidatorFactory = new SessionRequestValidatorFactory(logger);
            sessionRequestValidator = sessionRequestValidatorFactory.create(mockMap);
        });

        it("should return an error on JWT verification failure", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                new Promise<JWTPayload | null>((res) => res(null)),
            );

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id"),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details: "Invalid request: JWT validation/verification failed: JWT verification failure",
                }),
            );
        });

        it("should return an error on JWT verification failure", async () => {
            const jwtPayload = jest.mocked({} as JWTPayload);
            jest.spyOn(jwtVerifier.prototype, "verify").mockResolvedValueOnce(jwtPayload);

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id"),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details: "Invalid request: JWT validation/verification failed: JWT payload missing shared claims",
                }),
            );
        });

        it("should return anerror on mismatched client ID", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                new Promise<JWTPayload | null>((res) =>
                    res({
                        client_id: "payload-client-id",
                        shared_claims: personIdentity,
                    } as JWTPayload),
                ),
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
                new Promise<JWTPayload | null>((res) =>
                    res({
                        client_id: "request-client-id",
                        shared_claims: personIdentity,
                    } as JWTPayload),
                ),
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
                new Promise<JWTPayload | null>((res) =>
                    res({
                        client_id: "request-client-id",
                        redirect_uri: "wrong-redirect-uri",
                        shared_claims: personIdentity,
                    } as JWTPayload),
                ),
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
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                new Promise<JWTPayload | null>((res) =>
                    res({
                        client_id: "request-client-id",
                        redirect_uri: "redirect-uri",
                        shared_claims: personIdentity,
                    } as JWTPayload),
                ),
            );
            mockMap.set(ClientConfigKey.JWT_REDIRECT_URI, "redirect-uri");
            sessionRequestValidator = sessionRequestValidatorFactory.create(mockMap);

            const response = await sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id");
            expect(response).toEqual({
                client_id: "request-client-id",
                redirect_uri: "redirect-uri",
                shared_claims: personIdentity,
            });
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
