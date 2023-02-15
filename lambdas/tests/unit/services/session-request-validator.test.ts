import { Logger } from "@aws-lambda-powertools/logger";
import { JWTPayload } from "jose";
import { JwtVerifier } from "../../../src/common/security/jwt-verifier";
import {
    SessionRequestValidator,
    SessionRequestValidatorFactory,
} from "../../../src/services/session-request-validator";
import { ClientConfigKey } from "../../../src/common/config/config-keys";

describe("session-request-validator.ts", () => {
    const logger = new Logger();
    const mockMap = new Map<string, string>();
    mockMap.set("session-id", "test-session-id");

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
            const response = await sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id");
            expect(response.isValid).toEqual(false);
            expect(response.errorMsg).toEqual("JWT verification failure");
        });

        it("should return anerror on mismatched client ID", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                new Promise<JWTPayload | null>((res) =>
                    res({
                        client_id: "payload-client-id",
                    } as JWTPayload),
                ),
            );
            const response = await sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id");
            expect(response.isValid).toEqual(false);
            expect(response.errorMsg).toEqual(
                "Mismatched client_id in request body (request-client-id) & jwt (payload-client-id)",
            );
        });

        it("should return an error on failure to retrieve redirect URI", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                new Promise<JWTPayload | null>((res) =>
                    res({
                        client_id: "request-client-id",
                    } as JWTPayload),
                ),
            );
            const response = await sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id");
            expect(response.isValid).toEqual(false);
            expect(response.errorMsg).toEqual("Unable to retrieve redirect URI for client_id: request-client-id");
        });

        it("should return an error on mismatched redirect URI", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                new Promise<JWTPayload | null>((res) =>
                    res({
                        client_id: "request-client-id",
                        redirect_uri: "wrong-redirect-uri",
                    } as JWTPayload),
                ),
            );
            mockMap.set(ClientConfigKey.JWT_REDIRECT_URI, "redirect-uri");
            sessionRequestValidator = sessionRequestValidatorFactory.create(mockMap);

            const response = await sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id");
            expect(response.isValid).toEqual(false);
            expect(response.errorMsg).toEqual(
                "Redirect uri wrong-redirect-uri does not match configuration uri redirect-uri",
            );
        });

        it("should successfully validate the jwt", async () => {
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                new Promise<JWTPayload | null>((res) =>
                    res({
                        client_id: "request-client-id",
                        redirect_uri: "redirect-uri",
                    } as JWTPayload),
                ),
            );
            mockMap.set(ClientConfigKey.JWT_REDIRECT_URI, "redirect-uri");
            sessionRequestValidator = sessionRequestValidatorFactory.create(mockMap);

            const response = await sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), "request-client-id");
            expect(response.isValid).toEqual(true);
            expect(response.validatedObject).toEqual({
                client_id: "request-client-id",
                redirect_uri: "redirect-uri",
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
