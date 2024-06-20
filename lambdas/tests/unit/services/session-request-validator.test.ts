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
import { CRIEvidenceProperties } from "../../../src/services/cri_evidence_properties";

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
            const state = "state";
            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: "request-client-id",
                    redirect_uri: "redirect-uri",
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

        it("should pass when strength score is 2 and cri is di-ipv-check-hmrc-api", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            const previousCriIdentifier = process.env.CRI_IDENTIFIER;
            process.env.CRI_IDENTIFIER = "di-ipv-cri-check-hmrc-api";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    evidence_requested: {
                        scoringPolicy: "gpg45",
                        strengthScore: 2,
                    },
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () => sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id)).resolves;

            process.env.CRI_IDENTIFIER = previousCriIdentifier;
        });

        it("should fail when strength score not 2 and cri is di-ipv-check-hmrc-api", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            const previousCriIdentifier = process.env.CRI_IDENTIFIER;
            process.env.CRI_IDENTIFIER = "di-ipv-cri-check-hmrc-api";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    evidence_requested: {
                        scoringPolicy: "gpg45",
                        strengthScore: 1,
                    },
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () =>
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).rejects.toThrow(new Error("Session Validation Exception"));

            process.env.CRI_IDENTIFIER = previousCriIdentifier;
        });

        it("should fail to validate the evidence_requested is included and scoringPolicy is not gpg45", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    evidence_requested: {
                        scoringPolicy: "invalid-scoring-policy",
                    },
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () =>
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).rejects.toThrow(
                expect.objectContaining({
                    message: "Session Validation Exception",
                    details: "Invalid request: scoringPolicy in evidence_requested does not equal gpg45",
                }),
            );
        });

        it("should pass when the evidence_requested is included and scoringPolicy is gpg45", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    evidence_requested: {
                        scoringPolicy: "gpg45",
                    },
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () => sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id)).resolves;
        });

        it("should pass when the there is no evidence_requested", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () => sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id)).resolves;
        });
        it("should fail to validate the jwt if state is missing", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
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

    describe("sessionRequestValidator for di-ipv-cri-kbv-api", () => {
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
                { verificationScore: [1, 2] } as CRIEvidenceProperties,
            );
        });

        it("should pass when strengthScore is 1 and cri is di-ipv-cri-kbv-api", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            const previousCriIdentifier = process.env.CRI_IDENTIFIER;
            process.env.CRI_IDENTIFIER = "di-ipv-cri-kbv-api";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    evidence_requested: {
                        scoringPolicy: "gpg45",
                        verificationScore: 1,
                    },
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).resolves.not.toThrow();

            process.env.CRI_IDENTIFIER = previousCriIdentifier;
        });

        it("should pass when verificationScore is 2 and cri is di-ipv-cri-kbv-api", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            const previousCriIdentifier = process.env.CRI_IDENTIFIER;
            process.env.CRI_IDENTIFIER = "di-ipv-cri-kbv-api";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    evidence_requested: {
                        scoringPolicy: "gpg45",
                        verificationScore: 2,
                    },
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).resolves.not.toThrow();

            process.env.CRI_IDENTIFIER = previousCriIdentifier;
        });

        it("should pass when verifcationScore is not included in evidence_requested and cri is di-ipv-cri-kbv-api", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            const previousCriIdentifier = process.env.CRI_IDENTIFIER;
            process.env.CRI_IDENTIFIER = "di-ipv-cri-kbv-api";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    evidence_requested: {
                        scoringPolicy: "gpg45",
                    },
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).resolves.not.toThrow();

            process.env.CRI_IDENTIFIER = previousCriIdentifier;
        });

        it("should fail when verifcationScore is not 1,2 or empty and cri is di-ipv-cri-kbv-api", async () => {
            const client_id = "request-client-id";
            const redirect_uri = "redirect-uri";
            const state = "state";

            const previousCriIdentifier = process.env.CRI_IDENTIFIER;
            process.env.CRI_IDENTIFIER = "di-ipv-cri-kbv-api";

            jest.spyOn(jwtVerifier.prototype, "verify").mockReturnValue(
                await Promise.resolve({
                    client_id: client_id,
                    redirect_uri: redirect_uri,
                    state: state,
                    evidence_requested: {
                        scoringPolicy: "gpg45",
                        verificationScore: 3,
                    },
                    shared_claims: personIdentity,
                } as JWTPayload),
            );

            await expect(async () =>
                sessionRequestValidator.validateJwt(Buffer.from("test-jwt"), client_id),
            ).rejects.toThrow(new Error("Session Validation Exception"));

            process.env.CRI_IDENTIFIER = previousCriIdentifier;
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
