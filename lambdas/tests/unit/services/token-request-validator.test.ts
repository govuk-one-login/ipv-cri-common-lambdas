import { AccessTokenRequestValidator } from "../../../src/services/token-request-validator";
import { JwtVerifierFactory } from "../../../src/common/security/jwt-verifier";
import { SessionItem } from "../../../src/types/session-item";
describe("token-request-validator.ts", () => {
    let accessTokenRequestValidator: AccessTokenRequestValidator;
    const mockJwtVerifierFactory = jest.mocked(JwtVerifierFactory);
    const code = "test";
    const redirect_uri = "http://abc123.com";
    const client_assertion = "test";
    const client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    const grant_type = "authorization_code";

    beforeEach(() => {
        jest.resetAllMocks();
        accessTokenRequestValidator = new AccessTokenRequestValidator(mockJwtVerifierFactory.prototype);
    });

    describe("validatePayload", () => {
        it("should throw when the client_assertion_type is not valid", function () {
            const tokenRequestBody = `code=${code}&redirect_uri=${redirect_uri}&client_assertion=${client_assertion}&client_assertion_type=test&grant_type=${grant_type}`;
            let requestPayload;
            try {
                requestPayload = accessTokenRequestValidator.validatePayload(tokenRequestBody);
            } catch (e: any) {
                expect(e.message).toBe("Invalid grant_type parameter");
            }
            expect(requestPayload).toBe(undefined);
        });

        it("should throw when the grant_type is not authorization_code", function () {
            const tokenRequestBody = `code=${code}&redirect_uri=${redirect_uri}&client_assertion=${client_assertion}&client_assertion_type=${client_assertion_type}&grant_type=test`;
            let requestPayload;
            try {
                requestPayload = accessTokenRequestValidator.validatePayload(tokenRequestBody);
            } catch (e: any) {
                expect(e.message).toBe("Invalid grant_type parameter");
            }
            expect(requestPayload).toBe(undefined);
        });

        it("should throw when there is a missing client_assertion", function () {
            const tokenRequestBody = `code=${code}&redirect_uri=${redirect_uri}&client_assertion_type=${client_assertion_type}&grant_type=${grant_type}`;
            let requestPayload;
            try {
                requestPayload = accessTokenRequestValidator.validatePayload(tokenRequestBody);
            } catch (e: any) {
                expect(e.message).toBe("Invalid client_assertion parameter");
            }
            expect(requestPayload).toBe(undefined);
        });

        it("should throw when there is a missing code", function () {
            const tokenRequestBody = `redirect_uri=${redirect_uri}&client_assertion=${client_assertion}&client_assertion_type=${client_assertion_type}&grant_type=${grant_type}`;
            let requestPayload;
            try {
                requestPayload = accessTokenRequestValidator.validatePayload(tokenRequestBody);
            } catch (e: any) {
                expect(e.message).toBe("Invalid request: Missing code parameter");
            }
            expect(requestPayload).toBe(undefined);
        });

        it("should throw when there is a missing redirectUri", function () {
            const tokenRequestBody = `code=${code}&client_assertion=${client_assertion}&client_assertion_type=${client_assertion_type}&grant_type=${grant_type}`;
            let requestPayload;
            try {
                requestPayload = accessTokenRequestValidator.validatePayload(tokenRequestBody);
            } catch (e: any) {
                expect(e.message).toBe("Invalid request: Missing redirectUri parameter");
            }
            expect(requestPayload).toBe(undefined);
        });

        it("should pass with a fully validated tokenRequestBody", function () {
            const tokenRequestBody = `code=${code}&redirect_uri=${redirect_uri}&client_assertion=${client_assertion}&client_assertion_type=${client_assertion_type}&grant_type=${grant_type}`;
            const requestPayload = accessTokenRequestValidator.validatePayload(tokenRequestBody);
            expect(requestPayload.code).toEqual(code);
            expect(requestPayload.redirectUri).toEqual(redirect_uri);
            expect(requestPayload.client_assertion).toEqual(client_assertion);
            expect(requestPayload.client_assertion_type).toEqual(client_assertion_type);
            expect(requestPayload.grant_type).toEqual(grant_type);
        });

        it("should throw exception when there is no tokenRequestBody", async () => {
            const tokenRequestBody = null;
            let requestPayload;
            try {
                requestPayload = accessTokenRequestValidator.validatePayload(tokenRequestBody);
            } catch (e: any) {
                expect(e.message).toBe("Invalid request: missing body");
            }
            expect(requestPayload).toBe(undefined);
        });
    });

    describe("validateTokenRequestToRecord", () => {
        let sessionItem: SessionItem;

        it("should throw exception when there is no sessionItem", async () => {
            const authCode = "1234";
            const expectedRedirectUri = "http://abc123.com";
            try {
                accessTokenRequestValidator.validateTokenRequestToRecord(authCode, sessionItem, expectedRedirectUri);
            } catch (e: any) {
                expect(e.message).toBe("Invalid sessionItem");
            }
        });

        it("should throw exception the authorizationCode within the sessionItem does not match the authCode", async () => {
            const authCode = "1234";
            const expectedRedirectUri = "http://abc123.com";
            const sessionItem: SessionItem = {
                sessionId: "1",
                clientId: "1",
                clientSessionId: "1",
                authorizationCode: "test",
                authorizationCodeExpiryDate: 0,
                redirectUri: "http://abc123.com",
                accessToken: "test",
                accessTokenExpiryDate: 0,
            };
            try {
                accessTokenRequestValidator.validateTokenRequestToRecord(authCode, sessionItem, expectedRedirectUri);
            } catch (e: any) {
                expect(e.message).not.toEqual(null);
            }
        });

        it("should pass when the authorizationCode within the sessionItem does matches the authCode", async () => {
            const authCode = "1234";
            const expectedRedirectUri = "http://abc123.com";
            const sessionItem: SessionItem = {
                sessionId: "1",
                clientId: "1",
                clientSessionId: "1",
                authorizationCode: authCode,
                authorizationCodeExpiryDate: 0,
                redirectUri: expectedRedirectUri,
                accessToken: "test",
                accessTokenExpiryDate: 0,
            };
            accessTokenRequestValidator.validateTokenRequestToRecord(authCode, sessionItem, expectedRedirectUri);
        });

        it("should fail when the expectedRedirectUri does not match", async () => {
            const authCode = "1234";
            const expectedRedirectUri = "http://abc123.com";
            const badRedirectUri = "http://123Abc.com";
            const sessionItem: SessionItem = {
                sessionId: "1",
                clientId: "1",
                clientSessionId: "1",
                authorizationCode: authCode,
                authorizationCodeExpiryDate: 0,
                redirectUri: badRedirectUri,
                accessToken: "test",
                accessTokenExpiryDate: 0,
            };
            try {
                accessTokenRequestValidator.validateTokenRequestToRecord(authCode, sessionItem, expectedRedirectUri);
            } catch (e: any) {
                expect(e.message).toContain(
                    `Invalid request: redirect uri ${badRedirectUri} does not match configuration uri ${expectedRedirectUri}`,
                );
            }
        });
    });
});
