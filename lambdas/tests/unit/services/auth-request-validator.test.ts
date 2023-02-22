import { APIGatewayProxyEventQueryStringParameters } from "aws-lambda";
import { AuthorizationRequestValidator } from "../../../src/services/auth-request-validator";
import { SessionValidationError } from "../../../src/types/errors";

describe("auth-request-validator", () => {
    describe("validate", () => {
        let authRequestValidator: AuthorizationRequestValidator;
        const existingClientId = "a-valid-clientId";
        const configuredRedirectUri = "a-valid-redirect-uri";
        beforeEach(() => {
            authRequestValidator = new AuthorizationRequestValidator();
        });
        describe("no queryStringParams", () => {
            it("should return missing querystring parameters", () => {
                try {
                    authRequestValidator.validate(null, existingClientId, configuredRedirectUri);
                } catch (error) {
                    expect((error as SessionValidationError).details).toBe("Missing querystring parameters");
                    expect((error as SessionValidationError).message).toBe("Session Validation Exception");
                }
            });
        });
        describe("well-formed queryStringParams", () => {
            let queryStringParams: APIGatewayProxyEventQueryStringParameters;
            beforeEach(() => {
                queryStringParams = {
                    client_id: "a-valid-clientId",
                    redirect_uri: "a-valid-redirect-uri",
                    response_type: "a-valid-response-type",
                };
            });

            describe("with an existing client id and the configured redirect_uri", () => {
                it("should be called successfully and not throw any error", () => {
                    expect(() =>
                        authRequestValidator.validate(queryStringParams, existingClientId, configuredRedirectUri),
                    ).not.toThrow();
                });
            });
            describe("with a mismatched client id", () => {
                it("should return invalid client id parameter error", () => {
                    queryStringParams["client_id"] = "an-unexpected-clientId-in-the-request";
                    try {
                        authRequestValidator.validate(queryStringParams, existingClientId, configuredRedirectUri);
                    } catch (error) {
                        expect((error as SessionValidationError).details).toBe("Invalid client_id parameter");
                        expect((error as SessionValidationError).message).toBe("Session Validation Exception");
                    }
                });
            });
            describe("with mismatching configured redirect_uri", () => {
                it("should return invalid redirect uri parameter error", () => {
                    queryStringParams["redirect_uri"] = "an-unexpected-redirect-uri-in-the-request";
                    try {
                        authRequestValidator.validate(queryStringParams, existingClientId, configuredRedirectUri);
                    } catch (error) {
                        expect((error as SessionValidationError).details).toBe("Invalid redirect_uri parameter");
                        expect((error as SessionValidationError).message).toBe("Session Validation Exception");
                    }
                });
            });
            describe("client id and redirect_uri not matching", () => {
                it("first invalid returned i.e. client_id uri parameter error", () => {
                    queryStringParams["client_id"] = "an-unexpected-redirect-uri-in-the-request";
                    queryStringParams["redirect_uri"] = "an-unexpected-redirect-uri-in-the-request";
                    try {
                        authRequestValidator.validate(queryStringParams, existingClientId, configuredRedirectUri);
                    } catch (error) {
                        expect((error as SessionValidationError).details).toBe("Invalid client_id parameter");
                        expect((error as SessionValidationError).message).toBe("Session Validation Exception");
                    }
                });
            });
        });
        describe("incomplete queryStringParam", () => {
            describe("missing param attributes", () => {
                let queryStringParams: APIGatewayProxyEventQueryStringParameters;
                beforeEach(() => {
                    queryStringParams = {};
                });
                it("should return missing client id parameter error", () => {
                    (queryStringParams["redirect_uri"] = "a-valid-redirect-uri"),
                        (queryStringParams["response_type"] = "a-valid-response-type");
                    try {
                        authRequestValidator.validate(queryStringParams, existingClientId, configuredRedirectUri);
                    } catch (error) {
                        expect((error as SessionValidationError).details).toBe("Missing client_id parameter");
                        expect((error as SessionValidationError).message).toBe("Session Validation Exception");
                    }
                });
                it("should return missing redirect uri parameter error", () => {
                    queryStringParams["client_id"] = "a-valid-clientId";
                    queryStringParams["response_type"] = "a-valid-response-type";
                    try {
                        authRequestValidator.validate(queryStringParams, existingClientId, configuredRedirectUri);
                    } catch (error) {
                        expect((error as SessionValidationError).details).toBe("Missing redirect_uri parameter");
                        expect((error as SessionValidationError).message).toBe("Session Validation Exception");
                    }
                });
                it("should return missing response type parameter error", () => {
                    queryStringParams["client_id"] = "a-valid-clientId";
                    queryStringParams["redirect_uri"] = "a-valid-redirect-uri";
                    try {
                        authRequestValidator.validate(queryStringParams, existingClientId, configuredRedirectUri);
                    } catch (error) {
                        expect((error as SessionValidationError).details).toBe("Missing response_type parameter");
                        expect((error as SessionValidationError).message).toBe("Session Validation Exception");
                    }
                });
            });
        });
    });
});
