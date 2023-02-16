import { AuthorizationRequestValidator } from "../../../src/services/auth-request-validator";

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
                const validationResult = authRequestValidator.validate(null, existingClientId, configuredRedirectUri);
                expect(validationResult).toEqual({
                    isValid: false,
                    errorMsg: "Missing querystring parameters",
                });
            });
        });
        describe("well-formed queryStringParams", () => {
            let queryStringParams: any;
            beforeEach(() => {
                queryStringParams = {
                    client_id: "a-valid-clientId",
                    redirect_uri: "a-valid-redirect-uri",
                    response_type: "a-valid-response-type",
                };
            });

            describe("with an existing client id and the configured redirect_uri", () => {
                it("should return object true isValid attribute and null errorMsg", () => {
                    const validationResult = authRequestValidator.validate(
                        queryStringParams,
                        existingClientId,
                        configuredRedirectUri,
                    );
                    expect(validationResult).toEqual({
                        isValid: true,
                        errorMsg: null,
                    });
                });
            });
            describe("with a mismatched client id", () => {
                it("should return invalid client id parameter error", () => {
                    queryStringParams["client_id"] = "an-unexpected-clientId-in-the-request";

                    const validationResult = authRequestValidator.validate(
                        queryStringParams,
                        existingClientId,
                        configuredRedirectUri,
                    );
                    expect(validationResult).toEqual({
                        isValid: false,
                        errorMsg: "Invalid client_id parameter",
                    });
                });
            });
            describe("with mismatching configured redirect_uri", () => {
                it("should return invalid redirect uri parameter error", () => {
                    queryStringParams["redirect_uri"] = "an-unexpected-redirect-uri-in-the-request";

                    const validationResult = authRequestValidator.validate(
                        queryStringParams,
                        existingClientId,
                        configuredRedirectUri,
                    );
                    expect(validationResult).toEqual({
                        isValid: false,
                        errorMsg: "Invalid redirect_uri parameter",
                    });
                });
            });
            describe("client id and redirect_uri not matching", () => {
                it("first invalid returned i.e. client_id uri parameter error", () => {
                    queryStringParams["client_id"] = "an-unexpected-redirect-uri-in-the-request";
                    queryStringParams["redirect_uri"] = "an-unexpected-redirect-uri-in-the-request";

                    const validationResult = authRequestValidator.validate(
                        queryStringParams,
                        existingClientId,
                        configuredRedirectUri,
                    );
                    expect(validationResult).toEqual({
                        isValid: false,
                        errorMsg: "Invalid client_id parameter",
                    });
                });
            });
        });
        describe("incomplete queryStringParam", () => {
            describe("missing param attributes", () => {
                let queryStringParams: any;
                beforeEach(() => {
                    queryStringParams = {};
                });
                it("should return missing client id parameter error", () => {
                    (queryStringParams["redirect_uri"] = "a-valid-redirect-uri"),
                        (queryStringParams["response_type"] = "a-valid-response-type");

                    const validationResult = authRequestValidator.validate(
                        queryStringParams,
                        existingClientId,
                        configuredRedirectUri,
                    );
                    expect(validationResult).toEqual({
                        isValid: false,
                        errorMsg: "Missing client_id parameter",
                    });
                });
                it("should return missing redirect uri parameter error", () => {
                    queryStringParams["client_id"] = "a-valid-clientId";
                    queryStringParams["response_type"] = "a-valid-response-type";
                    const validationResult = authRequestValidator.validate(
                        queryStringParams,
                        existingClientId,
                        configuredRedirectUri,
                    );
                    expect(validationResult).toEqual({
                        isValid: false,
                        errorMsg: "Missing redirect_uri parameter",
                    });
                });
                it("should return missing response type parameter error", () => {
                    queryStringParams["client_id"] = "a-valid-clientId";
                    queryStringParams["redirect_uri"] = "a-valid-redirect-uri";
                    const validationResult = authRequestValidator.validate(
                        queryStringParams,
                        existingClientId,
                        configuredRedirectUri,
                    );
                    expect(validationResult).toEqual({
                        isValid: false,
                        errorMsg: "Missing response_type parameter",
                    });
                });
            });
        });
    });
});
