import { Logger } from "@aws-lambda-powertools/logger";
import { handleErrorResponse } from "../../src/errors/error-response";
import { HeadlessCoreStubError } from "../../src/errors/headless-core-stub-error";

describe("error-response", () => {
    const logger = new Logger();
    jest.spyOn(logger, "error");

    it("returns error with message on 400 HeadlessCoreStubError", () => {
        const error = new HeadlessCoreStubError("Custom Error", 400);
        const result = handleErrorResponse(error, logger);
        expect(result).toEqual({ body: '{"message":"Custom Error"}', statusCode: 400 });
        expect(logger.error).toHaveBeenCalledWith(error.message, error);
    });

    it("returns server error on 500 HeadlessCoreStubError", () => {
        const error = new HeadlessCoreStubError("Custom Error", 500);
        const result = handleErrorResponse(error, logger);
        expect(result).toEqual({ body: '{"message":"Server error"}', statusCode: 500 });
        expect(logger.error).toHaveBeenCalledWith("Custom Error", error);
    });

    it("returns 500 on Error", () => {
        const error = new Error();
        const result = handleErrorResponse(error, logger);
        expect(result).toEqual({ body: '{"message":"Server error"}', statusCode: 500 });
        expect(logger.error).toHaveBeenCalledWith(error.message, error);
    });

    it("returns 500 on null error", () => {
        const result = handleErrorResponse(null, logger);
        expect(result).toEqual({ body: '{"message":"Server error"}', statusCode: 500 });
    });
});
