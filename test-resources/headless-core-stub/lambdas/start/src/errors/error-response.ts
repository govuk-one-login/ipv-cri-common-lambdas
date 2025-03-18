import { Logger } from "@aws-lambda-powertools/logger";
import { HeadlessCoreStubError } from "./headless-core-stub-error";

export const handleErrorResponse = (err: unknown, logger: Logger) => {
    if (err instanceof Error) {
        logger.error(err.message, err);
    }
    if (!(err instanceof HeadlessCoreStubError)) {
        return {
            statusCode: 500,
            body: JSON.stringify({ message: "Server error" }),
        };
    }
    if (err.status >= 500) {
        err.message = "Server error";
    }
    return {
        statusCode: err.status,
        body: JSON.stringify({ message: err.message }),
    };
};
