import { Logger } from "@aws-lambda-powertools/logger";
import { HeadlessCoreStubError } from "./headless-core-stub-error";

export const handleErrorResponse = (err: unknown, logger: Logger) => {
    err instanceof Error ? logger.error(err.message, err) : logger.error("Unknown error caught");

    if (err instanceof HeadlessCoreStubError) {
        return {
            statusCode: err.status,
            body: JSON.stringify({ message: err.message }),
        };
    }

    return {
        statusCode: 500,
        body: JSON.stringify({ message: "Server error" }),
    };
};
