import { Logger } from "@aws-lambda-powertools/logger";
import { MiddlewareObj, Request } from "@middy/core";
import { errorPayload, SessionValidationError } from "../../common/utils/errors";
import { captureMetric, metrics } from "@govuk-one-login/cri-metrics";

const SESSION_CREATED_METRIC = "session_created";
const JWT_VERIFICATION_FAILED_METRIC = "jwt_verification_failed";
const JWT_EXPIRED_METRIC = "jwt_expired";
const defaults = {};

const errorMiddleware = (logger: Logger, opts: { metric_name: string; message: string }): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const onError = async (request: Request) => {
        if (request.response !== undefined) return;

        captureMetric(options.metric_name, 0);
        if (request.error instanceof SessionValidationError && options.metric_name === SESSION_CREATED_METRIC) {
            if (request.error.details?.includes("ERR_JWT_EXPIRED")) {
                captureMetric(JWT_EXPIRED_METRIC);
            } else {
                captureMetric(JWT_VERIFICATION_FAILED_METRIC);
            }
        }
        metrics.publishStoredMetrics();
        return errorPayload(request.error as Error, logger, options.message);
    };

    return {
        onError,
    };
};

export default errorMiddleware;
