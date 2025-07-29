import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { MiddlewareObj, Request } from "@middy/core";
import { errorPayload, SessionValidationError } from "../../common/utils/errors";

const SESSION_CREATED_METRIC = "session_created";
const JWT_VERIFICATION_FAILED_METRIC = "jwt_verification_failed";
const JWT_EXPIRED_METRIC = "jwt_expired";
const defaults = {};

const errorMiddleware = (
    logger: Logger,
    metrics: Metrics,
    opts: { metric_name: string; message: string },
): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const onError = async (request: Request) => {
        if (request.response !== undefined) return;

        metrics.addMetric(options.metric_name, MetricUnits.Count, 0);
        if (request.error instanceof SessionValidationError && options.metric_name === SESSION_CREATED_METRIC) {
            if (request.error.details?.includes("ERR_JWT_EXPIRED")) {
                metrics.addMetric(JWT_EXPIRED_METRIC, MetricUnits.Count, 1);
            } else {
                metrics.addMetric(JWT_VERIFICATION_FAILED_METRIC, MetricUnits.Count, 1);
            }
        }
        metrics.publishStoredMetrics();
        return Promise.resolve(errorPayload(request.error as Error, logger, options.message));
    };

    return {
        onError,
    };
};

export default errorMiddleware;
