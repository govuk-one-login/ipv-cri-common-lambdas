import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnits } from "@aws-lambda-powertools/metrics";
import { MiddlewareObj, Request } from "@middy/core";
import { errorPayload } from "../../common/utils/errors";

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
        return Promise.resolve(errorPayload(request.error as Error, logger, options.message));
    };

    return {
        onError,
    };
};

export default errorMiddleware;
