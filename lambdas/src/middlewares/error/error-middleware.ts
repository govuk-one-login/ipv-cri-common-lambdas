import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
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

        // eslint-disable-next-line no-console
        console.log("🍊 Error middleware");

        metrics.addMetric("test_caitlin", MetricUnit.Count, 0);
        // metrics.publishStoredMetrics();

        // eslint-disable-next-line no-console
        console.log("🍊 Metric has been added");

        return Promise.resolve(errorPayload(request.error as Error, logger, options.message));
    };

    return {
        onError,
    };
};

export default errorMiddleware;
