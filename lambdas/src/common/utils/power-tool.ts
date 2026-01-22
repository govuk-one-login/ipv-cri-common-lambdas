import { Metrics } from "@aws-lambda-powertools/metrics";
import { Tracer } from "@aws-lambda-powertools/tracer";

const metrics = new Metrics();
const tracer = new Tracer({ captureHTTPsRequests: false });

export { metrics, tracer };
