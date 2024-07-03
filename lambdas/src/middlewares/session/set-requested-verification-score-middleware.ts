import { Logger } from "@aws-lambda-powertools/logger";
import { MiddlewareObj, Request } from "@middy/core";

const setRequestedVerificationScoreMiddleware = (logger: Logger): MiddlewareObj => {
    const before = async (request: Request) => {
        const { evidence_requested } = request.event.body;
        if (evidence_requested?.verificationScore) {
            logger.appendKeys({ verification_score: evidence_requested.verificationScore });
            await request.event;
        }
    };

    return {
        before,
    };
};

export default setRequestedVerificationScoreMiddleware;
