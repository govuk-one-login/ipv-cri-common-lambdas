import { Logger } from "@aws-lambda-powertools/logger";
import { MiddlewareObj, Request } from "@middy/core";

const setGovUkSigningJourneyIdMiddleware = (logger: Logger): MiddlewareObj => {
    const before = async (request: Request) => {
        const { clientSessionId } = request.event.body;

        logger.appendKeys({ govuk_signin_journey_id: clientSessionId });
        await request.event;
    };

    return {
        before,
    };
};

export default setGovUkSigningJourneyIdMiddleware;
