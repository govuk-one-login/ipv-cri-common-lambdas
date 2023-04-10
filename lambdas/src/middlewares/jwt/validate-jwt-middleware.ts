import { Logger } from "@aws-lambda-powertools/logger";
import { MiddlewareObj, Request } from "@middy/core";
import { ConfigService } from "../../common/config/config-service";
import { SessionRequestValidatorFactory } from "../../services/session-request-validator";
import { JweRequest } from "../../types/jwe-request";

const defaults = {};

const validateJwtMiddleware = (
    logger: Logger,
    opts: { configService: ConfigService; jwtValidatorFactory: SessionRequestValidatorFactory },
): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        const { clientId, decryptedJwe } = request.event.body as JweRequest;

        const criClientConfig = options.configService.getClientConfig(clientId) as Map<string, string>;
        const jwtValidator = options.jwtValidatorFactory.create(criClientConfig);
        const jwtPayload = await jwtValidator.validateJwt(decryptedJwe, clientId);
        const clientSessionId = jwtPayload["govuk_signin_journey_id"] as string;
        request.event = {
            ...request.event,
            body: {
                clientSessionId,
                ...jwtPayload,
            },
        };
        logger.info("JWT validated");
        await request.event;
    };

    return {
        before,
    };
};

export default validateJwtMiddleware;
