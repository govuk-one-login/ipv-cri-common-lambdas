import { Logger } from "@aws-lambda-powertools/logger";
import { MiddlewareObj, Request } from "@middy/core";
import { ConfigService } from "../../common/config/config-service";
import { SessionRequestValidatorFactory } from "../../services/session-request-validator";
import { JweRequest } from "../../types/jwe-request";
import { JWTPayload } from "jose/dist/types/types";

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
        await request.event;

        throw new Error("🍊 Validated jwt error");
    };

    const after = async (request: Request) => {
        const jwtPayload = request.event.body as unknown as JWTPayload;
        const clientSessionId = jwtPayload["govuk_signin_journey_id"] as string;

        logger.appendKeys({ govuk_signin_journey_id: clientSessionId });
        logger.info("JWT validated");
        await request.event;
    };
    return {
        before,
        after,
    };
};

export default validateJwtMiddleware;
