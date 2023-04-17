import { Logger } from "@aws-lambda-powertools/logger";
import { MiddlewareObj, Request } from "@middy/core";
import { JweDecrypter } from "../../services/security/jwe-decrypter";
import { JWTPayload } from "jose/dist/types/types";

const defaults = {};

const decryptJweMiddleware = (logger: Logger, opts: { jweDecrypter: JweDecrypter }): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        const { client_id: clientId, request: input } = JSON.parse(request.event.body);
        const jwePayload = { decryptedJwe: await options.jweDecrypter.decryptJwe(input) };
        request.event = {
            ...request.event,
            body: {
                ...jwePayload,
                clientId,
            },
        };
        await request.event;
    };
    const after = async (request: Request) => {
        const jwtPayload = request.event.body as unknown as JWTPayload;
        const clientSessionId = jwtPayload["govuk_signin_journey_id"] as string;

        logger.appendKeys({ govuk_signin_journey_id: clientSessionId });
        logger.info("JWE decrypted");
        await request.event;
    };
    return {
        after,
        before,
    };
};

export default decryptJweMiddleware;
