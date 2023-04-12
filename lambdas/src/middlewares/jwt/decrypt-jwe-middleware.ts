import { Logger } from "@aws-lambda-powertools/logger";
import { MiddlewareObj, Request } from "@middy/core";
import { JweDecrypter } from "../../services/security/jwe-decrypter";

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
        logger.info("JWE decrypted");
        await request.event;
    };

    return {
        before,
    };
};

export default decryptJweMiddleware;
