import { MiddlewareObj, Request } from "@middy/core";
import { ConfigService } from "../../common/config/config-service";
import { ClientConfigKey } from "../../types/config-keys";

const defaults = {};

const initialiseClientConfigMiddleware = (opts: {
    configService: ConfigService;
    client_config_keys: ClientConfigKey[];
}): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        const event_body = request.event.body;
        if (!options.configService.hasClientConfig(event_body.clientId)) {
            await options.configService.initClientConfig(event_body.clientId, options.client_config_keys);
        }

        await request.event;
    };

    return {
        before,
    };
};

export default initialiseClientConfigMiddleware;
