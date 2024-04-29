import { MiddlewareObj, Request } from "@middy/core";
import { ConfigService } from "../../common/config/config-service";
import { AbsoluteParameterPath, ClientConfigKey } from "../../types/config-keys";

const defaults = {};

const initialiseClientConfigMiddleware = (opts: {
    configService: ConfigService;
    client_config_keys: ClientConfigKey[];
    client_absolute_paths?: [AbsoluteParameterPath];
}): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        const event_body = request.event.body;
        const clientId = event_body.clientId;

        if (!options.configService.hasClientConfig(clientId)) {
            await options.configService.initClientConfig(clientId, options.client_config_keys);

            if (options.client_absolute_paths) {
                for (const param of options.client_absolute_paths) {
                    await options.configService.initConfigUsingAbsolutePath(clientId, param.prefix, param.suffix);
                }
            }
        }
        await request.event;
    };

    return {
        before,
    };
};

export default initialiseClientConfigMiddleware;
