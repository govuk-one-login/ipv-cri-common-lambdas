import { MiddlewareObj, Request } from "@middy/core";
import { ConfigService } from "../../common/config/config-service";
import { CommonConfigKey } from "../../types/config-keys";

const defaults = {};

const initialiseConfigMiddleware = (opts: {
    configService: ConfigService;
    config_keys: CommonConfigKey[];
}): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        await options.configService.init(options.config_keys);

        await request.event;
    };

    return {
        before,
    };
};
export default initialiseConfigMiddleware;
