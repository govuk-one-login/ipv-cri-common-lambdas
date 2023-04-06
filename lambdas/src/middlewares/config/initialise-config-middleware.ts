import { SSMClient } from "@aws-sdk/client-ssm";
import { MiddlewareObj, Request } from "@middy/core";
import { AwsClientType, createClient } from "../../common/aws-client-factory";
import { ConfigService } from "../../common/config/config-service";
import { CommonConfigKey } from "../../types/config-keys";

const defaults = {};

const ssmClient = createClient(AwsClientType.SSM) as SSMClient;
const configService = new ConfigService(ssmClient);
const initialiseConfigMiddleware = (opts: { config_keys: Array<CommonConfigKey>}): MiddlewareObj => {
    const options = { ...defaults, ...opts };

    const before = async (request: Request) => {
        await configService.init(options.config_keys);

        await request.event;
    };

    return {
        before,
    };
};
export default initialiseConfigMiddleware;
export { configService };
