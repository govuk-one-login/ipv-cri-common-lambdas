import { SSMClient } from "@aws-sdk/client-ssm";
import { MiddlewareObj, Request } from "@middy/core";
import { AwsClientType, createClient } from "../../common/aws-client-factory";
import { ConfigService } from "../../common/config/config-service";
import { CommonConfigKey } from "../../types/config-keys";

const ssmClient = createClient(AwsClientType.SSM) as SSMClient;
const configService = new ConfigService(ssmClient);
const initPromise = configService.init([CommonConfigKey.SESSION_TABLE_NAME, CommonConfigKey.SESSION_TTL]);
const configurationInitMiddleware = (): MiddlewareObj => {
    const before = async (request: Request) => {
        await initPromise;

        await request.event;
    };

    return {
        before,
    };
};
export default configurationInitMiddleware;
export { configService };
