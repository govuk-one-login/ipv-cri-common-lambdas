import { getParametersByName } from "@aws-lambda-powertools/parameters/ssm";
import { ClientConfigKey, CommonConfigKey } from "./config-keys";

const commonParameterPrefix = process.env.AWS_STACK_NAME || "common-cri-api";
const testResourcesParameterPrefix = process.env.TEST_RESOURCES_STACK_NAME || "test-resources";

export enum ConfigSecretKey {
    STUB_PRIVATE_SIGNING_KEY = "ipv-core-stub-aws-headless/privateSigningKey", // pragma: allowlist secret
}

export class ConfigurationHelper {
    constructor() {}

    public getParameterWithClientId = async (clientId: string) => {
        const parameters = [
            {
                key: ClientConfigKey.JWT_AUDIENCE,
                prefix: `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication`,
            },
            {
                key: ClientConfigKey.JWT_ISSUER,
                prefix: `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication`,
            },
            {
                key: ClientConfigKey.JWT_REDIRECT_URI,
                prefix: `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication`,
            },
        ];
        return this.getParametersValues(parameters);
    };

    public getParametersWithoutClientId = async () => {
        const parameters = [
            { key: CommonConfigKey.SESSION_TABLE_NAME, prefix: `/${commonParameterPrefix}` },
            { key: ConfigSecretKey.STUB_PRIVATE_SIGNING_KEY, prefix: `/${testResourcesParameterPrefix}` },
        ];
        return this.getParametersValues(parameters);
    };

    async getParametersValues(configParams: Array<{ key: string; prefix: string }>): Promise<Record<string, string>> {
        const cacheTtlInSecond = 300;
        const { _errors: errors, ...parameters } = await getParametersByName<string>(
            Object.fromEntries(configParams.map((parameter) => [`${parameter.prefix}/${parameter.key}`, {}])),
            { maxAge: cacheTtlInSecond, throwOnError: false },
        );

        if (errors?.length) {
            const errorMessage = `Following SSM parameters do not exist: ${errors.join(", ")}`;
            throw new Error(errorMessage);
        }

        return Object.fromEntries(
            configParams.map((param) => [param.key, String(parameters[`${param.prefix}/${param.key}`])]),
        );
    }
}
