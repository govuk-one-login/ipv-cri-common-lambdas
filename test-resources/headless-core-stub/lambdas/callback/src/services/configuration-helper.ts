import { getParametersByName } from "@aws-lambda-powertools/parameters/ssm";

const commonParameterPrefix = process.env.AWS_STACK_NAME || "common-cri-api";
const testResourcesParameterPrefix = process.env.TEST_RESOURCES_STACK_NAME || "test-resources";

export class ConfigurationHelper {
    public getParameters = async (clientId: string) => {
        const parameters = [
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/audience`,
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/issuer`,
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/redirectUri`,
            `/${testResourcesParameterPrefix}/ipv-core-stub-aws-headless/privateSigningKey`,
        ];
        return this.getParametersValues(parameters);
    };

    async getParametersValues(parameterPaths: string[]): Promise<Record<string, string>> {
        const { _errors: errors, ...parameters } = await getParametersByName<string>(
            Object.fromEntries(parameterPaths.map((path) => [path, {}])),
            { maxAge: 300, throwOnError: false },
        );

        if (errors?.length) {
            const errorMessage = `Following SSM parameters do not exist: ${errors.join(", ")}`;
            throw new Error(errorMessage);
        }

        return Object.fromEntries(
            parameterPaths.map((path) => {
                return [path.split("/").pop()!, String(parameters[path])];
            }),
        );
    }
}
