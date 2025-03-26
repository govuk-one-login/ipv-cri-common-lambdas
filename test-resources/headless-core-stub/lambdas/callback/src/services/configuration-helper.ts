import { getParametersValues } from "./get-parameters";

const commonParameterPrefix = process.env.AWS_STACK_NAME || "common-cri-api";
const testResourcesParameterPrefix = process.env.TEST_RESOURCES_STACK_NAME || "test-resources";

export class ConfigurationHelper {
    public async getParameters(clientId: string) {
        const parameters = [
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/audience`,
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/issuer`,
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/redirectUri`,
            `/${testResourcesParameterPrefix}/${clientId}/privateSigningKey`,
        ];
        return getParametersValues(parameters);
    }
}
