import { getParametersValues } from "../parameter/get-parameters";
import config from "./config";
const { commonParameterPrefix, testResourcesParameterPrefix } = config;

export class ClientConfiguration {
    public static async getConfig(clientId: string) {
        const parameters = [
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/audience`,
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/issuer`,
            `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/redirectUri`,
            `/${testResourcesParameterPrefix}/ipv-core-stub-aws-headless/privateSigningKey`,
        ];
        return getParametersValues(parameters);
    }
}
