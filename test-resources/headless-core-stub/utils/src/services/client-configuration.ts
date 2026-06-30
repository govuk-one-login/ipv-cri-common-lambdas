import { getParametersValues } from "../parameter/get-parameters";
import config from "./config";
const { commonStackName } = config;

export class ClientConfiguration {
    public static async getConfig(clientId: string) {
        const parameters = [
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/audience`,
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/issuer`,
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/redirectUri`,
            `/test-resources/${clientId}/privateSigningKey`,
        ];
        return getParametersValues(parameters);
    }
}
