import { getParametersValues } from "../parameter/get-parameters";
import config from "./config";
const { commonStackName } = config;

export class ClientConfiguration {
    public static async getConfig(clientId: string) {
        const parameters = [
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/audience`,
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/issuer`,
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/redirectUri`,
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/publicSigningJwkBase64`,
            "/test-resources/ipv-core-stub-aws-headless/privateSigningKey",
        ];
        return getParametersValues(parameters);
    }
}
