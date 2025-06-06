import { ClientConfiguration } from "../../src/services/client-configuration";
import * as SSMPowerToolsParameter from "@aws-lambda-powertools/parameters/ssm";
import * as GetParameters from "../../src/parameter/get-parameters";
jest.mock("@aws-lambda-powertools/parameters/ssm");

describe("ClientConfiguration", () => {
    const commonStackName = "mock-common-prefix";
    const issuer = "mock-issuer";
    const clientId = "headless-core-stub";
    const audience = "my-audience";
    const redirectUri = "https://test-resources.headless-core-stub.redirect/callback";

    beforeEach(() => {
        process.env = {
            ...process.env,
            COMMON_STACK_NAME: commonStackName,
        };
        jest.clearAllMocks();
    });

    describe("getConfig", () => {
        beforeEach(() => {
            jest.mock("../../src/parameter/get-parameters");
        });
        afterEach(() => jest.clearAllMocks());
        it("returns expected values when properly configured", async () => {
            const expectedParameters = [
                `/${commonStackName}/clients/${clientId}/jwtAuthentication/audience`,
                `/${commonStackName}/clients/${clientId}/jwtAuthentication/issuer`,
                `/${commonStackName}/clients/${clientId}/jwtAuthentication/redirectUri`,
                `/${commonStackName}/clients/${clientId}/jwtAuthentication/publicSigningJwkBase64`,
                `/test-resources/${clientId}/privateSigningKey`,
            ];

            jest.spyOn(GetParameters, "getParametersValues").mockResolvedValueOnce({
                audience,
                issuer,
                redirectUri,
                privateSigningKey: "mock-key",
            });

            const result = await ClientConfiguration.getConfig(clientId);

            expect(GetParameters.getParametersValues).toHaveBeenCalledWith(expectedParameters);
            expect(result).toEqual({
                audience,
                redirectUri,
                issuer,
                privateSigningKey: "mock-key",
            });
        });
    });

    describe("getParametersValues", () => {
        it("returns parameter values when getParametersByName resolves successfully", async () => {
            const mockParameterPaths = [
                "/mock-common-prefix/clients/mock-client-id/jwtAuthentication/audience",
                "/mock-common-prefix/clients/mock-client-id/jwtAuthentication/issuer",
            ];

            const mockParameters = {
                "/mock-common-prefix/clients/mock-client-id/jwtAuthentication/audience": audience,
                "/mock-common-prefix/clients/mock-client-id/jwtAuthentication/issuer": issuer,
            };

            jest.spyOn(SSMPowerToolsParameter, "getParametersByName").mockResolvedValueOnce({
                ...mockParameters,
                _errors: [],
            });

            const result = await GetParameters.getParametersValues(mockParameterPaths);

            expect(SSMPowerToolsParameter.getParametersByName).toHaveBeenCalledWith(
                Object.fromEntries(mockParameterPaths.map((path) => [path, {}])),
                { maxAge: 300, throwOnError: false },
            );
            expect(result).toEqual({
                audience,
                issuer: "mock-issuer",
            });
        });

        it("throws an error when getParametersByName returns errors", async () => {
            const mockParameterPaths = [
                "/mock-common-prefix/clients/mock-client-id/jwtAuthentication/audience",
                "/mock-common-prefix/clients/mock-client-id/jwtAuthentication/issuer",
            ];

            jest.spyOn(SSMPowerToolsParameter, "getParametersByName").mockResolvedValueOnce({
                _errors: ["/mock-common-prefix/clients/mock-client-id/jwtAuthentication/audience"],
            });

            await expect(GetParameters.getParametersValues(mockParameterPaths)).rejects.toThrowError(
                "Following SSM parameters do not exist: /mock-common-prefix/clients/mock-client-id/jwtAuthentication/audience",
            );
        });
    });
});
