import { ConfigurationHelper } from "../../src/services/configuration-helper";
import * as SSMPowerToolsParameter from "@aws-lambda-powertools/parameters/ssm";
import * as GetParameters from "../../src/services/get-parameters";
jest.mock("@aws-lambda-powertools/parameters/ssm");

describe("ConfigurationHelper", () => {
    const commonParameterPrefix = "mock-common-prefix";
    const testResourcesParameterPrefix = "mock-test-resources-prefix";
    const issuer = "mock-issuer";
    const clientId = "headless-core-stub";
    const audience = "my-audience";
    const redirectUri = "https://test-resources.headless-core-stub.redirect/callback";

    beforeEach(() => {
        process.env = {
            ...process.env,
            AWS_STACK_NAME: commonParameterPrefix,
            TEST_RESOURCES_STACK_NAME: testResourcesParameterPrefix,
        };
        jest.clearAllMocks();
    });

    describe("getParameters", () => {
        beforeEach(() => {
            jest.mock("../../src/services/get-parameters");
        });
        afterEach(() => jest.clearAllMocks());
        it("generates correct parameter paths and calls getParametersValues", async () => {
            const expectedParameters = [
                `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/audience`,
                `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/issuer`,
                `/${commonParameterPrefix}/clients/${clientId}/jwtAuthentication/redirectUri`,
                `/${testResourcesParameterPrefix}/${clientId}/privateSigningKey`,
            ];

            jest.spyOn(GetParameters, "getParametersValues").mockResolvedValueOnce({
                audience,
                issuer,
                redirectUri,
                privateSigningKey: "mock-key",
            });

            const configurationHelper = new ConfigurationHelper();

            const result = await configurationHelper.getParameters(clientId);

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
