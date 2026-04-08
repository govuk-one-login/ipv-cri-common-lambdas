import { ClientConfiguration } from "../../src/services/client-configuration";
import { getParametersValues } from "../../src/parameter/get-parameters";
import { vi, describe, expect, it } from "vitest";

vi.mock("../../src/parameter/get-parameters", () => ({
    getParametersValues: vi.fn(),
}));

const mockGetParamatersValues = vi.mocked(getParametersValues);
const commonStackName = "mock-common-prefix";
const issuer = "mock-issuer";
const clientId = "headless-core-stub";
const audience = "my-audience";
const redirectUri = "https://test-resources.headless-core-stub.redirect/callback";

describe("getConfig", () => {
    beforeEach(() => {
        process.env = {
            ...process.env,
            COMMON_STACK_NAME: commonStackName,
        };
        vi.clearAllMocks();
    });
    it("returns expected values when properly configured", async () => {
        const expectedParameters = [
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/audience`,
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/issuer`,
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/redirectUri`,
            `/${commonStackName}/clients/${clientId}/jwtAuthentication/publicSigningJwkBase64`,
            `/test-resources/${clientId}/privateSigningKey`,
        ];

        mockGetParamatersValues.mockResolvedValueOnce({
            audience,
            issuer,
            redirectUri,
            privateSigningKey: "mock-key",
        });

        const result = await ClientConfiguration.getConfig(clientId);

        expect(mockGetParamatersValues).toHaveBeenCalledWith(expectedParameters);
        expect(result).toEqual({
            audience,
            redirectUri,
            issuer,
            privateSigningKey: "mock-key",
        });
    });
});
