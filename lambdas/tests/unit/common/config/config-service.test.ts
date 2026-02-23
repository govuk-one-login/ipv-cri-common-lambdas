import { SSMClient } from "@aws-sdk/client-ssm";
import { SSMProvider } from "@aws-lambda-powertools/parameters/ssm";
import { ConfigService } from "../../../../src/common/config/config-service";
import { ClientConfigKey, CommonConfigKey, ConfigKey } from "../../../../src/types/config-keys";

jest.mock("@aws-lambda-powertools/parameters/ssm");

const ssmProvider = jest.mocked(SSMProvider).prototype;
jest.spyOn(ssmProvider, "getParametersByName");

describe("ConfigService", () => {
    const mockUrl = "https://sqs.eu-west-2.amazonaws.com/123456789/txma-infrastructure-AuditEventQueue";
    let ssmClient: SSMClient;
    let configService: ConfigService;

    const mockSessionTable = "sessionTable";
    const mockPersonIdentityTable = "personIdentityTable";
    const mockVcIssuer = "mockVcIssuer";

    beforeEach(() => {
        ssmClient = new SSMClient({});
        configService = new ConfigService(new SSMProvider({ awsSdkV3Client: ssmClient }));

        process.env = {
            ...process.env,
            [CommonConfigKey.SESSION_TABLE_NAME]: mockSessionTable,
            [CommonConfigKey.PERSON_IDENTITY_TABLE_NAME]: mockPersonIdentityTable,
            [CommonConfigKey.VC_ISSUER]: mockVcIssuer,
        };
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe("getSessionExpirationEpoch", () => {
        jest.spyOn(global.Date, "now").mockReturnValue(1675382400000);

        it("should get the session expiration", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                "/di-ipv-cri-oauth-common/SessionTtl": "100",
            });

            await configService.init([CommonConfigKey.SESSION_TTL]);
            const epoch = configService.getSessionExpirationEpoch();
            expect(epoch).toEqual(Math.floor((Date.now() + 100 * 1000) / 1000));
        });
    });

    describe("init", () => {
        it("should initialise the default config", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({});
            await configService.init([CommonConfigKey.SESSION_TTL]);

            expect(ssmProvider.getParametersByName).toBeCalledWith(
                {
                    "/di-ipv-cri-oauth-common/SessionTtl": {},
                },
                expect.objectContaining({
                    maxAge: 300,
                }),
            );
        });

        it("should throw if an environment variable is missing", async () => {
            process.env.SESSION_TABLE = undefined;
            await expect(() => configService.init([CommonConfigKey.SESSION_TABLE_NAME])).rejects.toThrowError(
                `Missing environment variable SESSION_TABLE! Got: undefined`,
            );
        });
    });

    describe("initClientConfig", () => {
        it("should throw an error with no client ID", async () => {
            await expect(
                configService.initClientConfig(undefined as unknown as string, [ClientConfigKey.JWT_ISSUER]),
            ).rejects.toThrowError("Undefined clientId supplied");
        });

        it("should throw an error for an invalid client ID", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                _errors: [],
            });

            await expect(configService.initClientConfig("test", [ClientConfigKey.JWT_ISSUER])).rejects.toThrowError(
                "No client config found. Invalid client id encountered: test",
            );

            expect(ssmProvider.getParametersByName).toBeCalledWith(
                {
                    "/di-ipv-cri-oauth-common/clients/test/jwtAuthentication/issuer": {},
                },
                expect.objectContaining({
                    maxAge: 300,
                }),
            );
        });

        it("should throw an error for invalid parameters", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                _errors: ["invalid-param"],
            });

            await expect(configService.initClientConfig("test", [ClientConfigKey.JWT_ISSUER])).rejects.toThrowError(
                "Couldn't retrieve SSM parameters: invalid-param",
            );

            expect(ssmProvider.getParametersByName).toBeCalledWith(
                {
                    "/di-ipv-cri-oauth-common/clients/test/jwtAuthentication/issuer": {},
                },
                expect.objectContaining({
                    maxAge: 300,
                }),
            );
        });

        it("should successfully initialise the client config", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                "/di-ipv-cri-oauth-common/clients/test/jwtAuthentication/issuer": "test",
            });

            await configService.initClientConfig("test", [ClientConfigKey.JWT_ISSUER]);

            expect(ssmProvider.getParametersByName).toBeCalledWith(
                {
                    "/di-ipv-cri-oauth-common/clients/test/jwtAuthentication/issuer": {},
                },
                expect.objectContaining({
                    maxAge: 300,
                }),
            );
            expect(configService.hasClientConfig("test")).toBe(true);
        });

        it("should fail to initialise the client config when name suffix is empty", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                "": "session-cic-common-cri-api-local",
            });

            await expect(() => configService.initClientConfig("test", [ClientConfigKey.JWT_ISSUER])).rejects.toThrow(
                "NameSuffix may not be a valid string or the parameter is not found in the parameter store",
            );

            expect(configService.hasClientConfig("test")).toBe(false);
        });

        it("should fail to initialise the client config when value is empty", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                "/di-ipv-cri-oauth-common/clients/test/jwtAuthentication/issuer": "",
            });

            await expect(() => configService.initClientConfig("test", [ClientConfigKey.JWT_ISSUER])).rejects.toThrow(
                "The value of the parameter maybe undefined or empty",
            );

            expect(ssmProvider.getParametersByName).toHaveBeenCalledTimes(1);
            expect(configService.hasClientConfig("test")).toBe(false);
        });
    });

    describe("initConfigWithCriIdentifierInPath", () => {
        it("should successfully initialise the client config", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                "/di-ipv-cri-check-hmrc-api/strengthScore": "2",
            });

            await configService.initConfigWithCriIdentifierInPath(
                "test",
                "di-ipv-cri-check-hmrc-api",
                ConfigKey.CRI_EVIDENCE_PROPERTIES,
            );

            expect(ssmProvider.getParametersByName).toBeCalledWith(
                {
                    "/di-ipv-cri-check-hmrc-api/evidence-properties": {},
                },
                expect.objectContaining({
                    maxAge: 300,
                }),
            );
            expect(configService.hasClientConfig("test")).toBe(true);
        });

        it("should handle an empty SSM response due to an invalid client ID", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                _errors: [],
            });

            configService.initConfigWithCriIdentifierInPath(
                "test",
                "di-ipv-cri-check-hmrc-api",
                ConfigKey.CRI_EVIDENCE_PROPERTIES,
            );

            expect(ssmProvider.getParametersByName).toBeCalledWith(
                {
                    "/di-ipv-cri-check-hmrc-api/evidence-properties": {},
                },
                expect.objectContaining({
                    maxAge: 300,
                }),
            );
        });

        it("should handle an SSM response containing errors", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                _errors: ["blah", "blah", "no"],
            });

            configService.initConfigWithCriIdentifierInPath(
                "test",
                "di-ipv-cri-check-hmrc-api",
                ConfigKey.CRI_EVIDENCE_PROPERTIES,
            );

            expect(ssmProvider.getParametersByName).toBeCalledWith(
                {
                    "/di-ipv-cri-check-hmrc-api/evidence-properties": {},
                },
                expect.objectContaining({
                    maxAge: 300,
                }),
            );
        });
    });
    describe("hasClientConfig", () => {
        it("should return true for existing client config", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                "/di-ipv-cri-oauth-common/SessionTableName": "session-cic-common-cri-api-local",
            });

            await configService.initClientConfig("client-id", [ClientConfigKey.JWT_ISSUER]);

            expect(configService.hasClientConfig("client-id")).toBe(true);
        });

        it("should return true for existing client config", () => {
            expect(configService.hasClientConfig("client-id")).toBe(false);
        });
    });

    describe("getClientConfig", () => {
        it("returns the client config if available", async () => {
            ssmProvider.getParametersByName.mockResolvedValue({
                "/di-ipv-cri-oauth-common/SessionTableName": "session-cic-common-cri-api-local",
            });

            await configService.initClientConfig("client-id", [ClientConfigKey.JWT_ISSUER]);

            expect(configService.getClientConfig("client-id")).toEqual(
                new Map([["SessionTableName", "session-cic-common-cri-api-local"]]),
            );
        });

        it("throws no configuration for client id error when config is unavialable", () => {
            expect(() => configService.getClientConfig("client-id")).toThrowError(
                "no configuration for client id client-id",
            );
        });
    });

    describe("getConfigEntry", () => {
        it("should successfully return the config", async () => {
            await configService.init([CommonConfigKey.SESSION_TABLE_NAME]);
            const response = configService.getConfigEntry(CommonConfigKey.SESSION_TABLE_NAME);

            expect(response).toEqual(mockSessionTable);
        });

        it("should throw an error if the parameter is unavailable", async () => {
            expect(() => configService.getConfigEntry(CommonConfigKey.SESSION_TABLE_NAME)).toThrowError(
                "Request for a parameter that was not requested at init: SESSION_TABLE",
            );
        });
    });

    describe("getAuditConfig", () => {
        it("should throw an error if audit event prefix is unavailable", () => {
            expect(() => configService.getAuditConfig()).toThrowError(
                "Missing environment variable: SQS_AUDIT_EVENT_PREFIX",
            );
        });

        it("should throw an error if queue url is unavailable", () => {
            process.env = {
                ...process.env,
                SQS_AUDIT_EVENT_PREFIX: "IPV_ADDRESS_CRI",
            };

            expect(() => configService.getAuditConfig()).toThrowError(
                "Missing environment variable: SQS_AUDIT_EVENT_QUEUE_URL",
            );
        });

        it("should throw an error if the VC config not present", async () => {
            process.env = {
                ...process.env,
                SQS_AUDIT_EVENT_PREFIX: "IPV_ADDRESS_CRI",
                SQS_AUDIT_EVENT_QUEUE_URL: mockUrl,
            };

            ssmProvider.getParametersByName.mockResolvedValue({});
            await configService.init([CommonConfigKey.SESSION_TABLE_NAME]);

            expect(() => configService.getAuditConfig()).toThrowError(
                "Request for a parameter that was not requested at init: VC_ISSUER",
            );
        });

        it("should return the config", async () => {
            // needs the config entries
            process.env = {
                ...process.env,
                SQS_AUDIT_EVENT_PREFIX: "IPV_ADDRESS_CRI",
                SQS_AUDIT_EVENT_QUEUE_URL: mockUrl,
            };

            await configService.init([CommonConfigKey.VC_ISSUER]);

            expect(configService.getAuditConfig()).toEqual({
                auditEventNamePrefix: "IPV_ADDRESS_CRI",
                issuer: mockVcIssuer,
                queueUrl: mockUrl,
            });
        });
    });

    describe("getBearerAccessTokenExpirationEpoch", () => {
        jest.spyOn(Date.prototype, "getTime").mockReturnValue(1675382400000);
        it("should return the ttl of the access token", () => {
            const output = configService.getBearerAccessTokenExpirationEpoch();

            expect(output).toEqual(1675382500);
        });
    });

    describe("getAuthorizationCodeExpirationEpoch", () => {
        it("should get the authorization expiration", () => {
            jest.spyOn(global.Date, "now").mockReturnValue(1675382400000);
            const epoch = configService.getAuthorizationCodeExpirationEpoch();

            expect(epoch).toEqual(1675382500);
        });

        it("should use the default expiration if not available", () => {
            jest.spyOn(global.Date, "now").mockReturnValue(1675382400000);
            process.env.AUTHORIZATION_CODE_TTL = undefined;

            const epoch = configService.getAuthorizationCodeExpirationEpoch();

            expect(epoch).toEqual(1675382500);
        });
    });
});
