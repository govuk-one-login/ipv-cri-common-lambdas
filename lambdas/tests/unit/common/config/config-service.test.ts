import { GetParametersCommand, ParameterType, SSMClient } from "@aws-sdk/client-ssm";
import { ClientConfigKey, CommonConfigKey } from "../../../../src/types/config-keys";
import { ConfigService } from "../../../../src/common/config/config-service";

const getMockSend = (key: CommonConfigKey, value?: string) => {
    const mockPromise = new Promise<any>((resolve, reject) => {
        resolve({
            Parameters: [{
                Name: `/di-ipv-cri-common-lambdas/${key}`,
                Type: ParameterType.STRING,
                Value: value ? value : "session-cic-common-cri-api-local"
            }]
        })
    });
    const mockSend = jest.fn();
    mockSend.mockImplementation(() => {
        return mockPromise;
    });
    return mockSend;
}

jest.mock("@aws-sdk/client-ssm", () => {
    return {
        __esModule: true,
        ...jest.requireActual("@aws-sdk/client-ssm"),
        GetParametersCommand: jest.fn(),
        SSMClient: {
            prototype: {
                send: jest.fn()
            }
        }
    };
}); //  this is so we only mock out the GetParametersCommand

describe("ConfigService", () => {
    let configService: ConfigService;

    const mockUrl = "https://sqs.eu-west-2.amazonaws.com/123456789/txma-infrastructure-AuditEventQueue"

    const mockSsmClient = jest.mocked(SSMClient);
    mockSsmClient.prototype.send = getMockSend(CommonConfigKey.SESSION_TABLE_NAME);
    
    const mockGetParametersCommand = jest.mocked(GetParametersCommand);

    beforeEach(() => {
        jest.clearAllMocks();
        
        configService = new ConfigService(mockSsmClient.prototype);
    });
    
    describe("init", () => {
        it("should initialise the default config", async () => {
            await configService.init([
                CommonConfigKey.SESSION_TABLE_NAME
            ]);

            expect(mockGetParametersCommand).toBeCalledWith({
                Names: ["/di-ipv-cri-common-lambdas/SessionTableName"]
            });
        });
    });

    describe("initClientConfig", () => {
        it("should throw an error with no client ID", async () => {
            await expect(
                // @ts-ignore to allow an incorrect value to be entered
                configService.initClientConfig(undefined, ClientConfigKey.JWT_ISSUER)
            ).rejects.toThrowError("Undefined clientId supplied");
        });

        it("should throw an error for an invalid client ID", async () => {
            const mockPromise = new Promise<any>((resolve, reject) => {
                resolve({
                    Parameters: []
                })
            });
            mockSsmClient.prototype.send.mockImplementation(() => {
                return mockPromise;
            });
            await expect(
                configService.initClientConfig("test", [ClientConfigKey.JWT_ISSUER])
            ).rejects.toThrowError("No client config found. Invalid client id encountered: test");
            expect(mockGetParametersCommand).toHaveBeenCalledWith({
                Names: ["/di-ipv-cri-common-lambdas/clients/test/jwtAuthentication/issuer"]
            })
            expect(mockSsmClient.prototype.send).toHaveBeenCalledTimes(1);
        });

        it("should throw an error for invalid parameters", async () => {
            const mockPromise = new Promise<any>((resolve, reject) => {
                resolve({
                    Parameters: [],
                    InvalidParameters: ["invalid-param"]
                })
            });
            mockSsmClient.prototype.send.mockImplementation(() => {
                return mockPromise;
            });
            await expect(
                configService.initClientConfig("test", [ClientConfigKey.JWT_ISSUER])
            ).rejects.toThrowError("Invalid SSM parameters: invalid-param");

        });

        it("should successfully initialise the client config", async () => {
            mockSsmClient.prototype.send = getMockSend(CommonConfigKey.SESSION_TABLE_NAME);
            await configService.initClientConfig("test", [ClientConfigKey.JWT_ISSUER]);
            expect(mockGetParametersCommand).toHaveBeenCalledWith({
                Names: ["/di-ipv-cri-common-lambdas/clients/test/jwtAuthentication/issuer"]
            })
            expect(mockSsmClient.prototype.send).toHaveBeenCalledTimes(1);

            expect(configService.hasClientConfig("test")).toBe(true);
        });
    });

    describe("hasClientConfig", () => {
        it("should return true for existing client config", async () => {
            await configService.initClientConfig("client-id", [ClientConfigKey.JWT_ISSUER]);
            expect(configService.hasClientConfig("client-id")).toBe(true);
        });

        it("should return true for existing client config", () => {
            expect(configService.hasClientConfig("client-id")).toBe(false);
        });
    });

    describe("getClientConfig", () => {
        it("returns the client config if available", async () => {
            await configService.initClientConfig("client-id", [ClientConfigKey.JWT_ISSUER]);
            const mockMap = new Map<string, string>();
            mockMap.set("SessionTableName", "session-cic-common-cri-api-local")
            expect(configService.getClientConfig("client-id")).toEqual(mockMap);
        });

        it("returns undefined if client config is available", () => {
            expect(configService.getClientConfig("client-id")).toBe(undefined);
        })
    });

    describe("getConfigEntry", () => {
        it("should successfully return the config", async () => {
            await configService.init([
                CommonConfigKey.SESSION_TABLE_NAME
            ]);
            const response = configService.getConfigEntry(CommonConfigKey.SESSION_TABLE_NAME);
            expect(response).toEqual("session-cic-common-cri-api-local");
        });

        it("should throw an error if the parameter is unavailable", async () => {
            expect(() => configService.getConfigEntry(CommonConfigKey.SESSION_TABLE_NAME)).toThrowError("Missing SSM parameter /di-ipv-cri-common-lambdas/SessionTableName");
        });
    });

    describe("getAuditConfig", () => {
        it("should throw an error if audit event prefix is unavailable", () => {
            expect(() => configService.getAuditConfig()).toThrowError(
                "Missing environment variable: SQS_AUDIT_EVENT_PREFIX"
            );
        });

        it("should throw an error if queue url is unavailable", () => {
            process.env = {
                ...process.env,
                SQS_AUDIT_EVENT_PREFIX: "IPV_ADDRESS_CRI"
            };
            expect(() => configService.getAuditConfig()).toThrowError(
                "Missing environment variable: SQS_AUDIT_EVENT_QUEUE_URL"
            );
        });

        it("should throw an error if the VC config not present", async () => {
            process.env = {
                ...process.env,
                SQS_AUDIT_EVENT_PREFIX: "IPV_ADDRESS_CRI",
                SQS_AUDIT_EVENT_QUEUE_URL: mockUrl
            };
            await configService.init([
                CommonConfigKey.SESSION_TABLE_NAME
            ]);
            expect(() => configService.getAuditConfig()).toThrowError(
                "Missing SSM parameter /di-ipv-cri-common-lambdas/verifiable-credential/issuer"
            );
        });

        it("should return the config", async () => {
            // needs the config entries
            process.env = {
                ...process.env,
                SQS_AUDIT_EVENT_PREFIX: "IPV_ADDRESS_CRI",
                SQS_AUDIT_EVENT_QUEUE_URL: mockUrl
            };
            mockSsmClient.prototype.send = getMockSend(CommonConfigKey.VC_ISSUER);
            await configService.init([
                CommonConfigKey.VC_ISSUER
            ]);
            expect(configService.getAuditConfig()).toEqual({
                auditEventNamePrefix: "IPV_ADDRESS_CRI",
                issuer: "session-cic-common-cri-api-local",
                queueUrl: mockUrl
            })
        });
    });

    describe("getSessionExpirationEpoch", () => {
        jest.spyOn(global.Date, 'now').mockReturnValueOnce(1675382400000);
        it("should get the session expiration", async () => {
            mockSsmClient.prototype.send = getMockSend(CommonConfigKey.SESSION_TTL, "100");
            await configService.init([
                CommonConfigKey.SESSION_TABLE_NAME
            ]);
            const epoch = configService.getSessionExpirationEpoch();
            expect(epoch).toEqual(1675382500000);
        });
    });

    describe("getBearerAccessTokenExpirationEpoch", () => {
        jest.spyOn(Date.prototype, "getTime").mockReturnValueOnce(1675382400000);
        it("should return the ttl of the access token", () => {
            const output = configService.getBearerAccessTokenExpirationEpoch();
            expect(output).toEqual(1675382500);
        });
    });

    describe("getAuthorizationCodeExpirationEpoch", () => {
        it("should get the authorization expiration", () => {
            jest.spyOn(global.Date, 'now').mockReturnValueOnce(1675382400000);
            const epoch = configService.getAuthorizationCodeExpirationEpoch();
            expect(epoch).toEqual(1675382500000);
        });

        it("should use the default expiration if not available", () => {
            jest.spyOn(global.Date, 'now').mockReturnValueOnce(1675382400000);
            process.env.AUTHORIZATION_CODE_TTL = undefined;
            configService = new ConfigService(mockSsmClient.prototype);
            const epoch = configService.getAuthorizationCodeExpirationEpoch();
            expect(epoch).toEqual(1675383000000);
        });
    });
});