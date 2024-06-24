import { SSMClient } from "@aws-sdk/client-ssm";
import { Parameter } from "aws-sdk/clients/ssm";
import { CriAuditConfig } from "../../types/cri-audit-config";
import { ClientConfigKey, CommonConfigKey } from "../../types/config-keys";
import { SSMProvider } from "@aws-lambda-powertools/parameters/ssm";
import { logger } from "../utils/power-tool";

const AWS_STACK_NAME_PREFIX = process.env.AWS_STACK_NAME || "";
const AUTHORIZATION_CODE_TTL = parseNumber(process.env.AUTHORIZATION_CODE_TTL) || 600;
const PARAMETER_TTL = parseNumber(process.env.POWERTOOLS_PARAMETERS_MAX_AGE) || 300;
const ACCESS_TOKEN_TTL = parseNumber(process.env.ACCESS_TOKEN_TTL_IN_SECS) || 3600;

export class ConfigService {
    private readonly configEntries = new Map<string, string>();
    private readonly clientConfigurations = new Map<string, Map<string, string>>();
    private readonly ssmProvider: SSMProvider;

    constructor(ssmClient: SSMClient) {
        this.ssmProvider = new SSMProvider({ awsSdkV3Client: ssmClient });
    }

    public init(keys: CommonConfigKey[]): Promise<void> {
        return this.getDefaultConfig(keys);
    }

    public async initClientConfig(clientId: string, paramNameSuffixes: ClientConfigKey[]) {
        const parameterPrefix = `clients/${clientId}/jwtAuthentication`;
        if (!clientId) {
            throw new Error("Undefined clientId supplied");
        }
        const ssmParamNames: string[] = paramNameSuffixes.map((paramNameSuffix) => {
            return this.getParameterName(`${parameterPrefix}/${paramNameSuffix}`);
        });
        const ssmParameters = await this.getParameters(ssmParamNames);
        if (ssmParameters.length === 0) {
            throw new Error(`No client config found. Invalid client id encountered: ${clientId}`);
        }
        await this.setParametersByAbsolutePath(ssmParameters, clientId);
    }

    public async initConfigWithCriIdentifierInPath(clientId: string, parameterPrefix: string, paramNameSuffix: string) {
        const ssmParameters = await this.getCriIdentifierParameters([`/${parameterPrefix}/${paramNameSuffix}`]);
        if (ssmParameters.length === 0) {
            logger.info(`Invalid parameter beginning with ${parameterPrefix} encountered`);
            return;
        }
        await this.setParametersByAbsolutePath(ssmParameters, clientId);
    }

    private async setParametersByAbsolutePath(ssmParameters: Parameter[], identifier: string) {
        const clientConfigEntries: Map<string, string> =
            this.clientConfigurations.get(identifier) || new Map<string, string>();

        ssmParameters.forEach(({ Name, Value }) => {
            clientConfigEntries.set(...this.validateNameSuffix(Name, Value));
        });

        this.clientConfigurations.set(identifier, clientConfigEntries);
    }

    public hasClientConfig(clientId: string): boolean {
        return this.clientConfigurations.has(clientId);
    }

    public getClientConfig(clientId: string): Map<string, string> {
        if (!this.clientConfigurations.get(clientId)) {
            throw new Error(`no configuration for client id ${clientId}`);
        }
        return this.clientConfigurations.get(clientId) as Map<string, string>;
    }

    public getConfigEntry(key: CommonConfigKey) {
        const paramName = `/${AWS_STACK_NAME_PREFIX}/${key}`;
        if (!this.configEntries.has(paramName)) {
            throw new Error(`Missing SSM parameter ${paramName}`);
        }
        return this.configEntries.get(paramName) as string;
    }

    public getAuditConfig(): CriAuditConfig {
        const auditEventNamePrefix = process.env.SQS_AUDIT_EVENT_PREFIX;
        if (!auditEventNamePrefix) {
            throw new Error("Missing environment variable: SQS_AUDIT_EVENT_PREFIX");
        }
        const queueUrl = process.env["SQS_AUDIT_EVENT_QUEUE_URL"];
        if (!queueUrl) {
            throw new Error("Missing environment variable: SQS_AUDIT_EVENT_QUEUE_URL");
        }
        const issuer = this.getConfigEntry(CommonConfigKey.VC_ISSUER);
        return {
            auditEventNamePrefix,
            issuer,
            queueUrl,
        };
    }

    public getAuthorizationCodeExpirationEpoch() {
        return Math.floor((Date.now() + AUTHORIZATION_CODE_TTL * 1000) / 1000);
    }

    public getSessionExpirationEpoch() {
        const sessionTtl = parseInt(this.getConfigEntry(CommonConfigKey.SESSION_TTL), 10);
        return Math.floor((Date.now() + sessionTtl * 1000) / 1000);
    }

    public getBearerAccessTokenTtl() {
        return ACCESS_TOKEN_TTL;
    }

    public getBearerAccessTokenExpirationEpoch(): number {
        return Math.floor((Date.now() + this.getBearerAccessTokenTtl() * 1000) / 1000);
    }

    private getParameterName(parameterNameSuffix: string) {
        return `/${AWS_STACK_NAME_PREFIX}/${parameterNameSuffix}`;
    }

    private validateNameSuffix(nameSuffix?: string, nameSuffixValue?: string): [string, string] {
        const name = nameSuffix?.split("/").pop();
        const value = nameSuffixValue;
        if (!name) {
            throw Error("NameSuffix may not be a valid string or the parameter is not found in the parameter store");
        }
        if (!value) {
            throw Error("The value of the parameter maybe undefined or empty");
        }
        return [name, value];
    }

    private async getDefaultConfig(paramNameSuffixes: CommonConfigKey[]): Promise<void> {
        const ssmParamNames = paramNameSuffixes.map((p) => this.getParameterName(p));
        const ssmParameters = await this.getParameters(ssmParamNames);
        ssmParameters?.forEach((p) => this.configEntries.set(p.Name as string, p.Value as string));
    }

    private async getCriIdentifierParameters(ssmParamNames: string[]): Promise<Parameter[]> {
        const { _errors: errors, ...parameters } = await this.ssmProvider.getParametersByName<string>(
            Object.fromEntries(ssmParamNames.map((parameter) => [parameter, {}])),
            { maxAge: PARAMETER_TTL, throwOnError: false },
        );
        if (errors?.length) {
            logger.info(`Couldn't retrieve SSM parameters: ${errors.join(", ")}`);
            return Promise.resolve([]);
        }

        return Object.entries(parameters).map(([name, value]) => ({ Name: name, Value: value }));
    }

    private async getParameters(ssmParamNames: string[]): Promise<Parameter[]> {
        const { _errors: errors, ...parameters } = await this.ssmProvider.getParametersByName<string>(
            Object.fromEntries(ssmParamNames.map((parameter) => [parameter, {}])),
            { maxAge: PARAMETER_TTL, throwOnError: false },
        );
        if (errors?.length) {
            throw new Error(`Couldn't retrieve SSM parameters: ${errors.join(", ")}`);
        }

        return Object.entries(parameters).map(([name, value]) => ({ Name: name, Value: value }));
    }
}

function parseNumber(value?: string) {
    return parseInt(value || "", 10) || undefined;
}
