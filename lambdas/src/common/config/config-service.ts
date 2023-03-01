import { SSMClient, GetParametersCommand } from "@aws-sdk/client-ssm";
import { Parameter } from "aws-sdk/clients/ssm";
import { CriAuditConfig } from "../../types/cri-audit-config";
import { ClientConfigKey, CommonConfigKey } from "../../types/config-keys";

const DEFAULT_AUTHORIZATION_CODE_TTL_IN_SECS = 600;
const PARAMETER_PREFIX = process.env.AWS_STACK_NAME || "";
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL_IN_SECS || 3600;

export class ConfigService {
    private readonly authorizationCodeTtlInMillis: number;
    private readonly configEntries: Map<string, string>;
    private readonly clientConfigurations: Map<string, Map<string, string>>;

    constructor(private ssmClient: SSMClient) {
        const envAuthCodeTtl = parseInt(process.env.AUTHORIZATION_CODE_TTL || "", 10);
        this.authorizationCodeTtlInMillis =
            (Number.isInteger(envAuthCodeTtl) ? envAuthCodeTtl : DEFAULT_AUTHORIZATION_CODE_TTL_IN_SECS) * 1000;
        this.configEntries = new Map<string, string>();
        this.clientConfigurations = new Map<string, Map<string, string>>();
    }

    public init(keys: CommonConfigKey[]): Promise<void> {
        return this.getDefaultConfig(keys);
    }

    public async initClientConfig(clientId: string, paramNameSuffixes: ClientConfigKey[]) {
        if (!clientId) {
            throw new Error("Undefined clientId supplied");
        }
        const ssmParamNames: string[] = paramNameSuffixes.map((paramNameSuffix) => {
            return this.getParameterName(`clients/${clientId}/jwtAuthentication/${paramNameSuffix}`);
        });
        const ssmParameters = await this.getParameters(ssmParamNames);
        if (ssmParameters.length === 0) {
            throw new Error(`No client config found. Invalid client id encountered: ${clientId}`);
        }
        const clientConfigEntries: Map<string, string> = new Map<string, string>();
        ssmParameters.forEach((p) => {
            clientConfigEntries.set(p.Name!.substring(p.Name!.lastIndexOf("/") + 1), p.Value!);
        });
        this.clientConfigurations.set(clientId, clientConfigEntries);
    }

    public hasClientConfig(clientId: string): boolean {
        return this.clientConfigurations.has(clientId);
    }

    public getClientConfig(clientId: string): Map<string, string> | undefined {
        return this.clientConfigurations.get(clientId);
    }

    public getConfigEntry(key: CommonConfigKey) {
        const paramName = `/${PARAMETER_PREFIX}/${key}`;
        if (!this.configEntries.has(paramName)) {
            throw new Error(`Missing SSM parameter ${paramName}`);
        }
        return this.configEntries.get(paramName) as string;
    }

    public getAuditConfig(): CriAuditConfig {
        const auditEventNamePrefix = process.env["SQS_AUDIT_EVENT_PREFIX"];
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
        return Math.floor((Date.now() + this.authorizationCodeTtlInMillis) / 1000);
    }

    public getSessionExpirationEpoch() {
        const sessionTtl = this.getConfigEntry(CommonConfigKey.SESSION_TTL);
        return Math.floor((Date.now() + parseInt(sessionTtl, 10) * 1000) / 1000);
    }

    public getBearerAccessTokenTtl(): number {
        return Number(ACCESS_TOKEN_TTL);
    }

    public getBearerAccessTokenExpirationEpoch(): number {
        return Math.floor((Date.now() + this.getBearerAccessTokenTtl() * 1000) / 1000);
    }

    private getParameterName(parameterNameSuffix: string) {
        return `/${PARAMETER_PREFIX}/${parameterNameSuffix}`;
    }

    private async getDefaultConfig(paramNameSuffixes: CommonConfigKey[]): Promise<void> {
        const ssmParamNames = paramNameSuffixes.map((p) => this.getParameterName(p));
        const ssmParameters = await this.getParameters(ssmParamNames);
        if (ssmParameters && ssmParameters.length) {
            ssmParameters?.forEach((p) => {
                this.configEntries.set(p.Name as string, p.Value as string);
            }, this);
        }
    }

    private async getParameters(ssmParamNames: string[]): Promise<Parameter[]> {
        const getParamsByNameCommand = new GetParametersCommand({ Names: ssmParamNames });

        const getParamsResult = await this.ssmClient.send(getParamsByNameCommand);

        if (getParamsResult.InvalidParameters && getParamsResult.InvalidParameters.length) {
            const invalidParameterNames = getParamsResult.InvalidParameters?.join(", ");
            throw new Error(`Invalid SSM parameters: ${invalidParameterNames}`);
        }

        return getParamsResult.Parameters && getParamsResult.Parameters.length ? getParamsResult.Parameters : [];
    }
}
