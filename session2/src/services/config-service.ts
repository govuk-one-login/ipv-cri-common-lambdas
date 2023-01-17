import { SSMClient, GetParameterCommand, GetParametersCommand } from "@aws-sdk/client-ssm";

enum SsmParamNames {
    PERSON_IDENTITY_TABLE_NAME = "PersonIdentityTableName",
    SESSION_TABLE_NAME = "SessionTableName",
    SESSION_TTL = "SessionTtl",
    DECRYPTION_KEY_ID = "AuthRequestKmsEncryptionKeyId",
    VC_ISSUER = "verifiable-credential/issuer",
}

const DEFAULT_AUTHORIZATION_CODE_TTL_IN_SECS = 600;
const PARAMETER_PREFIX = process.env.AWS_STACK_NAME || "";

export class ConfigService {
    private readonly authorizationCodeTtlInMillis: number;
    private readonly configEntries: Map<string, string>;

    constructor(private ssmClient: SSMClient) {
        const envAuthCodeTtl = parseInt(process.env.AUTHORIZATION_CODE_TTL || "", 10);
        this.authorizationCodeTtlInMillis =
            (Number.isInteger(envAuthCodeTtl) ? envAuthCodeTtl : DEFAULT_AUTHORIZATION_CODE_TTL_IN_SECS) * 1000;
        this.configEntries = new Map<string, string>();
    }

    public init(): Promise<void> {
        const defaultKeys = [
            SsmParamNames.SESSION_TABLE_NAME,
            SsmParamNames.SESSION_TTL,
            SsmParamNames.PERSON_IDENTITY_TABLE_NAME,
            SsmParamNames.DECRYPTION_KEY_ID,
            SsmParamNames.VC_ISSUER,
        ];
        return this.getParameters(defaultKeys);
    }

    public getSqsQueueUrl(): string {
        if (!process.env["SQS_AUDIT_EVENT_QUEUE_URL"]) {
            throw new Error("Missing environment variable: SQS_AUDIT_EVENT_QUEUE_URL");
        }
        return process.env["SQS_AUDIT_EVENT_QUEUE_URL"] as string;
    }

    public getAuditEventNamePrefix() {
        if (!process.env["SQS_AUDIT_EVENT_PREFIX"]) {
            throw new Error("Missing environment variable: SQS_AUDIT_EVENT_PREFIX");
        }
        return process.env["SQS_AUDIT_EVENT_PREFIX"] as string;
    }

    public async getJwtIssuer(clientId: string) {
        if (!clientId) {
            throw new Error("Undefined clientId supplied");
        }
        return await this.getParameter(`clients/${clientId}/jwtAuthentication/issuer`);
    }

    public async getJwtAudience(clientId: string) {
        if (!clientId) {
            throw new Error("Undefined clientId supplied");
        }
        return await this.getParameter(`clients/${clientId}/jwtAuthentication/audience`);
    }

    public async getJwtSigningAlgorithm(clientId: string) {
        if (!clientId) {
            throw new Error("Undefined clientId supplied");
        }
        return await this.getParameter(`clients/${clientId}/jwtAuthentication/authenticationAlg`);
    }

    public async getJwtRedirectUri(clientId: string) {
        if (!clientId) {
            throw new Error("Undefined clientId supplied");
        }
        return await this.getParameter(`clients/${clientId}/jwtAuthentication/redirectUri`);
    }

    public async getPublicSigningJwk(clientId: string) {
        return await this.getParameter(`clients/${clientId}/jwtAuthentication/publicSigningJwkBase64`);
    }

    private getConfigEntry(key: SsmParamNames) {
        const paramName = `/${PARAMETER_PREFIX}/${key}`;
        if (!this.configEntries.has(paramName)) {
            throw new Error(`Missing SSM parameter ${paramName}`);
        }
        return this.configEntries.get(paramName) as string;
    }

    public getVerifiableCredentialIssuer(): string {
        return this.getConfigEntry(SsmParamNames.VC_ISSUER);
    }

    public getSessionTableName() {
        return this.getConfigEntry(SsmParamNames.SESSION_TABLE_NAME);
    }

    public getPersonIdentityTableName() {
        return this.getConfigEntry(SsmParamNames.PERSON_IDENTITY_TABLE_NAME);
    }

    public getKmsDecryptionKeyId() {
        return this.getConfigEntry(SsmParamNames.DECRYPTION_KEY_ID);
    }

    public getAuthorizationCodeExpirationEpoch() {
        // TODO: consider if this should be output in epoch seconds rather than milliseconds
        // so that it is consistent with the java implementation
        return Date.now() + this.authorizationCodeTtlInMillis;
    }

    public getSessionExpirationEpoch() {
        const sessionTtl = this.getConfigEntry(SsmParamNames.SESSION_TTL);
        return Date.now() + parseInt(sessionTtl, 10) * 1000;
    }

    private async getParameter(key: string): Promise<string> {
        const paramName = `/${PARAMETER_PREFIX}/${key}`;
        if (this.configEntries.has(paramName)) {
            return this.configEntries.get(paramName) as string;
        }

        const getParamByNameCommand = new GetParameterCommand({
            Name: paramName,
        });

        const getParamResult = await this.ssmClient.send(getParamByNameCommand);
        const value = getParamResult?.Parameter?.Value;

        if (!value) {
            throw new Error(`Could not retrieve SSM Parameter - ${key}`);
        } else {
            this.configEntries.set(paramName, value);
        }

        return value;
    }
    private async getParameters(keys: string[]): Promise<void> {
        const getParamsByNameCommand = new GetParametersCommand({
            Names: keys.map((k) => `/${PARAMETER_PREFIX}/${k}`),
        });

        const getParamsResult = await this.ssmClient.send(getParamsByNameCommand);

        getParamsResult.Parameters?.forEach((p) => {
            if (p.Name && p.Value) {
                this.configEntries.set(p.Name as string, p.Value as string);
            } else {
                console.log(`Parameter name (${p.Name}) or value (${p.Value}) is undefined/null/empty`);
            }
        }, this);

        if (getParamsResult.InvalidParameters && getParamsResult.InvalidParameters.length) {
            const invalidParameterNames = getParamsResult.InvalidParameters?.join(", ");
            console.log(`Invalid SSM parameters: ${invalidParameterNames}`);
            throw new Error(`Could not retrieve all SSM Parameters for keys: ${keys.join(", ")}`);
        }
    }
}
