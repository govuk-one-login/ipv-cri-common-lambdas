import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

enum SsmParamNames {
    PERSON_IDENTITY_TABLE_NAME = "PersonIdentityTableName",
    SESSION_TABLE_NAME = "SessionTableName",
    SESSION_TTL = "SessionTtl",
    DECRYPTION_KEY_ID = "AuthRequestKmsEncryptionKeyId",
    VC_ISSUER = "verifiable-credential/issuer"
}
// const PERSON_IDENTITY_TABLE_NAME_KEY = "PersonIdentityTableName";
// const SESSION_TABLE_NAME_KEY = "SessionTableName";
// const SESSION_TTL_KEY = "SessionTtl";
// const DECRYPTION_KEY_ID_KEY = "AuthRequestKmsEncryptionKeyId";
// const VC_ISSUER_KEY = "verifiable-credential/issuer";

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

    public init(): Promise<string[]> {
        const defaultKeys = [
            SsmParamNames.SESSION_TABLE_NAME,
            SsmParamNames.SESSION_TTL,
            SsmParamNames.PERSON_IDENTITY_TABLE_NAME,
            SsmParamNames.DECRYPTION_KEY_ID,
            SsmParamNames.VC_ISSUER
        ];
        const promises = [];
        for (const key of defaultKeys) {
            promises.push(this.getParameter(key));
        }

        return Promise.all(promises);
    }

    public async getRedirectUri(clientId: string) {
        if (!clientId) {
            throw new Error("Undefined clientId supplied");
        }
        return await this.getParameter(`clients/${clientId}/jwtAuthentication/redirectUri`);
    }

    public async getSessionTableName() {
        return await this.getParameter(SsmParamNames.SESSION_TABLE_NAME);
    }

    public async getKmsDecryptionKeyId() {
        return await this.getParameter(SsmParamNames.DECRYPTION_KEY_ID);
    }

    public getAuthorizationCodeExpirationEpoch() {
        // TODO: consider if this should be output in epoch seconds rather than milliseconds
        // so that it is consistent with the java implementation
        return Date.now() + this.authorizationCodeTtlInMillis;
    }

    public getSessionExpirationEpoch() {
        return 0; // TODO: complete implementation
    }

    private async getParameter(key: string): Promise<string> {
        if (this.configEntries.has(key)) {
            return this.configEntries.get(key) as string;
        }

        const paramName = `/${PARAMETER_PREFIX}/${key}`;
        const getParamByNameCommand = new GetParameterCommand({
            Name: paramName,
        });

        const getParamResult = await this.ssmClient.send(getParamByNameCommand);
        const value = getParamResult?.Parameter?.Value;

        if (!value) {
            throw new Error(`Could not retrieve SSM Parameter - ${key}`);
        } else {
            this.configEntries.set(key, value);
        }

        return value;
    }
}
