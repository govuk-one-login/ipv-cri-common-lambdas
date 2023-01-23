import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

const SESSION_TABLE_NAME_KEY = "SessionTableName";
const DEFAULT_AUTHORIZATION_CODE_TTL_IN_SECS = 600;
const PARAMETER_PREFIX = process.env.AWS_STACK_NAME || "";
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL_IN_SECS || 3600;

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
        const REDIRECT_URI = `clients/ipv-core-stub/jwtAuthentication/redirectUri`;
        const defaultKeys = [SESSION_TABLE_NAME_KEY, REDIRECT_URI];
        const promises = defaultKeys.map((key) => this.getParameter(key));
        return Promise.all(promises);
    }

    public getRedirectUri(clientId: string) {
        if (!clientId) {
            throw new Error("Undefined clientId supplied");
        }
        return this.configEntries.get(`clients/${clientId}/jwtAuthentication/redirectUri`);
    }

    public async getSessionTableName() {
        return await this.getParameter(SESSION_TABLE_NAME_KEY);
    }

    public getAuthorizationCodeExpirationEpoch() {
        // TODO: consider if this should be output in epoch seconds rather than milliseconds
        // so that it is consistent with the java implementation
        return Date.now() + this.authorizationCodeTtlInMillis;
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

    public async getPublicSigningJwk(clientId: string) {
        return await this.getParameter(`clients/${clientId}/jwtAuthentication/publicSigningJwkBase64`);
    }

    public getBearerAccessTokenTtl(): number {
        return Number(ACCESS_TOKEN_TTL);
    }

    public getBearerAccessTokenExpirationEpoch(): number {
        return Math.floor((new Date().getTime() + this.getBearerAccessTokenTtl() * 1000) / 1000);
    }
}
