import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

const SESSION_TABLE_NAME_KEY = "SessionTableName";
const DEFAULT_AUTHORIZATION_CODE_TTL_IN_SECS = 600;
const PARAMETER_PREFIX = process.env.AWS_STACK_NAME || "";

export class ConfigService {
    private readonly authorizationCodeTtlInMillis: number;
    private readonly configEntries: Map<string, string>;

    constructor(private ssmClient: SSMClient) {
        const envAuthCodeTtl = parseInt(process.env.AUTHORIZATION_CODE_TTL || '', 10);
        this.authorizationCodeTtlInMillis = (Number.isInteger(envAuthCodeTtl)
            ? envAuthCodeTtl
            : DEFAULT_AUTHORIZATION_CODE_TTL_IN_SECS) * 1000;
        this.configEntries = new Map<string, string>();
    }

    public init(): Promise<string[]> {
        const defaultKeys = [SESSION_TABLE_NAME_KEY];
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
        console.log('Before the parameter calll ');
        return await this.getParameter(`clients/${clientId}/jwtAuthentication/redirectUri`);
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
        console.log(`getParameter => key = ${paramName}`);


        const result = (await new SSMClient({ region: "eu-west-2" }).send(new GetParameterCommand({
            Name: paramName
        })))?.Parameter?.Value;

        console.log(`result => result = ${result}`);

        const getParamByNameCommand = new GetParameterCommand({
            Name: paramName
        });
        console.log('Before getParamResult');
        const getParamResult = this.ssmClient.send(getParamByNameCommand)
        .then(result => console.log('This is the then block'+result))
        .catch(error => console.log('ERROR -> '+error));


        console.log(`getParamResult ${getParamResult}`);
        const value = getParamResult?.Parameter?.Value;

        if (!value) {
            throw new Error(`Could not retrieve SSM Parameter - ${key}`);
        } else {
            this.configEntries.set(key, value);
        }

        return value;
    }
}