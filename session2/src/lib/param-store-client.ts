import { SSMClient } from "@aws-sdk/client-ssm";
import { fromEnv } from "@aws-sdk/credential-providers";

export const SsmClient = new SSMClient({ region: process.env["AWS_REGION"], credentials: fromEnv() });
