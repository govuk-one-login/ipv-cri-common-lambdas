import { SQSClient } from "@aws-sdk/client-sqs";
import { fromEnv } from "@aws-sdk/credential-providers";

export const SqsClient = new SQSClient({ region: process.env["AWS_REGION"], credentials: fromEnv() });
