import { SSMClient } from "@aws-sdk/client-ssm";
import { fromEnv } from "@aws-sdk/credential-providers";
import { SQSClient } from "@aws-sdk/client-sqs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { KMSClient } from "@aws-sdk/client-kms";

const awsRegion = process.env["AWS_REGION"];

export const enum AwsClientType {
    DYNAMO,
    SQS,
    SSM,
    KMS,
}

type AwsClient<Client extends AwsClientType> = Client extends AwsClientType.DYNAMO
    ? DynamoDBDocument
    : Client extends AwsClientType.SQS
    ? SQSClient
    : Client extends AwsClientType.SSM
    ? SSMClient
    : Client extends AwsClientType.KMS
    ? KMSClient
    : undefined;

export function createClient<ClientType extends AwsClientType>(clientType: ClientType): AwsClient<ClientType> {
    switch (clientType) {
        case AwsClientType.SQS:
            return new SQSClient({ region: awsRegion, credentials: fromEnv() }) as AwsClient<ClientType>;
        case AwsClientType.SSM:
            return new SSMClient({ region: awsRegion, credentials: fromEnv() }) as AwsClient<ClientType>;
        case AwsClientType.DYNAMO:
            return createDynamoDbClient() as AwsClient<ClientType>;
        case AwsClientType.KMS:
            return new KMSClient({ region: awsRegion, credentials: fromEnv() }) as AwsClient<ClientType>;
        default:
            throw new Error(`Unexpected aws client type encountered: ${clientType}`);
    }
}

const createDynamoDbClient = () => {
    const marshallOptions = {
        // Whether to automatically convert empty strings, blobs, and sets to `null`.
        convertEmptyValues: false,
        // Whether to remove undefined values while marshalling.
        removeUndefinedValues: true,
        // Whether to convert typeof object to map attribute.
        convertClassInstanceToMap: true,
    };
    const unmarshallOptions = {
        // Whether to return numbers as a string instead of converting them to native JavaScript numbers.
        wrapNumbers: false,
    };
    const translateConfig = { marshallOptions, unmarshallOptions };
    const dbClient = new DynamoDBClient({ region: awsRegion, credentials: fromEnv() });
    return DynamoDBDocument.from(dbClient, translateConfig);
};
