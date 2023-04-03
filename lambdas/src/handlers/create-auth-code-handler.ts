import { SSMClient } from "@aws-sdk/client-ssm";
import { DynamoDBDocument, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { randomUUID } from "crypto";
import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { AwsClientType, createClient } from "../common/aws-client-factory";
import { ConfigService } from "../common/config/config-service";
import { getSessionId } from "../common/utils/request-utils";
import { CommonConfigKey } from "../types/config-keys";
import { Logger } from "@aws-lambda-powertools/logger";
import { errorPayload } from "../common/utils/errors";

const dynamoDbClient = createClient(AwsClientType.DYNAMO) as DynamoDBDocument;
const ssmClient = createClient(AwsClientType.SSM) as SSMClient;
const logger = new Logger();
const configService = new ConfigService(ssmClient);
const initPromise = configService.init([CommonConfigKey.SESSION_TABLE_NAME]);

export class CreateAuthCodeLambda implements LambdaInterface {
    constructor(private readonly configService: ConfigService, private readonly dynamoDbClient: DynamoDBDocument) {}

    @logger.injectLambdaContext({ clearState: true })
    public async handler(
        event: APIGatewayProxyEvent,
        _context: unknown,
    ): Promise<APIGatewayProxyResult | { statusCode: number }> {
        try {
            await initPromise;
            logger.info("Create AuthCode Lambda triggered");

            const sessionId = getSessionId(event);
            const authorizationCode = randomUUID();

            await this.dynamoDbClient.send(
                new UpdateCommand({
                    TableName: this.configService.getConfigEntry(CommonConfigKey.SESSION_TABLE_NAME),
                    Key: { sessionId: sessionId },
                    UpdateExpression: "SET authorizationCode=:authCode, authorizationCodeExpiryDate=:authCodeExpiry",
                    ExpressionAttributeValues: {
                        ":authCode": authorizationCode,
                        ":authCodeExpiry": this.configService.getAuthorizationCodeExpirationEpoch(),
                    },
                }),
            );
            logger.info(`AuthCode Created on Session with Id: ${sessionId}`);
            return { statusCode: 200 };
        } catch (err: unknown) {
            return errorPayload(err as Error, logger, "Create AuthCode Lambda error occurred");
        }
    }
}

const handlerClass = new CreateAuthCodeLambda(configService, dynamoDbClient);
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
