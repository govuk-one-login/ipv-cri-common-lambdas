import { DynamoDBDocument, PutCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";
import { NativeAttributeValue } from "@aws-sdk/util-dynamodb";

export class ReplicationService {
    constructor(
        private dynamoDbClient: DynamoDBDocument,
        private sourceSessionTableName: string,
        private sourcePersonIdentityTableName: string,
        private targetSessionTableName: string,
        private targetPersonIdentityTableName: string,
    ) {}

    public resolveTargetTable(eventSourceArn: string): string {
        // Stream ARN format: arn:aws:dynamodb:<region>:<account>:table/<table-name>/stream/<timestamp>
        const sourceTableName = eventSourceArn.split("/")[1];

        if (sourceTableName === this.sourceSessionTableName) {
            return this.targetSessionTableName;
        }
        if (sourceTableName === this.sourcePersonIdentityTableName) {
            return this.targetPersonIdentityTableName;
        }

        throw new Error(
            `Unknown source table: ${sourceTableName}. ` +
                `Expected '${this.sourceSessionTableName}' or '${this.sourcePersonIdentityTableName}'.`,
        );
    }

    public async replicateItem(targetTable: string, item: Record<string, NativeAttributeValue>): Promise<void> {
        const putCommand = new PutCommand({
            TableName: targetTable,
            Item: item,
        });
        await this.dynamoDbClient.send(putCommand);
    }

    public async deleteItem(targetTable: string, key: Record<string, NativeAttributeValue>): Promise<void> {
        const deleteCommand = new DeleteCommand({
            TableName: targetTable,
            Key: key,
        });
        await this.dynamoDbClient.send(deleteCommand);
    }
}
