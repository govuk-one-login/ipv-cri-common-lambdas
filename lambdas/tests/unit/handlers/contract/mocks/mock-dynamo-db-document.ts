import { GetCommand, QueryCommandInput, QueryCommandOutput } from "@aws-sdk/lib-dynamodb";

export class MockDynamoDBDocument {
    private mockData: Record<string, unknown>;
    constructor(initialData: Record<string, unknown> = {}) {
        this.mockData = initialData;
    }

    public async send(command: GetCommand): Promise<unknown> {
        const matchingItems = await this.processCommand(command.input);

        return Promise.resolve({
            Item: matchingItems,
        } as unknown as QueryCommandOutput);
    }

    public async query(params: QueryCommandInput): Promise<QueryCommandOutput> {
        const matchingItems = await this.processCommand(params);

        return Promise.resolve({
            Items: matchingItems,
        } as QueryCommandOutput);
    }
    private async processCommand(params: QueryCommandInput) {
        return Object.values(this.mockData)
            .filter((item: unknown) => item && !!params)
            .map((item) => item as Record<string, unknown>);
    }
}
