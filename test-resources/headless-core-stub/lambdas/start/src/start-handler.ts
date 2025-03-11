import type { LambdaInterface } from "@aws-lambda-powertools/commons/types";

export class StartLambdaHandler implements LambdaInterface {
    async handler(): Promise<{ status: string; body: string }> {
        return {
            status: "200",
            body: "Hello start",
        };
    }
}

const handlerClass = new StartLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
