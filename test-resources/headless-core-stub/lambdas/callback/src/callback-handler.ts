import type { LambdaInterface } from "@aws-lambda-powertools/commons/types";

export class CallbackLambdaHandler implements LambdaInterface {
    async handler(): Promise<{ status: string; body: string }> {
        return {
            status: "200",
            body: "Hello callback",
        };
    }
}

const handlerClass = new CallbackLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
