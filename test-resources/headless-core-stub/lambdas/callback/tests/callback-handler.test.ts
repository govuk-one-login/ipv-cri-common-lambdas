import { CallbackLambdaHandler } from "../src/callback-handler";

describe("callback-handler", () => {
    it("Returns 200", async () => {
        const callbackLambdaHandler = new CallbackLambdaHandler();
        const result = await callbackLambdaHandler.handler();
        expect(result).toEqual({ status: "200", body: "Hello callback" });
    });
});
