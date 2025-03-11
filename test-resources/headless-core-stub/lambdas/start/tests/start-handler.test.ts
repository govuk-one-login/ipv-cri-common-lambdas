import { StartLambdaHandler } from "../src/start-handler";

describe("start-handler", () => {
    it("Returns 200", async () => {
        const startLambdaHandler = new StartLambdaHandler();
        const result = await startLambdaHandler.handler();
        expect(result).toEqual({ status: "200", body: "Hello start" });
    });
});
