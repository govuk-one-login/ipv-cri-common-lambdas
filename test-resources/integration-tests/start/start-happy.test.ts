import { stackOutputs } from "../helpers/cloudformation";

describe("core stub start endpoint", () => {
    let output;

    beforeAll(async () => {
        output = await stackOutputs(process.env.STACK_NAME);
        console.log("output", output);
    });
    it("works", () => {
        expect(true).toBe(true);
    });
});
