import { base64Encode, base64Decode } from "../../src/base64";

describe("base64 utils", () => {
    describe("#base64Encode", () => {
        it("returns a base64 encoded string", () => {
            const string = "test string";
            const result = base64Encode(string);

            expect(result).toBe("dGVzdCBzdHJpbmc=");
        });
    });

    describe("#base64Decode", () => {
        it("returns decoded string", () => {
            const base64String = "dGVzdCBzdHJpbmc=";
            const result = base64Decode(base64String);

            expect(result).toBe("test string");
        });
    });
});
