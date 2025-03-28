import { signJwt } from "../../../utils/src/crypto/signer";
import { TestData } from "../test-data";

describe("signJwt", () => {
    it("retrieves private signing key", async () => {
        const result = await signJwt(TestData.jwtPayload, TestData.privateSigningKey);
        expect(result).toMatch(/eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*/g);
        const expJwtWithoutSigRegex = new RegExp(`^${TestData.jwtWithoutSig}?`);
        expect(result).toMatch(expJwtWithoutSigRegex);
    });
});
