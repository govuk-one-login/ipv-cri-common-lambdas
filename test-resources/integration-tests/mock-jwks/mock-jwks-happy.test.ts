import { stackOutputs } from "../helpers/cloudformation";

describe("happy path mock-jwks", () => {
    it("calls .well-known/jwks.json successfully", async () => {
        const { TestHarnessExecuteUrl: testHarnessExecuteUrl } = await stackOutputs(process.env.STACK_NAME);

        const data = await fetch(new URL(".well-known/jwks.json", testHarnessExecuteUrl).href, {
            method: "GET",
            headers: { Accept: "application/json" },
        });
        const jwks = await data.json();

        expect(jwks).toEqual({
            keys: [
                {
                    kty: "EC",
                    use: "sig",
                    crv: "P-256",
                    kid: "74c5b00d698a18178a738f5305ee67f9d50fc620f8be6b89d94638fa16a4c828",
                    x: "k39uKacSukQBrMZrHDTBUZslivpXKDNZTg6inCHwrLc",
                    y: "8F8LnQ7wG9hxsT4ax0Aty7iMGIyiY_YGp3_qIZzKo1A",
                    alg: "ES256",
                },
                {
                    kty: "EC",
                    x: expect.any(String),
                    y: expect.any(String),
                    crv: "P-256",
                    alg: "ES256",
                    kid: expect.any(String),
                    use: "sig",
                },
            ],
        });
    });
});
