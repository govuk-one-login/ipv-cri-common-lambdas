import { BearerAccessTokenFactory } from "../../../src/services/bearer-access-token-factory";

describe("access-token-service", () => {
    let bearerAccessTokenFactory: BearerAccessTokenFactory;

    describe("createBearerAccessToken", () => {
        beforeEach(() => {
            jest.resetAllMocks();
            bearerAccessTokenFactory = new BearerAccessTokenFactory(10);
        });

        it("should return a bearer token when provided with an expires value", async () => {
            const output = await bearerAccessTokenFactory.create();
            expect(output.token_type).toBe("Bearer");
            expect(output.expires_in).toBe(10);
            const token = Buffer.from(output.access_token, "base64url");
            expect(token.length).toBe(32);
        });
    });
});
