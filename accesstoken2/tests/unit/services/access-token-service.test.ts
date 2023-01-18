import { AccessTokenService } from "../../../src/services/access-token-service";

describe("access-token-service", () => {
  let accessTokenService: AccessTokenService;

  describe("createBearerAccessToken", () => {

    beforeEach(() => {
      jest.resetAllMocks();
      accessTokenService = new AccessTokenService();
    });

    it("should return a bearer token when provided with an expires value", async () => {
      const output = await accessTokenService.createBearerAccessToken(10);
      expect(output.token_type).toBe("Bearer");
      expect(output.expires_in ).toBe(10);
      const token = Buffer.from(output.access_token, "base64url");
      expect(token.length).toBe(32);
    });
  });
});