import { BearerAccessToken } from "../types/bearer-access-token";

export class BearerAccessTokenFactory {
    constructor(private bearerAccessTokenTtl: number) {}
    public async create(): Promise<BearerAccessToken> {
        const { randomBytes } = await import("node:crypto");

        const token_type = "Bearer";
        const access_token = `${randomBytes(32).toString("base64url")}`;

        return {
            access_token,
            token_type,
            expires_in: this.bearerAccessTokenTtl,
        };
    }
}
