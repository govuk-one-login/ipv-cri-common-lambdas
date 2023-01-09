import { ConfigService } from "./config-service";
import { BearerAccessToken } from '../types/bearer-access-token';
import { SessionItem } from "../types/session-item";
export class AccessTokenService {

    public async createBearerAccessToken(expires_in: number) : Promise<BearerAccessToken> {
        const {
            randomBytes,
          } = await import('node:crypto');

        const access_token = `${randomBytes(32).toString('base64')}`;
        const token_type = 'Bearer';

        const BearerAccessToken = {
            access_token,
            token_type,
            expires_in
        }
        return BearerAccessToken;

    }
} 