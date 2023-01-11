import { BearerAccessToken } from '../types/bearer-access-token';

export class AccessTokenService {

    public async createBearerAccessToken(expires_in: number) : Promise<BearerAccessToken> {
        const {
            randomBytes,
          } = await import('node:crypto');

        const token_type = 'Bearer';
        const access_token = `${randomBytes(32).toString('base64url')}`;
        
        return {
            access_token,
            token_type,
            expires_in
        }
    }
} 