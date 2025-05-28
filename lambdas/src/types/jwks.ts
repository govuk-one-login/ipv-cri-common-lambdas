import { JWK } from "jose";

export interface JWKS {
    keys: JWK[];
}

export type JWKCacheCollection = {
    [endpoint: string]: {
        jwks: JWKS;
        expiry: number;
    };
};
