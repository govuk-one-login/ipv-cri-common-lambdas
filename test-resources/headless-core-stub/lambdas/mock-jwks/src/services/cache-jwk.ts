import { randomUUID } from "crypto";
import { JSONWebKeySet, JWK } from "jose";
import { getJwkKeyPair, GetJwkKeyPairOptions } from "../../../../utils/src/keypair";
import { getHashedKid } from "../../../../utils/src/hashing";
import { CORE_STUB_SIGNING_PUBLIC_JWK } from "../../../../utils/src/constants";

let cachedKeys: { jwks: JSONWebKeySet } | null = null;

export const generateJWKS = async (): Promise<{ jwks: JSONWebKeySet }> => {
    if (cachedKeys) {
        return cachedKeys;
    }

    const currentPublicKey = CORE_STUB_SIGNING_PUBLIC_JWK as JWK;

    const [key1, key2] = await Promise.all([
        getJwkKeyPair({ currentPublicKey } as GetJwkKeyPairOptions),
        getJwkKeyPair({ kid: getHashedKid(randomUUID()) }),
    ]);

    const result = {
        jwks: {
            keys: [key1.publicKey, key2.publicKey],
        } as JSONWebKeySet,
    };

    cachedKeys = result;

    return result;
};
