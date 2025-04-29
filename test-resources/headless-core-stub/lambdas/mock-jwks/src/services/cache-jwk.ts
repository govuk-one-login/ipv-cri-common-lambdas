import { randomUUID } from "crypto";
import { JSONWebKeySet, JWK } from "jose";
import { getJwkKeyPair, GetJwkKeyPairOptions } from "../../../../utils/src/keypair";
import { getHashedKid } from "../../../../utils/src/hashing";
import { CORE_STUB_SIGNING_PUBLIC_JWK, STUB_PRIVATE_SIGNING_KEY_PARAMETER_PATH } from "../../../../utils/src/constants";
import { getParametersValues } from "../../../../utils/src/parameter/get-parameters";

let cachedKeys: { jwks: JSONWebKeySet } | null = null;

export const generateJWKS = async (): Promise<{ jwks: JSONWebKeySet; privateKeys?: JWK[] }> => {
    if (cachedKeys) {
        return cachedKeys;
    }

    const ssmParameters = await getParametersValues([STUB_PRIVATE_SIGNING_KEY_PARAMETER_PATH]);
    const currentPublicKey = CORE_STUB_SIGNING_PUBLIC_JWK as JWK;
    const currentPrivateKey = JSON.parse(ssmParameters.privateSigningKey) as JWK;

    const [key1, key2] = await Promise.all([
        getJwkKeyPair({ currentPublicKey, currentPrivateKey } as GetJwkKeyPairOptions),
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
