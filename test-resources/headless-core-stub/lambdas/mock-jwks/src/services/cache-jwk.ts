import { randomUUID } from "crypto";
import { JSONWebKeySet, JWK } from "jose";
import { getJwkKeyPair, GetJwkKeyPairOptions } from "../../../../utils/src/keypair";
import { getHashedKid } from "../../../../utils/src/hashing";
import { ClientConfiguration } from "../../../../utils/src/services/client-configuration";
import { base64Decode } from "../../../../utils/src/base64";

let cachedKeys: { jwks: JSONWebKeySet; privateKeys?: JWK[] } | null = null;

export const generateJWKS = async (clientId: string): Promise<{ jwks: JSONWebKeySet; privateKeys?: JWK[] }> => {
    if (cachedKeys) {
        return cachedKeys;
    }

    const ssmParameters = await ClientConfiguration.getConfig(clientId);
    const currentPublicKey = JSON.parse(base64Decode(ssmParameters.publicSigningJwkBase64)) as JWK;
    const currentPrivateKey = JSON.parse(ssmParameters.privateSigningKey) as JWK;

    const [key1, key2] = await Promise.all([
        getJwkKeyPair({ currentPublicKey, currentPrivateKey } as GetJwkKeyPairOptions),
        getJwkKeyPair({ kid: getHashedKid(randomUUID()) }),
    ]);

    const result = {
        jwks: {
            keys: [key1.publicKey, key2.publicKey],
        } as JSONWebKeySet,
        privateKeys: [key1.privateKey, key2.privateKey],
    };

    cachedKeys = result;

    return result;
};
