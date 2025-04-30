import { randomUUID } from "crypto";
import { generateKeyPair, exportJWK, JWK } from "jose";
import { getHashedKid } from "../hashing";

type KeyPair = {
    publicKey: JWK;
};
export interface GetJwkKeyPairOptions {
    kid: string;
    alg?: string;
    use?: "sig" | "enc";
    currentPublicKey?: JWK;
}

export async function getJwkKeyPair({
    kid = randomUUID(),
    alg = "ES256",
    use = "sig",
    currentPublicKey,
}: GetJwkKeyPairOptions): Promise<KeyPair> {
    if (currentPublicKey && currentPublicKey.kid) {
        const hashedKid = getHashedKid(`${currentPublicKey.kid}`);

        return {
            publicKey: { ...currentPublicKey, alg, kid: hashedKid, use },
        };
    }
    const { publicKey } = await generateKeyPair(alg, {
        modulusLength: alg.startsWith("RS") || alg.startsWith("PS") ? 2048 : undefined,
    });

    return {
        publicKey: { ...(await exportJWK(publicKey)), alg, kid, use },
    };
}
