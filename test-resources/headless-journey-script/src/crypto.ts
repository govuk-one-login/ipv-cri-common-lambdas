import { createHash, randomUUID, createPrivateKey, sign, type JsonWebKey } from "node:crypto";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import assert from "node:assert";
import { logIfVerbose } from "./log.ts";

const ssmClient = new SSMClient();

interface PrivateJWK extends JsonWebKey {
    alg: string;
    kid: string;
    kty: string;
    use: string;
}

export function base64Encode(value: string | Buffer, mode?: "url") {
    return Buffer.from(value).toString(mode === "url" ? "base64url" : "base64");
}

export function base64Decode(value: string) {
    return Buffer.from(value, "base64").toString();
}

async function retrievePrivateKey(clientId: string) {
    const getParamRes = await ssmClient.send(
        new GetParameterCommand({
            Name: `/test-resources/${clientId}/privateSigningKey`,
        }),
    );

    assert(getParamRes.Parameter?.Value);

    const keyString = getParamRes.Parameter.Value;

    const key = JSON.parse(keyString) as PrivateJWK;

    const hashedKid = createHash("sha256").update(Buffer.from(key.kid, "utf8")).digest().toString("hex");

    logIfVerbose(`Retrieved signing key with kid='${key.kid}' (hashed KID='${hashedKid}')`);

    const privateKey = createPrivateKey({ format: "jwk", key });

    return { privateKey, hashedKid };
}

export async function buildAndSignJwt({ clientId, audience }: { clientId: string; audience: string }) {
    const { privateKey, hashedKid } = await retrievePrivateKey(clientId);

    const nowInSeconds = Math.floor(Date.now() / 1000);

    const header = {
        alg: "ES256",
        typ: "JWT",
        kid: hashedKid,
    };
    const payload = {
        iss: clientId,
        sub: clientId,
        aud: audience,
        nbf: nowInSeconds,
        exp: nowInSeconds + 10 * 60,
        jti: randomUUID(),
    };

    const encodedHeader = base64Encode(JSON.stringify(header), "url");
    const encodedPayload = base64Encode(JSON.stringify(payload), "url");

    const dataToSign = `${encodedHeader}.${encodedPayload}`;

    const signature = sign("sha256", Buffer.from(dataToSign), {
        key: privateKey,
        dsaEncoding: "ieee-p1363",
    });

    const encodedSignature = base64Encode(signature, "url");

    return `${dataToSign}.${encodedSignature}`;
}
