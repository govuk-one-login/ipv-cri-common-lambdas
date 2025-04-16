import { importJWK, JWTVerifyResult, jwtVerify } from "jose";
import { JWTVerifyOptions } from "jose/dist/types/jwt/verify";

export interface JwtVerificationConfig {
    publicSigningJwk: string;
    jwtSigningAlgorithm: string;
}

export enum ClaimNames {
    ISSUER = "iss",
    SUBJECT = "sub",
    AUDIENCE = "aud",
    EXPIRATION_TIME = "exp",
    NOT_BEFORE = "nbf",
    ISSUED_AT = "iat",
    JWT_ID = "jti",
    REDIRECT_URI = "redirect_uri",
    EVIDENCE_REQUESTED = "evidence_requested",
    STATE = "state",
}

export class JwtVerifier {
    static ClaimNames = ClaimNames;
    constructor(private jwtVerifierConfig: JwtVerificationConfig) {}

    public async verify(
        encodedJwt: Buffer,
        mandatoryClaims: Set<string>,
        expectedClaimValues: Map<string, string>,
    ): Promise<JWTVerifyResult | null> {
        try {
            const signingPublicJwkBase64 = this.jwtVerifierConfig.publicSigningJwk;
            const signingAlgorithm = this.jwtVerifierConfig.jwtSigningAlgorithm;
            const signingPublicJwk = JSON.parse(Buffer.from(signingPublicJwkBase64, "base64").toString("utf8"));
            const publicKey = await importJWK(signingPublicJwk, signingPublicJwk?.alg || signingAlgorithm);

            const jwtVerifyOptions = this.createJwtVerifyOptions(signingAlgorithm, expectedClaimValues);
            const verifyResult = await jwtVerify(encodedJwt, publicKey, jwtVerifyOptions);

            if (!mandatoryClaims || mandatoryClaims?.size === 0) throw new Error("No mandatory claims provided");

            mandatoryClaims?.forEach((mandatoryClaim) => {
                if (!verifyResult.payload[mandatoryClaim]) {
                    throw new Error(`Claims-set missing mandatory claim: ${mandatoryClaim}`);
                }
            });

            return verifyResult;
        } catch (error) {
            // eslint-disable-next-line no-console
            console.error("JWT verification failed", error as Error);
            return null;
        }
    }

    private createJwtVerifyOptions(
        signingAlgorithm: string,
        expectedClaimValues: Map<string, string>,
    ): JWTVerifyOptions {
        return {
            algorithms: [signingAlgorithm],
            audience: expectedClaimValues.get(JwtVerifier.ClaimNames.AUDIENCE),
            issuer: expectedClaimValues.get(JwtVerifier.ClaimNames.ISSUER),
            subject: expectedClaimValues.get(JwtVerifier.ClaimNames.SUBJECT),
        };
    }
}

export class JwtVerifierFactory {
    public constructor() {}
    public create(jwtSigningAlgo: string, jwtPublicSigningKey: string): JwtVerifier {
        return new JwtVerifier({
            jwtSigningAlgorithm: jwtSigningAlgo,
            publicSigningJwk: jwtPublicSigningKey,
        });
    }
}
