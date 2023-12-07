import { importJWK, JWTPayload, jwtVerify } from "jose";
import { JWTVerifyOptions } from "jose/dist/types/jwt/verify";
import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerificationConfig } from "../../types/jwt-verification-config";

export enum ClaimNames {
    ISSUER = "iss",
    SUBJECT = "sub",
    AUDIENCE = "aud",
    EXPIRATION_TIME = "exp",
    NOT_BEFORE = "nbf",
    ISSUED_AT = "iat",
    JWT_ID = "jti",
    REDIRECT_URI = "redirect_uri",
    SCOPE = "scope",
    STATE = "state",
}

export class JwtVerifier {
    static ClaimNames = ClaimNames;
    constructor(
        private jwtVerifierConfig: JwtVerificationConfig,
        private logger: Logger,
    ) {}

    public async verify(
        encodedJwt: Buffer,
        mandatoryClaims: Set<string>,
        expectedClaimValues: Map<string, string>,
    ): Promise<JWTPayload | null> {
        try {
            const signingPublicJwkBase64 = this.jwtVerifierConfig.publicSigningJwk;
            const signingAlgorithm = this.jwtVerifierConfig.jwtSigningAlgorithm;
            const signingPublicJwk = JSON.parse(Buffer.from(signingPublicJwkBase64, "base64").toString("utf8"));
            const publicKey = await importJWK(signingPublicJwk, signingPublicJwk?.alg || signingAlgorithm);

            const jwtVerifyOptions = this.createJwtVerifyOptions(signingAlgorithm, expectedClaimValues);
            const { payload } = await jwtVerify(encodedJwt, publicKey, jwtVerifyOptions);

            if (!mandatoryClaims || mandatoryClaims?.size === 0) throw new Error("No mandatory claims provided");

            mandatoryClaims?.forEach((mandatoryClaim) => {
                if (!payload[mandatoryClaim]) {
                    throw new Error(`Claims-set missing mandatory claim: ${mandatoryClaim}`);
                }
            });

            return payload;
        } catch (error) {
            this.logger.error("JWT verification failed", error as Error);
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
    public constructor(private readonly logger: Logger) {}
    public create(jwtSigningAlgo: string, jwtPublicSigningKey: string): JwtVerifier {
        return new JwtVerifier(
            {
                jwtSigningAlgorithm: jwtSigningAlgo,
                publicSigningJwk: jwtPublicSigningKey,
            },
            this.logger,
        );
    }
}
