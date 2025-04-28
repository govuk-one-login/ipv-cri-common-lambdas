import {
    createRemoteJWKSet,
    JWTPayload,
    jwtVerify,
    JWTVerifyOptions,
    JWTVerifyResult,
    RemoteJWKSetOptions,
} from "jose";
import { Logger } from "@aws-lambda-powertools/logger";
interface JwtVerificationConfig {
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
    constructor(
        private jwtVerifierConfig: JwtVerificationConfig,
        private logger: Logger,
    ) {}

    public async verify(
        encodedJwt: Buffer,
        mandatoryClaims: Set<string>,
        expectedClaimValues: Map<string, string>,
    ): Promise<JWTVerifyResult | null> {
        if (!mandatoryClaims || mandatoryClaims?.size === 0) throw new Error("No mandatory claims provided");
        const jwtVerifyOptions = this.createJwtVerifyOptions(expectedClaimValues);

        try {
            this.logger.info("Expected claims:", JSON.stringify(expectedClaimValues));

            const verifyResult = await jwtVerify(
                encodedJwt.toString(),
                this.getPublicKeyUsingJwksUri(expectedClaimValues.get(JwtVerifier.ClaimNames.ISSUER)), // wellknown endpoint for test is the core-stub but in live it going to be the CRI
                jwtVerifyOptions,
            );
            this.checkMandatoryClaims(verifyResult.payload, mandatoryClaims);
            return verifyResult;
        } catch (error) {
            this.logger.error("JWT verification failed", error as Error);
            return null;
        }
    }
    private checkMandatoryClaims(payload: JWTPayload, mandatoryClaims: Set<string>) {
        mandatoryClaims.forEach((mandatoryClaim) => {
            if (!payload[mandatoryClaim]) {
                throw new Error(`Claims-set missing mandatory claim: ${mandatoryClaim}`);
            }
        });
    }

    private getPublicKeyUsingJwksUri(issuer?: string) {
        this.logger.info({ message: "getPublicKeyUsingJwksUri:- using issuer", issuer });

        this.logger.info("Retrieving publicSigningKey from JwkEndpoint");
        const jwkEndpoint = `${issuer}/.well-known/jwks.json`;

        this.logger.info("JWK_ENDPOINT", jwkEndpoint.toString());
        return createRemoteJWKSet(new URL(jwkEndpoint), { cache: false } as RemoteJWKSetOptions);
    }

    private createJwtVerifyOptions(expectedClaimValues: Map<string, string>): JWTVerifyOptions {
        return {
            algorithms: [this.jwtVerifierConfig.jwtSigningAlgorithm],
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
