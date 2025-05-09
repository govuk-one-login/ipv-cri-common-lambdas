import { createLocalJWKSet, importJWK, JWTPayload, jwtVerify } from "jose";
import { JWTVerifyOptions } from "jose/dist/types/jwt/verify";
import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerificationConfig } from "../../types/jwt-verification-config";
import { JWKS } from "../../types/jwks";

let cachedJWKS: JWKS | null = null;
let cachedJWKSExpiry: number | null = null;

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
    private readonly usePublicJwksEndpoint;
    private readonly publicJwksEndpoint;

    constructor(
        private jwtVerifierConfig: JwtVerificationConfig,
        private logger: Logger,
    ) {
        this.usePublicJwksEndpoint = process.env.ENV_VAR_FEATURE_CONSUME_PUBLIC_JWK ?? "false";
        this.publicJwksEndpoint = process.env.PUBLIC_JWKS_ENDPOINT ?? "";
    }

    public async verify(
        encodedJwt: Buffer,
        mandatoryClaims: Set<string>,
        expectedClaimValues: Map<string, string>,
    ): Promise<JWTPayload | null> {
        const jwtVerifyOptions = this.createJwtVerifyOptions(expectedClaimValues);
        if (this.usePublicJwksEndpoint === "true") {
            return await this.verifyWithJwksEndpoint(encodedJwt, mandatoryClaims, jwtVerifyOptions);
        } else {
            this.logger.info("Using public JWKS endpoint is disabled");
            return await this.verifyWithJwksParam(encodedJwt, mandatoryClaims, jwtVerifyOptions);
        }
    }

    private async verifyWithJwksEndpoint(
        encodedJwt: Buffer,
        mandatoryClaims: Set<string>,
        jwtVerifyOptions: JWTVerifyOptions,
    ) {
        this.logger.info("Using JWKS endpoint: " + this.publicJwksEndpoint);
        try {
            if (this.publicJwksEndpoint === "") {
                throw new Error("PUBLIC_JWKS_ENDPOINT env variable has not been set");
            }

            if (cachedJWKS && cachedJWKSExpiry && cachedJWKSExpiry >= Date.now()) {
                this.logger.info("Using locally cached JWKs from " + this.publicJwksEndpoint);
            } else {
                this.logger.info("Fetching new JWKS from " + this.publicJwksEndpoint);
                await this.fetchAndCacheJWKS(new URL(this.publicJwksEndpoint));
            }

            const localJWKSet = createLocalJWKSet(cachedJWKS!);
            const { payload } = await jwtVerify(encodedJwt.toString(), localJWKSet, jwtVerifyOptions);
            this.verifyMandatoryClaims(mandatoryClaims, payload);
            this.logger.info("Sucessfully verified JWT using Public JWKS Endpoint");
            return payload;
        } catch (error) {
            this.clearJWKSCache();
            this.logger.error("Failed to call JWKS endpoint, attempting with params.", error as Error);
            return this.verifyWithJwksParam(encodedJwt, mandatoryClaims, jwtVerifyOptions);
        }
    }

    private async fetchAndCacheJWKS(jwksUrl: URL) {
        const jwksResponse = await fetch(jwksUrl);
        if (!jwksResponse.ok) {
            throw new Error("Error recieved from the JWKS endpoint, status recieved: " + jwksResponse.status);
        }

        cachedJWKS = await jwksResponse.json();
        cachedJWKSExpiry = this.parseCacheControlHeader(jwksResponse.headers.get("Cache-Control"));
        this.logger.info("JWKS cache has been updated to " + cachedJWKSExpiry);
    }

    private parseCacheControlHeader(cacheControlHeaderValue: string | null) {
        const matches = cacheControlHeaderValue?.match(/max-age=(\d+)/);
        const maxAgeSeconds = matches ? parseInt(matches[1], 10) : -1;
        return Date.now() + maxAgeSeconds * 1000;
    }

    public clearJWKSCache() {
        cachedJWKS = null;
        cachedJWKSExpiry = null;
    }

    private async verifyWithJwksParam(
        encodedJwt: Buffer,
        mandatoryClaims: Set<string>,
        jwtVerifyOptions: JWTVerifyOptions,
    ) {
        this.logger.info("Attempting to verify JWT using Public JWKS parameter");
        try {
            const signingPublicJwkBase64 = this.jwtVerifierConfig.publicSigningJwk;
            const signingAlgorithm = this.jwtVerifierConfig.jwtSigningAlgorithm;
            const signingPublicJwk = JSON.parse(Buffer.from(signingPublicJwkBase64, "base64").toString("utf8"));
            const publicKey = await importJWK(signingPublicJwk, signingPublicJwk?.alg || signingAlgorithm);
            const { payload } = await jwtVerify(encodedJwt, publicKey, jwtVerifyOptions);
            this.verifyMandatoryClaims(mandatoryClaims, payload);
            this.logger.info("Sucessfully verified JWT using Public JWKS Parameter");
            return payload;
        } catch (error) {
            this.logger.error("JWT verification failed with JWKS parameter", error as Error);
            return null;
        }
    }

    private verifyMandatoryClaims(mandatoryClaims: Set<string>, payload: JWTPayload) {
        if (!mandatoryClaims || mandatoryClaims?.size === 0) throw new Error("No mandatory claims provided");

        mandatoryClaims?.forEach((mandatoryClaim) => {
            if (!payload[mandatoryClaim]) {
                throw new Error(`Claims-set missing mandatory claim: ${mandatoryClaim}`);
            }
        });
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
