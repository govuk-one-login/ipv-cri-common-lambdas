import { createLocalJWKSet, importJWK, JWTPayload, jwtVerify } from "jose";
import { JWTVerifyOptions } from "jose/dist/types/jwt/verify";
import { Logger } from "@aws-lambda-powertools/logger";
import { JwtVerificationConfig } from "../../types/jwt-verification-config";
import { JWKCacheCollection, JWKS } from "../../types/jwks";

let cachedJWKS: JWKCacheCollection = {};

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

    constructor(
        private jwtVerifierConfig: JwtVerificationConfig,
        private logger: Logger,
    ) {
        this.usePublicJwksEndpoint = process.env.ENV_VAR_FEATURE_CONSUME_PUBLIC_JWK ?? "false";
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
        this.logger.info("Using JWKS endpoint: " + this.jwtVerifierConfig.jwksEndpoint);
        try {
            if (!this.jwtVerifierConfig.jwksEndpoint) {
                throw new Error(
                    `Unable to retrieve jwksEndpoint SSM param from JWT verifier config! Got: ${JSON.stringify(
                        this.jwtVerifierConfig.jwksEndpoint,
                    )}`,
                );
            }

            const jwks = await this.fetchJWKSWithCache(this.jwtVerifierConfig.jwksEndpoint);

            const localJWKSet = createLocalJWKSet(jwks);
            const { payload } = await jwtVerify(encodedJwt.toString(), localJWKSet, jwtVerifyOptions);
            this.verifyMandatoryClaims(mandatoryClaims, payload);
            this.logger.info("Sucessfully verified JWT using Public JWKS Endpoint");
            return payload;
        } catch (error) {
            this.clearJWKSCacheForCurrentEndpoint();
            this.logger.error(
                "Caught an error when using JWKS endpoint. Falling back on public JWKS parameter.",
                error as Error,
            );
            return this.verifyWithJwksParam(encodedJwt, mandatoryClaims, jwtVerifyOptions);
        }
    }

    private async fetchJWKSWithCache(jwksUrl: string) {
        const cachedJwkEntry = cachedJWKS[jwksUrl];

        const now = Date.now();

        if (cachedJwkEntry && cachedJwkEntry.expiry >= now) {
            // If we have a valid cache entry, use it
            this.logger.info(
                `Using locally cached JWKs from ${this.jwtVerifierConfig.jwksEndpoint} (expiry: ${new Date(
                    cachedJwkEntry.expiry,
                ).toISOString()} >= ${new Date(now).toISOString()})`,
            );
            return cachedJwkEntry.jwks;
        }

        // No valid cache entry - fetch fresh JWKS
        this.logger.info(`Fetching new JWKS from ${this.jwtVerifierConfig.jwksEndpoint}...`);

        const jwksResponse = await fetch(jwksUrl);
        if (!jwksResponse.ok) {
            throw new Error("Error received from the JWKS endpoint, status received: " + jwksResponse.status);
        }

        const jwks = (await jwksResponse.json()) as JWKS;
        const expiry = this.parseCacheControlHeader(jwksResponse.headers.get("Cache-Control"));

        cachedJWKS[jwksUrl] = {
            jwks,
            expiry,
        };

        this.logger.info(`JWKS cache for ${jwksUrl} has been updated - expiry: ${new Date(expiry).toISOString()}`);

        return jwks;
    }

    private parseCacheControlHeader(cacheControlHeaderValue: string | null) {
        const matches = cacheControlHeaderValue?.match(/max-age=(\d+)/);
        const maxAgeSeconds = matches ? parseInt(matches[1], 10) : -1;
        return Date.now() + maxAgeSeconds * 1000;
    }

    public clearJWKSCacheForCurrentEndpoint() {
        const { [this.jwtVerifierConfig.jwksEndpoint]: _, ...remainingEntries } = cachedJWKS;
        cachedJWKS = remainingEntries;
    }

    public clearJWKSCacheForAllEndpoints() {
        cachedJWKS = {};
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
    public create(jwtSigningAlgo: string, jwtPublicSigningKey: string, jwksEndpoint: string): JwtVerifier {
        return new JwtVerifier(
            {
                jwtSigningAlgorithm: jwtSigningAlgo,
                publicSigningJwk: jwtPublicSigningKey,
                jwksEndpoint,
            },
            this.logger,
        );
    }
}
