import { importJWK, JWTPayload, jwtVerify } from "jose";
import { ConfigService } from "./config-service";
import { JWTVerifyOptions } from "jose/dist/types/jwt/verify";
import { Logger } from "@aws-lambda-powertools/logger";

export class JwtVerifier {
    constructor(private configService: ConfigService, private logger: Logger) {}

    public async verify(
        encodedJwt: Buffer,
        clientId: string,
        mandatoryClaims: Set<string>,
        expectedClaimValues: Map<string, string>,
    ): Promise<JWTPayload | null> {
        let jwtPayload: JWTPayload;
        try {
            const signingPublicJwkBase64 = await this.configService.getPublicSigningJwk(clientId);
            const signingPublicJwk = JSON.parse(Buffer.from(signingPublicJwkBase64, "base64").toString("utf8"));
            const signingAlgorithm = await this.configService.getJwtSigningAlgorithm(clientId);
            const publicKey = await importJWK(signingPublicJwk, signingPublicJwk.alg);

            const jwtVerifyOptions = this.createJwtVerifyOptions(signingAlgorithm, expectedClaimValues);
            const { payload } = await jwtVerify(encodedJwt, publicKey, jwtVerifyOptions);

            if (mandatoryClaims && mandatoryClaims.size) {
                mandatoryClaims.forEach((mandatoryClaim) => {
                    if (!payload[mandatoryClaim]) {
                        throw new Error(`Claims-set missing mandatory claim: ${mandatoryClaim}`);
                    }
                });
            }
            jwtPayload = payload;
        } catch (error) {
            this.logger.error("JWT verification failed", error as Error);
            return null;
        }

        return jwtPayload;
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

export namespace JwtVerifier {
    export enum ClaimNames {
        ISSUER = "iss",
        SUBJECT = "sub",
        AUDIENCE = "aud",
        EXPIRATION_TIME = "exp",
        NOT_BEFORE = "nbf",
        ISSUED_AT = "iat",
        JWT_ID = "jti",
        REDIRECT_URI = "redirect_uri",
    }
}
