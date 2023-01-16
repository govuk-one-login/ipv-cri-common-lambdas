import { importJWK, JWTPayload, jwtVerify } from "jose";
import { ConfigService } from "./config-service";
import { JWTVerifyOptions } from "jose/dist/types/jwt/verify";
export class JwtVerifier {
    constructor(private configService: ConfigService) {}

    public async verify(
        encodedJwt: any,
        clientId: string,
        mandatoryClaims: Set<string>,
        expectedClaimValues: Map<string, string>,
    ): Promise<JWTPayload> {
        const signingPublicJwkBase64 = await this.configService.getPublicSigningJwk(clientId);
        const signingPublicJwk = JSON.parse(Buffer.from(signingPublicJwkBase64, "base64").toString("utf8"));
        const signingAlgorithm = await this.configService.getJwtSigningAlgorithm(clientId);
        const publicKey = await importJWK(signingPublicJwk, signingPublicJwk.alg);

        const jwtVerifyOptions = this.createJwtVerifyOptions(signingAlgorithm, expectedClaimValues);
        const { payload } = await jwtVerify(encodedJwt, publicKey, jwtVerifyOptions);

        if (mandatoryClaims?.size) {
            mandatoryClaims.forEach((mandatoryClaim) => {
                if (!payload[mandatoryClaim]) {
                    throw new Error(`Claims-set missing mandatory claim: ${mandatoryClaim}`);
                }
            });
        }

        return payload;
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
    }
}
