import { importJWK, JWTPayload, jwtVerify } from "jose";
import { ConfigService } from "./config-service";

export class JwtVerifier {
    constructor(private configService: ConfigService) {}
    public async verify(encodedJwt: any, clientId: string): Promise<JWTPayload> {
        const signingPublicJwkBase64 = await this.configService.getPublicSigningJwk(clientId);
        const signingPublicJwk = JSON.parse(Buffer.from(signingPublicJwkBase64, "base64").toString("utf8"));

        const expectedIssuer = await this.configService.getJwtIssuer(clientId);
        const expectedAudience = await this.configService.getJwtAudience(clientId);
        const signingAlgorithm = await this.configService.getJwtSigningAlgorithm(clientId);
        const publicKey = await importJWK(signingPublicJwk, signingPublicJwk.alg);
        const { payload } = await jwtVerify(encodedJwt, publicKey, {
            algorithms: [signingAlgorithm],
            issuer: expectedIssuer,
            audience: expectedAudience,
        });
        return payload;
    }
}
