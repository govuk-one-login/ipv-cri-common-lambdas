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
            issuer: clientId,
            audience: expectedAudience,
            subject: clientId
        });

        // {
        //     "iss": "ipv-core-stub",
        //     "sub": "ipv-core-stub",
        //     "aud": "https://review-a.dev.account.gov.uk",
        //     "exp": 1673008565,
        //     "jti": "Tp_g295FrLm5k9WPmGVBKbb4XOYnTO6lotEXpV-4nR4"
        // }

        // Set<String> requiredClaims =
        // Set.of(
        //         JWTClaimNames.EXPIRATION_TIME,
        //         JWTClaimNames.SUBJECT,
        //         JWTClaimNames.ISSUER,
        //         JWTClaimNames.AUDIENCE,
        //         JWTClaimNames.JWT_ID);
        
        if(!payload.exp){
            
        }

        return payload;
    }
}
