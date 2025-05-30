export interface JwtVerificationConfig {
    publicSigningJwk: string;
    jwtSigningAlgorithm: string;
    jwksEndpoint: string;
}
