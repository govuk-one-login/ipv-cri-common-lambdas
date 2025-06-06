export enum CommonConfigKey {
    PERSON_IDENTITY_TABLE_NAME = "PersonIdentityTableName",
    SESSION_TABLE_NAME = "SessionTableName",
    SESSION_TTL = "SessionTtl",
    DECRYPTION_KEY_ID = "AuthRequestKmsEncryptionKeyId",
    VC_ISSUER = "verifiable-credential/issuer",
}

export enum ClientConfigKey {
    JWT_ISSUER = "issuer",
    JWT_AUDIENCE = "audience",
    JWT_PUBLIC_SIGNING_KEY = "publicSigningJwkBase64",
    JWT_REDIRECT_URI = "redirectUri",
    JWT_SIGNING_ALGORITHM = "authenticationAlg",
    JWKS_ENDPOINT = "jwksEndpoint",
}

export enum ConfigKey {
    CRI_EVIDENCE_PROPERTIES = "evidence-properties",
}

export interface ParameterPath {
    prefix: string;
    suffix: string;
}
