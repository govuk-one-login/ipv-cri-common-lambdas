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
}

export enum ConfigKey {
    STRENGTH_SCORE = "strengthScore",
    CRI_EVIDENCE_PROPERTIES = "evidenceProperties",
}

export interface ParameterPath {
    prefix: string;
    suffix: string;
}
