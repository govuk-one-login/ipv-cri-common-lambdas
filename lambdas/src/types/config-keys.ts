export enum CommonConfigKey {
    PERSON_IDENTITY_TABLE_NAME = "PERSON_IDENTITY_TABLE",
    SESSION_TABLE_NAME = "SESSION_TABLE",
    SESSION_TTL = "SessionTtl",
    DECRYPTION_KEY_ID = "AuthRequestKmsEncryptionKeyId",
    VC_ISSUER = "VC_ISSUER",
}

export const EnvVarConfigKeys: CommonConfigKey[] = [
    CommonConfigKey.SESSION_TABLE_NAME,
    CommonConfigKey.PERSON_IDENTITY_TABLE_NAME,
    CommonConfigKey.VC_ISSUER,
];

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
