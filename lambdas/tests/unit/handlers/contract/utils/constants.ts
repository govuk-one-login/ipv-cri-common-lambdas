export enum LogLevel {
    DEBUG = "DEBUG",
    INFO = "INFO",
}
export enum Provider {
    EXPERIAN_KBV_CRI_TOKEN_PROVIDER = "ExperianKbvCriTokenProvider",
}
export class Constants {
    static readonly TOKEN = "/token";
    static readonly LOCAL_APP_PORT = 3000;
    static readonly HTTP_CONTENT_TYPE_HEADER = "Content-Type";
    static readonly JSON_CONTENT_TYPE = "application/json";
    static readonly LOCAL_HOST = "http://localhost";
}
