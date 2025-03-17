import { Logger } from "@aws-lambda-powertools/logger";

export interface ErrorResponse {
    statusCode: number;
    body: string;
}

export function errorPayload(err: Error, logger: Logger, loggerMessage: string): ErrorResponse {
    let code,
        errorSummary,
        errorDetails,
        statusCode = 500,
        message = err.message;

    if (err instanceof BaseError) {
        code = err.code;
        statusCode = err?.statusCode as number;
        errorSummary = err.getErrorSummary();
        errorDetails = err.getErrorDetails();
    }

    if (statusCode >= 500) {
        message = "Server Error";
    }

    logger.error(`${loggerMessage}: ${errorDetails}`, err);
    return { statusCode, body: JSON.stringify({ message, code, errorSummary }) };
}
export abstract class BaseError extends Error {
    constructor(
        public readonly message: string,
        public statusCode?: number,
        public code?: number | string,
        public readonly details?: string,
    ) {
        super(message);
    }
    getErrorSummary() {
        return this.code ? this.code + ": " + this.message : this.message;
    }

    getErrorDetails() {
        const error = this.getErrorSummary();

        return this.details ? error + " - " + this.details : error;
    }
}

export class InvalidAccessTokenError extends BaseError {
    constructor() {
        super("Access token expired");
        this.statusCode = 403;
        this.code = 1026;
    }
}

export class AuthorizationCodeExpiredError extends BaseError {
    constructor() {
        super("Authorization code expired");
        this.statusCode = 403;
        this.code = 1027;
    }
}

export class SessionExpiredError extends BaseError {
    constructor() {
        super("Session expired");
        this.statusCode = 403;
        this.code = 1028;
    }
}
