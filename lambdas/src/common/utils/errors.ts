import { Logger } from "@aws-lambda-powertools/logger";
// Implementation of ErrorResponse.java in di-ipv-cri-lib

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
        public code?: number,
        public readonly details?: string,
    ) {
        super(message);
    }
    getErrorSummary() {
        if (this.code) {
            return this.code + ": " + this.message;
        } else {
            return this.message;
        }
    }

    getErrorDetails() {
        const error = this.getErrorSummary();
        if (this.details) {
            return error + " - " + this.details;
        } else {
            return error;
        }
    }
}

export class InvalidAccessTokenError extends BaseError {
    constructor() {
        super("Access token expired");
        this.statusCode = 403;
        this.code = 1026;
    }
}

export class InvalidRequestError extends BaseError {
    constructor(public readonly message: string) {
        super(message);
        this.statusCode = 400;
    }
}

export class InvalidPayloadError extends BaseError {
    constructor(public readonly message: string) {
        super(message);
        this.statusCode = 400;
    }
}

export class ServerError extends BaseError {
    constructor() {
        super("Server error");
        this.statusCode = 500;
    }
}

export class JweDecrypterError extends BaseError {
    constructor(public readonly err: Error) {
        super(`Session Validation Error", "Invalid request - JWE decryption failed :${err}`);
        this.statusCode = 403;
        Object.setPrototypeOf(this, JweDecrypterError.prototype);
    }
}

export class GenericServerError extends BaseError {
    constructor(public readonly details?: string) {
        super("Request failed due to a server error");
        this.statusCode = 500;
        this.code = 1025;
        this.details = details;
        Object.setPrototypeOf(this, GenericServerError.prototype);
    }
}

export class JwtSignatureValidationError extends BaseError {
    constructor() {
        super("Signature of the shared attribute JWT is invalid");
        this.statusCode = 403; // Check!!!
        this.code = 1013;
    }
}

export class SessionNotFoundError extends BaseError {
    constructor(public readonly id: string) {
        super(`Could not find session item with id: ${id}`);
        this.statusCode = 400; // check
        this.code = 1029;
    }
}

export class SessionValidationError extends BaseError {
    constructor(public readonly message: string, public readonly details?: string) {
        super(message);
        this.statusCode = 400;
        this.code = 1019;
        this.details = details;
        Object.setPrototypeOf(this, SessionValidationError.prototype);
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
