// Implementation of ErrorResponse.java in di-ipv-cri-lib
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
        let error = this.message;
        if (this.code) {
            error = this.code + ": " + error;
        }
        if (this.details) {
            error = error + " - " + this.details;
        }
        return error;
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
