// Implementation of ErrorResponse.java in di-ipv-cri-lib
export abstract class BaseError extends Error {
    constructor(m: string, public statusCode?: number, public code?:number) {
        super(m);
    }

    getErrorSummary() {
        return this.code + ": " + this.message;
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
    constructor(m: string) {
        super(m);
        this.statusCode = 400;
    }
}


export class InvalidPayloadError extends BaseError {
    constructor(m: string) {
        super(m);
        this.statusCode = 400;
    }
}

export class ServerError extends BaseError {
    constructor(m: string) {
        super("Server error");
        this.statusCode = 500;
    }
}

export class JwtSignatureValidationError extends BaseError {
    constructor() {
        super("Signature of the shared attribute JWT is invalid");
        this.statusCode = 403 // Check!!!
        this.code = 1013;
    }
}

export class SessionNotFoundError extends BaseError {
    constructor(id: string) {
        super(`Could not find session item with id: ${id}`);
        this.statusCode = 400 // check
        this.code = 1029;
    }
}