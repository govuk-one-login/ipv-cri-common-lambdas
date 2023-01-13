// Implementation of ErrorResponse.java in di-ipv-cri-lib
class BaseError extends Error {
    statusCode: number | undefined;
    code: number | undefined;

    constructor(m: string) {
        super(m);
    }

    getErrorSummary() {
        return this.code + ": " + this.message;
    }
}

export class InvalidAccessTokenError extends BaseError {
    constructor() {
        super("Access token expired");
        this.code = 1026;
        this.statusCode = 403;
    }
}

export class InvalidRequestError extends BaseError {
    constructor(m: string) {
        super(m);
        this.statusCode = 400;
    }
}

export class ServerError extends BaseError {
    constructor(m: string) {
        super(m);
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
