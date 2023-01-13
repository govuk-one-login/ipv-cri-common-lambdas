// Implementation of ErrorResponse.java in di-ipv-cri-lib
class BaseError extends Error {
  statusCode: number | undefined
  code: number | undefined

  constructor(m: string) {
    super(m)
  }

  getErrorSummary() {
    return this.statusCode + ": " + this.message;
  }
}

export class InvalidAccessToken extends BaseError {
  constructor() {
    super("Invalid request: Access token expired")
    this.code = 1026;
    this.statusCode = 403;
  }
}

export class InvalidRequest extends BaseError {
  constructor(m:string) {
    super(m)
    this.statusCode = 400;
  }
}

export class ServerError extends BaseError {
  constructor(m:string) {
    super(m)
    this.statusCode = 500;
  }
}