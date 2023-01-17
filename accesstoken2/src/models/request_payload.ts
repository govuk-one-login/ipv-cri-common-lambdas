export class RequestPayload {
    constructor(
        public grantType: string,
        public code: string,
        public redirectUri: string,
        public clientAssertionType: string,
        public clientAssertion: string
    ) { }
}