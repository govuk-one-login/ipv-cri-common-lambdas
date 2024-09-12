import express, { NextFunction, Request, Response } from "express";
import { Context } from "aws-lambda";
import { lambdaHandler } from "../../../../../src/handlers/authorization-handler";
import { Constants } from "../utils/constants";
import { JwtVerifier } from "../../../../../src/common/security/jwt-verifier";
import { logger } from "../../../../../src/common/utils/power-tool";

class AccessTokenRouter {
    private redirectUri = "https://identity.staging.account.gov.uk";
    private code = "123abc";
    private clientSessionId = "1";

    public router = express.Router();
    private jwtVerifier = new JwtVerifier(
        {
            publicSigningJwk: "",
            jwtSigningAlgorithm: "",
        },
        logger,
    );

    constructor() {
        this.initializeRoutes();
    }
    private initializeRoutes() {
        this.router.post("/", this.handlePostRequest.bind(this));
    }

    private async handlePostRequest(req: Request, res: Response, next: NextFunction) {
        try {
            const event = res.locals.event;

            const clientConfig = new Map<string, string>();
            clientConfig.set("code", this.code);
            clientConfig.set("redirectUri", this.redirectUri);

            const tokenResponse = await lambdaHandler(event, {} as Context);

            res.status(tokenResponse.statusCode);
            res.setHeader(Constants.HTTP_CONTENT_TYPE_HEADER, Constants.JSON_CONTENT_TYPE);
            res.send(tokenResponse.body);
        } catch (error) {
            next(error);
        }
    }
}

export const accessTokenRouter = new AccessTokenRouter().router;
