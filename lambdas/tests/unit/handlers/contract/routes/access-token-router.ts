import express, { NextFunction, Request, Response } from "express";
import { APIGatewayProxyEvent, Context } from "aws-lambda";
import { Constants } from "../utils/constants";
import { logger, metrics } from "../../../../../src/common/utils/power-tool";
import { CreateAccessTokenLambda } from "./access-token-factory";
import { injectLambdaContext } from "@aws-lambda-powertools/logger";
import middy from "@middy/core";
import initialiseClientConfigMiddleware from "../../../../../src/middlewares/config/initialise-client-config-middleware";
import initialiseConfigMiddleware from "../../../../../src/middlewares/config/initialise-config-middleware";
import errorMiddleware from "../../../../../src/middlewares/error/error-middleware";
import getSessionByAuthCodeMiddleware from "../../../../../src/middlewares/session/get-session-by-auth-code-middleware";
import getSessionByIdMiddleware from "../../../../../src/middlewares/session/get-session-by-id-middleware";
import setGovUkSigningJourneyIdMiddleware from "../../../../../src/middlewares/session/set-gov-uk-signing-journey-id-middleware";
import setRequestedVerificationScoreMiddleware from "../../../../../src/middlewares/session/set-requested-verification-score-middleware";
import accessTokenValidatorMiddleware from "../../../../../src/middlewares/access-token/validate-event-payload-middleware";
import { CommonConfigKey, ClientConfigKey } from "../../../../../src/types/config-keys";
import { MockSSMProvider } from "../mocks/mock-ssm-provider";
import { AccessTokenLambda } from "../../../../../src/handlers/access-token-handler";

const parameterPathPrefix = process.env.AWS_STACK_NAME || "";
const { JWT_AUDIENCE, JWT_PUBLIC_SIGNING_KEY, JWT_REDIRECT_URI, JWT_SIGNING_ALGORITHM } = ClientConfigKey;
const { SESSION_TABLE_NAME, SESSION_TTL } = CommonConfigKey;
class AccessTokenRouter {
    public router = express.Router();

    constructor() {
        this.initializeRoutes();
    }
    private initializeRoutes() {
        this.router.post("/", this.handlePostRequest.bind(this));
    }

    private async handlePostRequest(_req: Request, res: Response, next: NextFunction) {
        try {
            const body = res.locals.event.body;
            const bodyAsJson = res.locals.json;
            const componentId = res.locals.componentId;

            const lambda = CreateAccessTokenLambda(
                new MockSSMProvider({
                    [`/${parameterPathPrefix}/${SESSION_TABLE_NAME}`]: "SessionTable",
                    [`/${parameterPathPrefix}/${SESSION_TTL}`]: "10",
                    [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWT_SIGNING_ALGORITHM}`]: "ES256",
                    [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWT_REDIRECT_URI}`]:
                        bodyAsJson.redirect_uri,
                    [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWT_AUDIENCE}`]: componentId,
                    [`/${parameterPathPrefix}/clients/ipv-core/jwtAuthentication/${JWT_PUBLIC_SIGNING_KEY}`]:
                        bodyAsJson.client_assertion,
                }),
                bodyAsJson.redirect_uri,
            );

            const handler = this.middyfy(lambda);
            const response = await handler({ body } as APIGatewayProxyEvent, {} as Context);

            res.status(response.statusCode);
            res.setHeader(Constants.HTTP_CONTENT_TYPE_HEADER, Constants.JSON_CONTENT_TYPE);
            res.send(response.body);
        } catch (error) {
            next(error);
        }
    }

    private middyfy(lambda: AccessTokenLambda) {
        return middy(lambda.handler.bind(lambda))
            .use(
                errorMiddleware(logger, metrics, {
                    metric_name: "accesstoken",
                    message: "Access Token Lambda error occurred",
                }),
            )
            .use(injectLambdaContext(logger, { clearState: true }))
            .use(
                initialiseConfigMiddleware({
                    configService: lambda.getConfigService(),
                    config_keys: [SESSION_TABLE_NAME, SESSION_TTL],
                }),
            )
            .use(
                accessTokenValidatorMiddleware({
                    requestValidator: lambda.getAccessTokenRequestValidator(),
                }),
            )
            .use(getSessionByAuthCodeMiddleware({ sessionService: lambda.getSessionService() }))
            .use(
                initialiseClientConfigMiddleware({
                    configService: lambda.getConfigService(),
                    client_config_keys: [JWT_AUDIENCE, JWT_PUBLIC_SIGNING_KEY, JWT_REDIRECT_URI, JWT_SIGNING_ALGORITHM],
                }),
            )
            .use(getSessionByIdMiddleware({ sessionService: lambda.getSessionService() }))
            .use(setGovUkSigningJourneyIdMiddleware(logger))
            .use(setRequestedVerificationScoreMiddleware(logger));
    }
}

export const accessTokenRouter = new AccessTokenRouter().router;
