import type { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { Logger } from "@aws-lambda-powertools/logger";
import { IssuerAuthorizationRequestClass } from "@govuk-one-login/data-vocab/credentials";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { JWK, JWTPayload, KeyLike } from "jose";
import { handleErrorResponse } from "./errors/error-response";
import { generateJwtClaimsSet, parseJwtClaimsSetOverrides, validateClaimsSet } from "./services/jwt-claims-set-service";
import { encryptSignedJwt, getPrivateSigningKey, getPublicEncryptionKey, signJwt } from "./services/signing-service";
import { ClaimsSetOverrides } from "./types/claims-set-overrides";

const logger = new Logger();

export class StartLambdaHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
        try {
            const jwtClaimsSetOverrides: ClaimsSetOverrides = parseJwtClaimsSetOverrides(event?.body);

            const jwtClaimsSet: IssuerAuthorizationRequestClass = await generateJwtClaimsSet(jwtClaimsSetOverrides);

            validateClaimsSet(jwtClaimsSet);

            const signingKey: JWK = await getPrivateSigningKey();

            const signedJwt = await signJwt(jwtClaimsSet as unknown as JWTPayload, signingKey);

            const publicEncryptionKey: KeyLike = await getPublicEncryptionKey();

            const encryptedSignedJwt = await encryptSignedJwt(signedJwt, publicEncryptionKey);

            return Promise.resolve({
                statusCode: 200,
                body: JSON.stringify({
                    request: encryptedSignedJwt,
                    client_id: jwtClaimsSet.client_id,
                }),
            });
        } catch (err: unknown) {
            return handleErrorResponse(err, logger);
        }
    }
}

const handlerClass = new StartLambdaHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
