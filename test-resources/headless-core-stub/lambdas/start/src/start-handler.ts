import type { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { Logger } from "@aws-lambda-powertools/logger";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import middy from "@middy/core";
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from "aws-lambda";
import { JWK, JWTPayload, KeyLike } from "jose";
import { signJwt } from "../../../utils/src/crypto/signer";
import { handleErrorResponse } from "./../../../utils/src/errors/error-response";
import { ClientConfiguration } from "../../../utils/src/services/client-configuration";
import { generateJwtClaimsSet, parseJwtClaimsSetOverrides, validateClaimsSet } from "./services/jwt-claims-set-service";
import { encryptSignedJwt, getPublicEncryptionKey } from "./services/signing-service";
import { ClaimsSetOverrides } from "./types/claims-set-overrides";
import { JWTClaimsSet } from "./types/jwt-claims-set";
import { getHashedKid } from "../../../utils/src/hashing";

export const logger = new Logger();

export class StartLambdaHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent, _context: Context): Promise<APIGatewayProxyResult> {
        try {
            const jwtClaimsSetOverrides: ClaimsSetOverrides = parseJwtClaimsSetOverrides(event?.body);

            const ssmParameters = await ClientConfiguration.getConfig(jwtClaimsSetOverrides.client_id);

            const jwtClaimsSet: JWTClaimsSet = await generateJwtClaimsSet(jwtClaimsSetOverrides, ssmParameters);

            validateClaimsSet(jwtClaimsSet);

            const signingKey: JWK = JSON.parse(ssmParameters.privateSigningKey);
            const jwtHeader = {
                alg: "ES256",
                typ: "JWT",
                ...(signingKey.kid && { kid: getHashedKid(signingKey.kid) }),
            };
            const signedJwt = await signJwt(jwtClaimsSet as JWTPayload, signingKey, jwtHeader);

            const publicEncryptionKey = (await getPublicEncryptionKey(jwtClaimsSet.aud)) as KeyLike;

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

export const lambdaHandler = middy(handlerClass.handler.bind(handlerClass)).use(
    injectLambdaContext(logger, { clearState: true }),
);
