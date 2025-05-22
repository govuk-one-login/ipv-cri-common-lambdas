import { APIGatewayProxyEvent, Context, APIGatewayProxyResult } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { LambdaInterface } from "@aws-lambda-powertools/commons/types";
import { handleErrorResponse } from "../../../utils/src/errors/error-response";
import { generateJWKS } from "./services/cache-jwk";

const logger = new Logger({ serviceName: "Mock Jwk Handler" });

export class MockJwkHandler implements LambdaInterface {
    async handler(event: APIGatewayProxyEvent, _context: Context): Promise<APIGatewayProxyResult> {
        try {
            logger.info({ message: "Retrieving JWKS", path: event.path });
            const { jwks } = await generateJWKS();

            if (jwks.keys.length) {
                logger.info({ message: "Retrieved JWKS", ...jwks });

                return {
                    statusCode: 200,
                    body: JSON.stringify(jwks),
                    headers: {
                        "Cache-Control": "max-age=900",
                    },
                };
            }

            logger.error({ message: "JWKS not found or empty" });
            return {
                statusCode: 404,
                body: JSON.stringify({ error: "JWKS not found" }),
            };
        } catch (error: unknown) {
            return handleErrorResponse(error, logger);
        }
    }
}

const mockJwkHandler = new MockJwkHandler();
export const lambdaHandler = mockJwkHandler.handler.bind(mockJwkHandler);
