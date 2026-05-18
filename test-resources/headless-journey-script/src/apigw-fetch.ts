import { APIGatewayClient, GetResourcesCommand, TestInvokeMethodCommand } from "@aws-sdk/client-api-gateway";
import { input } from "./cli-args.ts";
import { createSignedFetcher } from "aws-sigv4-fetch";
import assert from "node:assert";
import { error, logIfVerbose } from "./log.ts";

const client = new APIGatewayClient();

const signedFetch = createSignedFetcher({
    service: "execute-api",
    region: input.awsRegion,
});

type BasicHttpMethod = "POST" | "GET" | "PUT" | "DELETE";

interface Request {
    method: BasicHttpMethod;
    path: `/${string}`;
    headers?: Record<string, string>;
    jsonBody?: Record<string, unknown> | unknown[];
    formEncodedBody?: Record<string, string>;
    queryParameters?: Record<string, string>;
}

interface Response {
    status: number;
    body?: string;
    headers: Record<string, string>;
}

function serialiseBody({ jsonBody, formEncodedBody }: Request) {
    if (jsonBody)
        return {
            contentTypeHeader: { "Content-Type": "application/json" },
            serialisedBody: JSON.stringify(jsonBody),
        };
    if (formEncodedBody)
        return {
            contentTypeHeader: { "Content-Type": "application/x-www-form-encoded" },
            serialisedBody: new URLSearchParams(formEncodedBody).toString(),
        };

    return {};
}

/**
 * If we send 'redirect_uri=https%3A%2F%2Ftest-resources.review-hc.dev.account.gov.uk%2Fcallback'
 * then the authorization function fails as it expects 'https://test-resources.review-hc.dev.account.gov.uk/callback'.
 *
 * Therefore, we can't use the built-in 'new URLSearchParams(request.queryParameters)' and must concatenate strings directly instead.
 */
function concatenateQueryParams(params: Record<string, string>) {
    return Object.entries(params)
        .map(([k, v]) => `${k}=${v}`)
        .join("&");
}

export async function invokeApi(gateway: "private" | "public" | "test-harness", request: Request): Promise<Response> {
    const { contentTypeHeader, serialisedBody } = serialiseBody(request);

    const queryString = request.queryParameters ? `?${concatenateQueryParams(request.queryParameters)}` : "";

    logIfVerbose(`Requesting ${gateway} API - ${request.method} "${request.path}":`, request);

    if (gateway === "test-harness") {
        const response = await signedFetch(
            `https://${input.testResourcesSubdomain}.${input.criSubdomain}.${input.awsAccountEnvironment}.account.gov.uk${request.path}${queryString}`,
            {
                method: request.method,
                body: serialisedBody,
                headers: { ...request.headers, ...contentTypeHeader },
            },
        );

        const body = await response.text();

        if (response.status >= 400)
            error(`Received error response from ${request.method} "${request.path}":`, {
                status: response.status,
                body,
            });
        else {
            logIfVerbose(`Received response from ${request.method} "${request.path}":`, {
                status: response.status,
                body,
            });
        }

        return {
            status: response.status,
            body,
            headers: Object.fromEntries(response.headers.entries()),
        };
    } else {
        const gatewayId = gateway === "private" ? input.privateApiGatewayId : input.publicApiGatewayId;

        // AWS resource ID is required to use TestInvokeMethodCommand
        const resources = await client.send(
            new GetResourcesCommand({
                restApiId: gatewayId,
                limit: 500,
            }),
        );
        const resourceId = resources.items?.find((r) => r.path === request.path)?.id;

        assert(resourceId);

        const invokeCommand = new TestInvokeMethodCommand({
            restApiId: gatewayId,
            httpMethod: request.method,
            resourceId,
            pathWithQueryString: `${request.path}${queryString}`,
            body: serialisedBody,
            headers: {
                ...request.headers,
                ...contentTypeHeader,
            },
        });

        const cmdOutput = await client.send(invokeCommand);

        if (!cmdOutput.status || cmdOutput.status >= 400) {
            error(`Received error response from ${request.method} "${request.path}":`, {
                status: cmdOutput.status,
                body: cmdOutput.body,
            });
        } else {
            logIfVerbose(`Received response from ${request.method} "${request.path}":`, {
                status: cmdOutput.status,
                body: cmdOutput.body,
            });
        }

        return {
            status: cmdOutput.status ?? -1,
            body: cmdOutput.body,
            headers: cmdOutput.headers ?? {},
        };
    }
}
