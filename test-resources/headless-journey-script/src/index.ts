import { input } from "./cli-args.ts";
import { invokeApi } from "./apigw-fetch.ts";
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { base64Decode, buildAndSignJwt } from "./crypto.ts";
import { journeyConfig } from "./journey-config.ts";
import { logFinalEnvironment } from "./log.ts";

const environment: {
    sessionJar?: string;
    clientId?: string;
    sessionId?: string;
    redirectUri?: string;
    state?: string;
    audience?: string;
    authorizationCode?: string;
    accessToken?: string;
    vcPayload?: Record<string, unknown>;
} = {};

assert(input.journeyIdentifier);

const criConfig = journeyConfig[input.journeyIdentifier];

assert(criConfig);

describe(`Completes ${input.journeyIdentifier} OAuth journey`, { concurrency: false }, () => {
    it("calls the headless core stub to generate a session JAR", async () => {
        const response = await invokeApi("test-harness", {
            method: "POST",
            path: "/start",
            jsonBody: { ...criConfig.customClaims },
        });

        assert(response.status === 200 && response.body);

        const parsedBody = JSON.parse(response.body);

        environment.sessionJar = parsedBody.request;
        environment.clientId = parsedBody.client_id;
    });

    it("creates a CRI session", async () => {
        const response = await invokeApi("private", {
            method: "POST",
            path: "/session",
            jsonBody: {
                request: environment.sessionJar,
                client_id: environment.clientId,
            },
        });

        assert(response.status === 201 && response.body);

        const parsedBody = JSON.parse(response.body);

        assert("session_id" in parsedBody && "redirect_uri" in parsedBody && "state" in parsedBody);

        environment.sessionId = parsedBody.session_id;
        environment.redirectUri = parsedBody.redirect_uri;
        environment.state = parsedBody.state;

        environment.audience = JSON.parse(base64Decode(parsedBody.state)).aud;
    });

    it(`completes the ${input.journeyIdentifier} journey`, async () => {
        assert(environment.sessionId);
        await criConfig.completeCri({ sessionId: environment.sessionId });
    });

    it("gets an auth code", async () => {
        assert(environment.clientId && environment.redirectUri && environment.sessionId && environment.state);

        const response = await invokeApi("private", {
            method: "GET",
            path: "/authorization",
            headers: {
                "session-id": environment.sessionId,
            },
            queryParameters: {
                redirect_uri: environment.redirectUri,
                client_id: environment.clientId,
                response_type: "code",
                state: environment.state,
                scope: "openid",
            },
        });

        assert(response.status === 200 && response.body);

        const parsedBody = JSON.parse(response.body);

        assert("authorizationCode" in parsedBody && "redirectionURI" in parsedBody && "state" in parsedBody);

        environment.authorizationCode = parsedBody.authorizationCode.value;
    });

    it("exchanges the auth code for an access token", async () => {
        assert(
            environment.authorizationCode && environment.redirectUri && environment.clientId && environment.audience,
        );

        const response = await invokeApi("public", {
            method: "POST",
            path: "/token",
            formEncodedBody: {
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                grant_type: "authorization_code",
                code: environment.authorizationCode,
                redirect_uri: environment.redirectUri,
                client_assertion: await buildAndSignJwt({
                    clientId: environment.clientId,
                    audience: environment.audience,
                }),
            },
        });

        assert(response.status === 200 && response.body);

        const parsedBody = JSON.parse(response.body);

        assert("access_token" in parsedBody);

        environment.accessToken = parsedBody.access_token;
    });

    it("retrieves the verifiable credential", async () => {
        assert(environment.accessToken);

        const response = await invokeApi("public", {
            method: "POST",
            path: "/credential/issue",
            headers: {
                Authorization: `Bearer ${environment.accessToken}`,
            },
        });

        assert(response.status === 200 && response.body);

        const verifiableCredential = response.body;
        const [headerJSON, payloadJSON] = verifiableCredential.split(".").map(base64Decode);

        const [header, payload] = [headerJSON, payloadJSON].map((v) => JSON.parse(v));

        assert(header.typ && header.alg && header.kid);
        assert(
            payload.sub && payload.nbf && payload.iss && payload.exp && payload.vc,
            // && payload.jti | not all CRIs return jti
        );

        environment.vcPayload = payload;
    });
});

after(() => {
    logFinalEnvironment(environment);
});
