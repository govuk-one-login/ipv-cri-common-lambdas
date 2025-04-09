import { IssuerAuthorizationRequestSchema } from "@govuk-one-login/data-vocab-schemas";
import { IssuerAuthorizationRequestClass } from "@govuk-one-login/data-vocab/credentials";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { v4 as uuidv4 } from "uuid";
import { HeadlessCoreStubError } from "../errors/headless-core-stub-error";
import { ClaimsSetOverrides } from "../types/claims-set-overrides";
import { JWTClaimsSet } from "../types/jwt-claims-set";
import { logger } from "../start-handler";
import { base64Encode } from "../../../../utils/src/base64";

export const DEFAULT_CLIENT_ID = "ipv-core-stub-aws-headless";

export const parseJwtClaimsSetOverrides = (body: string | null): ClaimsSetOverrides => {
    try {
        const claimsSetOverrides = body ? JSON.parse(body) : {};
        if (!claimsSetOverrides.client_id) {
            claimsSetOverrides.client_id = DEFAULT_CLIENT_ID;
        }
        return claimsSetOverrides;
    } catch (e) {
        throw new HeadlessCoreStubError("Body is not valid JSON", 400);
    }
};

export const generateJwtClaimsSet = async (overrides: ClaimsSetOverrides, ssmParameters: Record<string, string>) => {
    const audience = overrides.aud || ssmParameters["audience"];
    const issuer = overrides.iss || ssmParameters["issuer"];
    const redirectUri = overrides.redirect_uri || ssmParameters["redirectUri"];
    const state = overrides.state || base64Encode(JSON.stringify({ aud: audience, redirect_uri: redirectUri }));

    const now = Date.now();
    return {
        iss: issuer,
        sub: overrides.sub || "urn:fdc:gov.uk:" + uuidv4(),
        aud: audience,
        iat: overrides.iat || msToSeconds(now),
        exp: overrides.exp || msToSeconds(now + 5 * 60 * 1000),
        nbf: overrides.nbf || msToSeconds(now - 1),
        response_type: overrides.response_type || "code",
        client_id: overrides.client_id,
        redirect_uri: redirectUri,
        state,
        govuk_signin_journey_id: overrides.govuk_signin_journey_id || uuidv4(),
        shared_claims: overrides.shared_claims != null ? overrides.shared_claims : defaultClaims,
        ...(overrides.evidence_requested && { evidence_requested: overrides.evidence_requested }),
        ...(overrides.context && { context: overrides.context }),
    } as JWTClaimsSet;
};

export const validateClaimsSet = (claimsSet: JWTClaimsSet) => {
    //Current data-vocab schemas do not exactly match what our CRIs so we have to validate context manually and add scope and nonce
    const claimsSetCopy = { ...claimsSet };
    if (claimsSetCopy.context) {
        if (typeof claimsSetCopy.context !== "string") {
            logger.error("Invalid context field");
            throw new HeadlessCoreStubError("Claims set failed validation", 400);
        }
        delete claimsSetCopy.context;
    }
    const dataVocabClaimsSet: IssuerAuthorizationRequestClass = { ...claimsSetCopy, scope: "", nonce: "" };

    const ajv = new Ajv({ allErrors: true });
    addFormats(ajv);
    const validateCredential = ajv
        .addSchema(IssuerAuthorizationRequestSchema)
        .compile(IssuerAuthorizationRequestSchema);

    if (!validateCredential(dataVocabClaimsSet)) {
        const errorMessages: string[] = [];
        if (validateCredential.errors) {
            logger.error(JSON.stringify(validateCredential.errors));
            validateCredential.errors?.forEach((error) => {
                errorMessages.push(error.instancePath + " - " + error.message);
            });
        }

        const errorDetails = errorMessages?.length ? ": " + errorMessages.join(", ") : "";
        throw new HeadlessCoreStubError("Claims set failed validation" + errorDetails, 400);
    }
};

const msToSeconds = (ms: number) => Math.floor(ms / 1000);

const defaultClaims = {
    name: [
        {
            nameParts: [
                {
                    type: "GivenName",
                    value: "KENNETH",
                },
                {
                    type: "FamilyName",
                    value: "DECERQUEIRA",
                },
            ],
        },
    ],
    birthDate: [
        {
            value: "1965-07-08",
        },
    ],
    address: [
        {
            buildingNumber: "8",
            streetName: "HADLEY ROAD",
            addressLocality: "BATH",
            postalCode: "BA2 5AA",
            validFrom: "2021-01-01",
        },
    ],
};
