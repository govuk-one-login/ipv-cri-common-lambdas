// import { Logger } from "@aws-lambda-powertools/logger";
// import { IssuerAuthorizationRequestSchema } from "@govuk-one-login/data-vocab-schemas";
// // import { IssuerAuthorizationRequestClass } from "@govuk-one-login/data-vocab/credentials";
// import Ajv from "ajv";
// import addFormats from "ajv-formats";
// import { v4 as uuidv4 } from "uuid";
// import { HeadlessCoreStubError } from "../errors/headless-core-stub-error";
// import { ClaimsSetOverrides } from "../types/claims-set-overrides";
// import { getSSMParameter } from "./ssm-service";

// const logger = new Logger();

// const COMMON_LAMBDAS_STACK_NAME = process.env.COMMON_LAMBDAS_STACK_NAME || "common-cri-api";

// const ISSUER_SSM_NAME = `/${COMMON_LAMBDAS_STACK_NAME}/clients/ipv-core-stub-aws-headless/jwtAuthentication/issuer`;
// const REDIRECT_URI_SSM_NAME = `/${COMMON_LAMBDAS_STACK_NAME}/clients/ipv-core-stub-aws-headless/jwtAuthentication/redirectUri`;

// export const parseJwtClaimsSetOverrides = (body: string | null): ClaimsSetOverrides => {
//     try {
//         const jwtClaimsSetOverrides = body !== null ? JSON.parse(body) : null;
//         if (jwtClaimsSetOverrides?.aud) {
//             return jwtClaimsSetOverrides as ClaimsSetOverrides;
//         }
//     } catch (e) {
//         throw new HeadlessCoreStubError("Body is not valid JSON", 400);
//     }
//     throw new HeadlessCoreStubError("Missing required body field: aud (audience) not present", 400);
// };

// export const generateJwtClaimsSet = async (overrides: ClaimsSetOverrides) => {
//     const issuer = await getSSMParameter(ISSUER_SSM_NAME);
//     const redirectUri = await getSSMParameter(REDIRECT_URI_SSM_NAME);

//     const now = Date.now();
//     return {
//         iss: overrides.iss || issuer,
//         sub: overrides.sub || "urn:fdc:gov.uk:" + uuidv4(),
//         aud: overrides.aud,
//         iat: overrides.iat || msToSeconds(now),
//         exp: overrides.exp || msToSeconds(now + 5 * 60 * 1000),
//         nbf: overrides.nbf || msToSeconds(now - 1),
//         response_type: overrides.response_type || "code",
//         client_id: overrides.client_id || "ipv-core-stub-aws-headless",
//         redirect_uri: overrides.redirect_uri || redirectUri,
//         state: overrides.state || uuidv4(),
//         govuk_signin_journey_id: overrides.govuk_signin_journey_id || uuidv4(),
//         shared_claims: overrides.shared_claims != null ? overrides.shared_claims : defaultClaims,
//         ...(overrides.evidence_requested && { evidence_requested: overrides.evidence_requested }),
//         ...(overrides.context && { context: overrides.context }),
//         scope: "",
//         nonce: "",
//     } as IssuerAuthorizationRequestClass;
// };

// export const validateClaimsSet = (claimsSet: IssuerAuthorizationRequestClass) => {
//     const ajv = new Ajv({ allErrors: true });
//     addFormats(ajv);
//     const validateCredential = ajv
//         .addSchema(IssuerAuthorizationRequestSchema)
//         .compile(IssuerAuthorizationRequestSchema);
//     if (!validateCredential(claimsSet)) {
//         logger.error(JSON.stringify(validateCredential.errors));
//         throw new HeadlessCoreStubError("Claims set failed validation", 400);
//     }
// };

// const msToSeconds = (ms: number) => Math.round(ms / 1000);

// const defaultClaims = {
//     name: [
//         {
//             nameParts: [
//                 {
//                     type: "GivenName",
//                     value: "KENNETH",
//                 },
//                 {
//                     type: "FamilyName",
//                     value: "DECERQUEIRA",
//                 },
//             ],
//         },
//     ],
//     birthDate: [
//         {
//             value: "1965-07-08",
//         },
//     ],
//     address: [
//         {
//             buildingNumber: "8",
//             streetName: "HADLEY ROAD",
//             addressLocality: "BATH",
//             postalCode: "BA2 5AA",
//             validFrom: "2021-01-01",
//         },
//     ],
// };
