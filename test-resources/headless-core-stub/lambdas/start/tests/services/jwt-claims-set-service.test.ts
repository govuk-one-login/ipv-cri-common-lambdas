import { validate as isValidUUID } from "uuid";
import { HeadlessCoreStubError } from "../../src/errors/headless-core-stub-error";
import {
    generateJwtClaimsSet,
    parseJwtClaimsSetOverrides,
    validateClaimsSet,
} from "../../src/services/jwt-claims-set-service";
import { ClaimsSetOverrides } from "../../src/types/claims-set-overrides";
import { TestData } from "../../../../utils/tests/test-data";

describe("jwt-claims-set-service", () => {
    describe("parseJwtClaimsSetOverrides", () => {
        const expectedDefaultOverrides: ClaimsSetOverrides = { client_id: "ipv-core-stub-aws-headless" };

        it("returns ClaimsSetOverrides with default client_id when overrides empty", async () => {
            const result = parseJwtClaimsSetOverrides(JSON.stringify({}));
            expect(result).toEqual(expectedDefaultOverrides);
        });

        it("returns ClaimsSetOverrides with default client_id when overrides empty null", async () => {
            const result = parseJwtClaimsSetOverrides(null);
            expect(result).toEqual(expectedDefaultOverrides);
        });

        it("should return empty overrides when body is empty", async () => {
            const result = parseJwtClaimsSetOverrides("");
            expect(result).toEqual(expectedDefaultOverrides);
        });

        it("returns ClaimsSetOverrides with overidden client_id when client_id set", async () => {
            const result = parseJwtClaimsSetOverrides(JSON.stringify({ client_id: "a-different-client-id" }));
            expect(result).toEqual({ client_id: "a-different-client-id" });
        });

        it("throws error with 400 when invalid JSON", async () => {
            expect(() => {
                parseJwtClaimsSetOverrides("{");
            }).toThrow(new HeadlessCoreStubError("Body is not valid JSON", 400));
        });

        it("returns fully populated ClaimsSetOverrides", async () => {
            const overrides = {
                iss: "unit.test.mock",
                sub: "unit.test.mock",
                aud: "unit.test.mock",
                iat: 100,
                exp: 100,
                nbf: 100,
                response_type: "unit.test.mock",
                client_id: "unit.test.mock",
                redirect_uri: "unit.test.mock",
                state: "unit.test.mock",
                govuk_signin_journey_id: "unit.test.mock",
                shared_claims: {
                    address: [
                        {
                            addressCountry: "GB",
                        },
                    ],
                },
                evidence_requested: { verificationScore: 1 },
                context: "unit.test.mock",
            };

            const body = JSON.stringify(overrides);
            const result = parseJwtClaimsSetOverrides(body);

            expect(result).toEqual(overrides);
        });
    });

    describe("generateJwtClaimsSet", () => {
        it("returns a JwtClaimsSet", async () => {
            const ssmParameters: Record<string, string> = {
                audience: "https://localhost.com",
                issuer: "https://localhost.com",
                redirectUri: "https://localhost.com/callback",
            };

            const overrides: ClaimsSetOverrides = {
                client_id: "ipv-core-stub-aws-headless",
                govuk_signin_journey_id: "d6e00a9b-d66a-4572-b331-318edf307eca",
                iat: 1742384945,
                exp: 1742385244,
                nbf: 1742384945,
                state: "b72b0ac6-4038-44e1-904c-f1e07832f266",
                sub: "urn:fdc:gov.uk:a9fb8e38-0458-4dc0-8bec-2662709cb240",
            };

            const result = await generateJwtClaimsSet(overrides, ssmParameters);

            expect(result).toEqual(TestData.jwtClaimsSet);
        });

        it("returns a JwtClaimsSet with default dynamic values", async () => {
            const ssmParameters: Record<string, string> = {
                audience: "https://localhost.com",
                issuer: "https://localhost.com",
                redirectUri: "https://localhost.com/callback",
            };

            const overrides: ClaimsSetOverrides = { client_id: "ipv-core-stub-aws-headless" };

            const before = Math.round(Date.now() / 1000);
            const jwtClaimsSet = await generateJwtClaimsSet(overrides, ssmParameters);
            const after = Math.round(Date.now() / 1000);
            expect(isValidUUID(jwtClaimsSet.govuk_signin_journey_id || "")).toBeTruthy();
            expect(isValidUUID(jwtClaimsSet.state || "")).toBeTruthy();
            expect(jwtClaimsSet.iat && jwtClaimsSet.iat >= before && jwtClaimsSet.iat <= after);
            expect(jwtClaimsSet.nbf && jwtClaimsSet.nbf <= after);
            expect(jwtClaimsSet.exp && jwtClaimsSet.exp >= after);
            let url;
            try {
                url = new URL(jwtClaimsSet.sub || "");
            } catch (_) {
                return false;
            }
            expect(url).toBeTruthy();
        });

        it("returns a JwtClaimsSet with overridden aud, issuer, redirect", async () => {
            const ssmParameters: Record<string, string> = {
                audience: "https://localhost",
                issuer: "https://localhost",
                redirectUri: "https://localhost/callback",
            };

            const overrides: ClaimsSetOverrides = {
                client_id: "ipv-core-stub-aws-headless",
                aud: "https://overridden",
                iss: "https://overridden",
                redirect_uri: "https://overridden/callback",
            };

            const jwtClaimsSet = await generateJwtClaimsSet(overrides, ssmParameters);

            expect(jwtClaimsSet.aud).toEqual("https://overridden");
            expect(jwtClaimsSet.iss).toEqual("https://overridden");
            expect(jwtClaimsSet.redirect_uri).toEqual("https://overridden/callback");
        });
    });

    describe("validateClaimsSet", () => {
        it("is valid", async () => {
            expect(() => validateClaimsSet(TestData.jwtClaimsSet)).not.toThrow();
        });

        it("is invalid", async () => {
            const invalidClaimsSet = { ...TestData.jwtClaimsSet };
            invalidClaimsSet.iss = "";
            expect(() => validateClaimsSet(invalidClaimsSet)).toThrow(
                new HeadlessCoreStubError('Claims set failed validation: /iss - must match format "uri"', 400),
            );
        });

        it("does not delete context from claim set", async () => {
            const claimsSet = { ...TestData.jwtClaimsSet };
            claimsSet.context = "Test";
            expect(() => validateClaimsSet(claimsSet)).not.toThrow();
            expect(claimsSet.context).toEqual("Test");
        });

        it("formats error message correctly", async () => {
            const invalidClaimsSet = { ...TestData.jwtClaimsSet };
            invalidClaimsSet.iss = "";
            invalidClaimsSet.aud = "";
            expect(() => validateClaimsSet(invalidClaimsSet)).toThrow(
                new HeadlessCoreStubError(
                    'Claims set failed validation: /aud - must match format "uri", /iss - must match format "uri"',
                    400,
                ),
            );
        });
    });
});
