import { clearCaches } from "@aws-lambda-powertools/parameters";
import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { mockClient } from "aws-sdk-client-mock";
import { validate as isValidUUID } from "uuid";
import { HeadlessCoreStubError } from "../../src/errors/headless-core-stub-error";
import {
    generateJwtClaimsSet,
    parseJwtClaimsSetOverrides,
    validateClaimsSet,
} from "../../src/services/jwt-claims-set-service";
import { ClaimsSetOverrides } from "../../src/types/claims-set-overrides";
import { TestData } from "../test-data";

describe("jwt-claims-set-service", () => {
    describe("parseJwtClaimsSetOverrides", () => {
        it("returns ClaimsSetOverrides with aud", async () => {
            const body = JSON.stringify({ aud: "unit.test.mock" });
            const result = parseJwtClaimsSetOverrides(body);

            const expectedOverrides: ClaimsSetOverrides = { aud: "unit.test.mock" };

            expect(result).toEqual(expectedOverrides);
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

            const expectedOverrides: ClaimsSetOverrides = overrides;

            expect(result).toEqual(expectedOverrides);
        });

        it("throws error with 400 when invalid JSON", async () => {
            expect(() => {
                parseJwtClaimsSetOverrides("");
            }).toThrow(new HeadlessCoreStubError("Body is not valid JSON", 400));
        });

        it("throws error with 400 when body is null", async () => {
            expect(() => {
                parseJwtClaimsSetOverrides(null);
            }).toThrow(new HeadlessCoreStubError("Missing required body field: aud (audience) not present", 400));
        });

        it("throws error with 400 when body does not contain aud field", async () => {
            const body = JSON.stringify({ iss: "issuer" });
            expect(() => {
                parseJwtClaimsSetOverrides(body);
            }).toThrow(new HeadlessCoreStubError("Missing required body field: aud (audience) not present", 400));
        });

        it("throws error with 400 when body contains empty aud field", async () => {
            const body = JSON.stringify({ aud: "" });
            expect(() => {
                parseJwtClaimsSetOverrides(body);
            }).toThrow(new HeadlessCoreStubError("Missing required body field: aud (audience) not present", 400));
        });
    });

    describe("generateJwtClaimsSet", () => {
        const mockSSMClient = mockClient(SSMClient);

        afterEach(() => {
            mockSSMClient.reset();
            clearCaches();
        });

        it("returns a JwtClaimsSet", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/issuer",
                })
                .resolvesOnce({ Parameter: { Value: "https://localhost.com" } });
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/redirectUri",
                })
                .resolvesOnce({ Parameter: { Value: "https://localhost.com/callback" } });

            const overrides: ClaimsSetOverrides = {
                aud: "https://localhost.com",
                govuk_signin_journey_id: "d6e00a9b-d66a-4572-b331-318edf307eca",
                iat: 1742384945,
                exp: 1742385244,
                nbf: 1742384945,
                state: "b72b0ac6-4038-44e1-904c-f1e07832f266",
                sub: "urn:fdc:gov.uk:a9fb8e38-0458-4dc0-8bec-2662709cb240",
            };

            const result = await generateJwtClaimsSet(overrides);

            expect(result).toEqual(TestData.jwtClaimsSet);
        });

        it("returns a JwtClaimsSet with default dynamic values", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/issuer",
                })
                .resolvesOnce({ Parameter: { Value: "issuer" } });
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/redirectUri",
                })
                .resolvesOnce({ Parameter: { Value: "redirect_uri" } });

            const overrides: ClaimsSetOverrides = {
                aud: "aud",
            };

            const before = Math.round(Date.now() / 1000);
            const jwtClaimsSet = await generateJwtClaimsSet(overrides);
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

        it("returns 500 if unable to retrieve an issuer SSM param", async () => {
            await expect(generateJwtClaimsSet({ aud: "https://localhost.com" })).rejects.toThrow(
                new HeadlessCoreStubError(
                    "Error retrieving /common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/issuer",
                    500,
                ),
            );
        });

        it("returns 500 if unable to retrieve an redirectUri SSM param", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/issuer",
                })
                .resolvesOnce({ Parameter: { Value: "https://localhost.com" } });

            await expect(generateJwtClaimsSet({ aud: "https://localhost.com" })).rejects.toThrow(
                new HeadlessCoreStubError(
                    "Error retrieving /common-cri-api/clients/ipv-core-stub-aws-headless/jwtAuthentication/redirectUri",
                    500,
                ),
            );
        });
    });

    describe("validateClaimsSet", () => {
        it("is valid", async () => {
            expect(() => validateClaimsSet(TestData.jwtClaimsSet)).not.toThrow();
        });

        it("is invalid", async () => {
            expect(() =>
                validateClaimsSet({
                    client_id: "",
                    nonce: "",
                    redirect_uri: "",
                    response_type: "",
                    scope: "",
                    state: "",
                }),
            ).toThrow(new HeadlessCoreStubError("Claims set failed validation", 400));
        });
    });
});
