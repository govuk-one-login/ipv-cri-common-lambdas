import { EvidenceRequestSchema } from "../../../src/schemas/evidence-request.schema";

describe("EvidenceRequestSchema", () => {
    describe("valid requests", () => {
        it("should accept an empty object (all fields optional)", () => {
            const result = EvidenceRequestSchema.safeParse({});
            expect(result.success).toBe(true);
        });

        it("should accept a complete valid evidence request", () => {
            const validRequest = {
                scoringPolicy: "gpg45",
                strengthScore: 2,
                verificationScore: 2,
                validityScore: 2,
                activityHistoryScore: 2,
                identityFraudScore: 1,
            };

            const result = EvidenceRequestSchema.safeParse(validRequest);
            expect(result.success).toBe(true);
            if (result.success) {
                expect(result.data).toEqual(validRequest);
            }
        });

        it("should accept partial evidence request with only scoringPolicy", () => {
            const result = EvidenceRequestSchema.safeParse({ scoringPolicy: "gpg45" });
            expect(result.success).toBe(true);
        });

        it("should accept partial evidence request with only scores", () => {
            const result = EvidenceRequestSchema.safeParse({
                strengthScore: 3,
                verificationScore: 1,
            });
            expect(result.success).toBe(true);
        });

        it("should accept minimum valid values", () => {
            const result = EvidenceRequestSchema.safeParse({
                strengthScore: 1,
                verificationScore: 0,
                validityScore: 0,
                activityHistoryScore: 0,
                identityFraudScore: 0,
            });
            expect(result.success).toBe(true);
        });

        it("should accept maximum valid values", () => {
            const result = EvidenceRequestSchema.safeParse({
                strengthScore: 4,
                verificationScore: 4,
                validityScore: 4,
                activityHistoryScore: 4,
                identityFraudScore: 3,
            });
            expect(result.success).toBe(true);
        });
    });

    describe("invalid scoringPolicy", () => {
        it("should reject scoringPolicy that is not 'gpg45'", () => {
            const result = EvidenceRequestSchema.safeParse({ scoringPolicy: "gpg46" });
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].path).toEqual(["scoringPolicy"]);
                expect(result.error.issues[0].message).toContain('Invalid input: expected "gpg45"');
            }
        });

        it("should reject empty string scoringPolicy", () => {
            const result = EvidenceRequestSchema.safeParse({ scoringPolicy: "" });
            expect(result.success).toBe(false);
        });

        it("should reject numeric scoringPolicy", () => {
            const result = EvidenceRequestSchema.safeParse({ scoringPolicy: 45 });
            expect(result.success).toBe(false);
        });
    });

    describe("invalid strengthScore", () => {
        it("should reject strengthScore below minimum (1)", () => {
            const result = EvidenceRequestSchema.safeParse({ strengthScore: 0 });
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].path).toEqual(["strengthScore"]);
                expect(result.error.issues[0].message).toBe("strengthScore must be at least 1");
            }
        });

        it("should reject strengthScore above maximum (4)", () => {
            const result = EvidenceRequestSchema.safeParse({ strengthScore: 5 });
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].path).toEqual(["strengthScore"]);
                expect(result.error.issues[0].message).toBe("strengthScore must be at most 4");
            }
        });

        it("should reject non-integer strengthScore", () => {
            const result = EvidenceRequestSchema.safeParse({ strengthScore: 2.5 });
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].message).toContain("Invalid input: expected int, received number");
            }
        });

        it("should reject string strengthScore", () => {
            const result = EvidenceRequestSchema.safeParse({ strengthScore: "2" });
            expect(result.success).toBe(false);
        });
    });

    describe("invalid verificationScore", () => {
        it("should reject verificationScore below minimum (0)", () => {
            const result = EvidenceRequestSchema.safeParse({ verificationScore: -1 });
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].message).toBe("verificationScore must be at least 0");
            }
        });

        it("should reject verificationScore above maximum (4)", () => {
            const result = EvidenceRequestSchema.safeParse({ verificationScore: 5 });
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].message).toBe("verificationScore must be at most 4");
            }
        });
    });

    describe("invalid validityScore", () => {
        it("should reject validityScore below minimum (0)", () => {
            const result = EvidenceRequestSchema.safeParse({ validityScore: -1 });
            expect(result.success).toBe(false);
        });

        it("should reject validityScore above maximum (4)", () => {
            const result = EvidenceRequestSchema.safeParse({ validityScore: 5 });
            expect(result.success).toBe(false);
        });
    });

    describe("invalid activityHistoryScore", () => {
        it("should reject activityHistoryScore below minimum (0)", () => {
            const result = EvidenceRequestSchema.safeParse({ activityHistoryScore: -1 });
            expect(result.success).toBe(false);
        });

        it("should reject activityHistoryScore above maximum (4)", () => {
            const result = EvidenceRequestSchema.safeParse({ activityHistoryScore: 5 });
            expect(result.success).toBe(false);
        });
    });

    describe("invalid identityFraudScore", () => {
        it("should reject identityFraudScore below minimum (0)", () => {
            const result = EvidenceRequestSchema.safeParse({ identityFraudScore: -1 });
            expect(result.success).toBe(false);
        });

        it("should reject identityFraudScore above maximum (3)", () => {
            const result = EvidenceRequestSchema.safeParse({ identityFraudScore: 4 });
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].message).toBe("identityFraudScore must be at most 3");
            }
        });
    });

    describe("unknown fields", () => {
        it("should reject objects with unknown properties", () => {
            const result = EvidenceRequestSchema.safeParse({
                scoringPolicy: "gpg45",
                unknownField: "value",
            });
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].code).toBe("unrecognized_keys");
                expect(result.error.issues[0].message).toContain("Unrecognized key");
            }
        });
    });

    describe("edge cases", () => {
        it("should reject undefined (undefined is handled before validation in validator)", () => {
            const result = EvidenceRequestSchema.safeParse(undefined);
            expect(result.success).toBe(false);
        });

        it("should reject null", () => {
            const result = EvidenceRequestSchema.safeParse(null);
            expect(result.success).toBe(false);
        });

        it("should reject array", () => {
            const result = EvidenceRequestSchema.safeParse([]);
            expect(result.success).toBe(false);
        });

        it("should reject string", () => {
            const result = EvidenceRequestSchema.safeParse("invalid");
            expect(result.success).toBe(false);
        });
    });
});
