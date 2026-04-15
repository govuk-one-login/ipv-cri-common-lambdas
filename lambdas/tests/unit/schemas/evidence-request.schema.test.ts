import { describe, expect, it } from "vitest";
import { EvidenceRequestSchema } from "../../../src/schemas/evidence-request.schema";

const allValidValues: Record<string, unknown> = {
    scoringPolicy: "gpg45",
    strengthScore: 2,
    validityScore: 2,
    verificationScore: 2,
    activityHistoryScore: 2,
    identityFraudScore: 1,
};

const invalidValues: Record<string, unknown> = {
    scoringPolicy: "invalid",
    strengthScore: 999,
    validityScore: 999,
    verificationScore: 999,
    activityHistoryScore: 999,
    identityFraudScore: 999,
};

const validValues = (fields: string[], exclude = false) =>
    Object.fromEntries(
        Object.entries(allValidValues).filter(([f]) => (exclude ? !fields.includes(f) : fields.includes(f))),
    );

describe("EvidenceRequestSchema", () => {
    describe.each(Object.keys(allValidValues))("%s required vs optional", (field) => {
        it("Is optional when absent", () => {
            expect(EvidenceRequestSchema.safeParse(validValues([field])).success).toBe(true);
        });

        it("Is validated when present", () => {
            const testData = { ...validValues([field], true), [field]: invalidValues[field] };
            const result = EvidenceRequestSchema.safeParse(testData);

            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.error.issues[0].path).toEqual([field]);
            }
        });
    });

    it("should fail when evidence request is empty", () => {
        const result = EvidenceRequestSchema.safeParse({});
        expect(result.success).toBe(false);
        expect(result.error!.issues[0].message).toBe(
            "Evidence request cannot be empty, it must contain at least one field",
        );
    });

    describe("Should return success true when field values are within value boundaries", () => {
        it.each([
            ["scoringPolicy", "gpg45"],
            ["strengthScore", 1],
            ["strengthScore", 4],
            ["validityScore", 0],
            ["validityScore", 4],
            ["verificationScore", 0],
            ["verificationScore", 4],
            ["activityHistoryScore", 0],
            ["activityHistoryScore", 4],
            ["identityFraudScore", 0],
            ["identityFraudScore", 3],
        ])("%s = %p", (field, value) => {
            const result = EvidenceRequestSchema.safeParse({ ...allValidValues, [field]: value });
            expect(result.success).toBe(true);
        });
    });

    describe("Should return success false when field values are not within value boundaries or are invalid", () => {
        const commonInvalidJsonTypes: Array<[unknown, string]> = [
            [null, "Invalid input: expected number, received null"],
            ["test", "Invalid input: expected number, received string"],
            [[], "Invalid input: expected number, received array"],
            [{}, "Invalid input: expected number, received object"],
            [true, "Invalid input: expected number, received boolean"],
        ];

        const numericFieldTests: Record<string, Array<[unknown, string]>> = {
            strengthScore: [
                [0, "Too small: expected number to be >=1"],
                [5, "Too big: expected number to be <=4"],
                [1.5, "Invalid input: expected int, received number"],
                ...commonInvalidJsonTypes,
            ],
            validityScore: [
                [-1, "Too small: expected number to be >=0"],
                [5, "Too big: expected number to be <=4"],
                [1.5, "Invalid input: expected int, received number"],
                ...commonInvalidJsonTypes,
            ],
            verificationScore: [
                [-1, "Too small: expected number to be >=0"],
                [5, "Too big: expected number to be <=4"],
                [1.5, "Invalid input: expected int, received number"],
                ...commonInvalidJsonTypes,
            ],
            activityHistoryScore: [
                [-1, "Too small: expected number to be >=0"],
                [5, "Too big: expected number to be <=4"],
                [1.5, "Invalid input: expected int, received number"],
                ...commonInvalidJsonTypes,
            ],
            identityFraudScore: [
                [-1, "Too small: expected number to be >=0"],
                [4, "Too big: expected number to be <=3"],
                [1.5, "Invalid input: expected int, received number"],
                ...commonInvalidJsonTypes,
            ],
        };

        // Create the combined test combinations
        const allTests = [
            ["scoringPolicy", null, 'Invalid input: expected "gpg45"'],
            ["scoringPolicy", "gpg46", 'Invalid input: expected "gpg45"'],
            ...Object.entries(numericFieldTests).flatMap(([field, tests]) =>
                tests.map(([value, msg]) => [field, value, msg]),
            ),
        ] as Array<[string, unknown, string]>;

        it.each(allTests)("%s = %p", (field, value, failureErrorMessage) => {
            const result = EvidenceRequestSchema.safeParse({ ...allValidValues, [field as string]: value });
            expect(result.success).toBe(false);
            expect(result.error!.issues[0].path).toEqual([field]);
            expect(result.error!.issues[0].message).toBe(failureErrorMessage);
        });
    });
});
