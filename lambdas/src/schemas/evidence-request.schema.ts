import { z } from "zod";

// Follows https://github.com/govuk-one-login/data-vocab/blob/main/v1/linkml-schemas/evidence.yaml
const ScoringPolicySchema = z
    .literal("gpg45")
    .optional()
    .describe(
        "The scoring policy that is applicable for the evidence requested scores. The current supported scoring policy is `gpg45`.",
    );
const StrengthScoreSchema = z.number().int().min(1).max(4).optional().describe("Evidence strength score (range: 1-4)");
const ValidityScoreSchema = z.number().int().min(0).max(4).optional().describe("Validity score (range: 0-4)");
const VerificationScoreSchema = z.number().int().min(0).max(4).optional().describe("Verification score (range: 0-4)");
const ActivityHistoryScoreSchema = z
    .number()
    .int()
    .min(0)
    .max(4)
    .optional()
    .describe("Activity history score (range: 0-4)");
const IdentityFraudScoreSchema = z
    .number()
    .int()
    .min(0)
    .max(3)
    .optional()
    .describe("Identity fraud score (range: 0-3)");

export const EvidenceRequestSchema = z
    .strictObject({
        scoringPolicy: ScoringPolicySchema,
        strengthScore: StrengthScoreSchema,
        validityScore: ValidityScoreSchema,
        verificationScore: VerificationScoreSchema,
        activityHistoryScore: ActivityHistoryScoreSchema,
        identityFraudScore: IdentityFraudScoreSchema,
    })
    .refine((data) => Object.keys(data).length > 0, {
        message: "Evidence request cannot be empty, it must contain at least one field",
    });

export type EvidenceRequest = z.infer<typeof EvidenceRequestSchema>;
