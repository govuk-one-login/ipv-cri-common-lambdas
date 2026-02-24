import { z } from "zod";

/**
 * https://github.com/govuk-one-login/data-vocab/blob/main/v1/linkml-schemas/evidence.yaml
 */
export const EvidenceRequestSchema = z
    .object({
        scoringPolicy: z
            .literal("gpg45")
            .optional()
            .describe(
                "The scoring policy that is applicable for the evidence requested scores. The current supported scoring policy is `gpg45`.",
            ),

        strengthScore: z
            .number()
            .int()
            .min(1, "strengthScore must be at least 1")
            .max(4, "strengthScore must be at most 4")
            .optional()
            .describe("Evidence strength score (range: 1-4)"),

        verificationScore: z
            .number()
            .int()
            .min(0, "verificationScore must be at least 0")
            .max(4, "verificationScore must be at most 4")
            .optional()
            .describe("Verification score (range: 0-4)"),

        validityScore: z
            .number()
            .int()
            .min(0, "validityScore must be at least 0")
            .max(4, "validityScore must be at most 4")
            .optional()
            .describe("Validity score (range: 0-4)"),

        activityHistoryScore: z
            .number()
            .int()
            .min(0, "activityHistoryScore must be at least 0")
            .max(4, "activityHistoryScore must be at most 4")
            .optional()
            .describe("Activity history score (range: 0-4)"),

        identityFraudScore: z
            .number()
            .int()
            .min(0, "identityFraudScore must be at least 0")
            .max(3, "identityFraudScore must be at most 3")
            .optional()
            .describe("Identity fraud score (range: 0-3)"),
    })
    .strict(); // reject anything else

export type EvidenceRequest = z.infer<typeof EvidenceRequestSchema>;
