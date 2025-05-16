import { Logger } from "@aws-lambda-powertools/logger";
import { formatAudience } from "../../src/audience-formatter";

describe("formatAudience", () => {
    it("replaces 'review-' with 'api.review-'", () => {
        const expected = "https://api.review-example.co.uk";

        const actual = formatAudience("https://review-example.co.uk");

        expect(actual).toBe(expected);
    });

    it("returns input unchanged if 'review-' is not present", () => {
        const input = "https://example.co.uk";

        const actual = formatAudience(input);

        expect(actual).toBe(input);
    });

    it("logs when logger is provided", () => {
        const logger: Logger = { info: jest.fn() } as unknown as Logger;

        formatAudience("https://review-example.co.uk", logger);

        expect(logger.info).toHaveBeenCalledWith({
            message: "Using Audience",
            audienceApi: "https://api.review-example.co.uk",
        });
    });

    it("does not throw or log if logger is not provided", () => {
        expect(() => formatAudience("https://review-example.co.uk")).not.toThrow();
    });

    it("handles empty string input gracefully", () => {
        const result = formatAudience("");

        expect(result).toBe("");
    });
});
