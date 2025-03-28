import { Logger } from "@aws-lambda-powertools/logger";
import { withRetry, RetryConfig } from "../../src/retrier/retry";

describe("withRetry", () => {
    let mockLogger: Logger;

    beforeEach(() => {
        mockLogger = {
            info: jest.fn(),
            warn: jest.fn(),
            error: jest.fn(),
        } as unknown as Logger;
    });

    it("succeeds on the first attempt without retries", async () => {
        const mockFn = jest.fn().mockResolvedValue("success");

        const result = await withRetry(mockFn, mockLogger);

        expect(result).toBe("success");
        expect(mockFn).toHaveBeenCalledTimes(1);
        expect(mockLogger.warn).not.toHaveBeenCalled();
    });

    it("retries on failure and succeed before max retries", async () => {
        const mockFn = jest.fn().mockRejectedValueOnce(new Error("First error")).mockResolvedValueOnce("success");

        const result = await withRetry(mockFn, mockLogger);

        expect(result).toBe("success");
        expect(mockFn).toHaveBeenCalledTimes(2);
        expect(mockLogger.warn).toHaveBeenCalledWith(
            expect.stringContaining("Retrying in"),
            expect.objectContaining({ attempt: 0, delay: 200, exception: new Error("First error") }),
        );
    });

    it("throws an error after max retries are reached", async () => {
        const retryConfig: RetryConfig = { maxRetries: 3, delayInMs: 100, initialDelayMs: 50 };
        const mockFn = jest.fn().mockRejectedValue(new Error("Persistent error"));

        await expect(withRetry(mockFn, mockLogger, retryConfig)).rejects.toThrow("Persistent error");

        expect(mockFn).toHaveBeenCalledTimes(3);
        expect(mockLogger.error).toHaveBeenCalledWith(
            expect.stringContaining("Max retries reached"),
            expect.objectContaining(new Error("Persistent error")),
        );
    });

    it("applies an initial delay before the first attempt", async () => {
        const retryConfig: RetryConfig = { maxRetries: 1, delayInMs: 100, initialDelayMs: 200 };
        const mockFn = jest.fn().mockResolvedValue("success");

        const delaySpy = jest.spyOn(global, "setTimeout");
        await withRetry(mockFn, mockLogger, retryConfig);

        expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining("Initial delay of 200 ms"));
        expect(delaySpy).toHaveBeenCalledWith(expect.any(Function), 200);
        delaySpy.mockRestore();
    });

    it("exponentially increases the delay on each retry", async () => {
        const retryConfig: RetryConfig = { maxRetries: 4, delayInMs: 100, initialDelayMs: 0 };
        const mockFn = jest.fn().mockRejectedValue(new Error("Error"));

        const delaySpy = jest.spyOn(global, "setTimeout");
        await expect(withRetry(mockFn, mockLogger, retryConfig)).rejects.toThrow();

        expect(delaySpy).toHaveBeenCalledWith(expect.any(Function), 100);
        expect(delaySpy).toHaveBeenCalledWith(expect.any(Function), 200);
        expect(delaySpy).toHaveBeenCalledWith(expect.any(Function), 400);

        delaySpy.mockRestore();
    });

    it("handles unknown errors correctly", async () => {
        const mockFn = jest.fn().mockRejectedValue(new Error("Unexpected error"));

        await expect(withRetry(mockFn, mockLogger)).rejects.toThrow("Unexpected error");
        expect(mockLogger.error).toHaveBeenCalledWith(
            expect.stringContaining("Max retries reached. Operation failed."),
            expect.objectContaining(new Error("Unexpected error")),
        );
    });
});
