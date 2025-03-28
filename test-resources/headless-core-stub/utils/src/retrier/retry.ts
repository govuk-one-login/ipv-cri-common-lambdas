import { Logger } from "@aws-lambda-powertools/logger";
export interface RetryConfig {
    maxRetries: number;
    delayInMs: number;
    initialDelayMs: number;
}

const defaultRetryConfig: RetryConfig = {
    maxRetries: 3,
    delayInMs: 200,
    initialDelayMs: 100,
};

export const withRetry = async <T>(
    fn: () => Promise<T>,
    logger: Logger = new Logger(),
    config: RetryConfig = defaultRetryConfig,
): Promise<T> => {
    const { maxRetries, delayInMs, initialDelayMs } = config;
    let exception: Error;
    if (initialDelayMs > 0) {
        logger.info(`Initial delay of ${initialDelayMs} ms before first attempt.`);
        await new Promise((resolve) => setTimeout(resolve, initialDelayMs));
    }

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            return await fn();
        } catch (error: unknown) {
            if (!(error instanceof Error)) {
                exception = new Error(String(error));
            }
            exception = error as Error;
            if (attempt < maxRetries - 1) {
                const delay = delayInMs * Math.pow(2, attempt);
                const retryMessage = `Retrying in ${delay} ms... Attempt ${attempt + 1}/${maxRetries}`;
                logger.warn(retryMessage, { attempt, delay, exception });
                await new Promise((resolve) => setTimeout(resolve, delay));
            } else {
                logger.error("Max retries reached. Operation failed.", { exception });
                throw exception;
            }
        }
    }
    throw new Error("Unexpected error");
};
