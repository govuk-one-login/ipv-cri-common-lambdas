import { Logger } from "@aws-lambda-powertools/logger";
export const formatAudience = (audience: string, logger?: Logger) => {
    const audienceApi = audience.includes("review-") ? audience.replace("review-", "api.review-") : audience;

    logger?.info({ message: "Using Audience", audienceApi });
    return audienceApi;
};
