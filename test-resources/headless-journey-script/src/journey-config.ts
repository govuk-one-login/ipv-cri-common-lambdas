import assert from "node:assert/strict";
import { invokeApi } from "./apigw-fetch.ts";

interface CriExecutorFunctionInput {
    sessionId: string;
}

interface CriConfig {
    customClaims?: Record<string, unknown>;
    completeCri: (input: CriExecutorFunctionInput) => Promise<void>;
}

export const journeyConfig: Record<string, CriConfig> = {
    CHECK_HMRC_HAPPY: {
        completeCri: async function ({ sessionId }) {
            const response = await invokeApi("private", {
                method: "POST",
                path: "/check",
                headers: {
                    "session-id": sessionId,
                },
                jsonBody: {
                    nino: "AA000000B",
                },
            });

            assert(response.status === 200);
        },
    },
    ADDRESS_HAPPY: {
        completeCri: async function ({ sessionId }) {
            const response = await invokeApi("private", {
                method: "PUT",
                path: "/address",
                headers: { session_id: sessionId },
                jsonBody: [
                    {
                        uprn: 100000000000,
                        buildingNumber: "10",
                        streetName: "street",
                        addressLocality: "City",
                        postalCode: "SW1A 2AA",
                        addressCountry: "GB",
                        validFrom: "2000-01-01",
                    },
                ],
            });

            assert(response.status === 204);
        },
    },
    EXPERIAN_KBV_HAPPY: {
        completeCri: async function ({ sessionId }) {
            const kennethAnswers: Record<string, string> = {
                Q00042: "OVER £550 UP TO £600",
                Q00015: "UP TO £60,000",
                Q00018: "UP TO £600",
            };

            let questionResponse = await invokeApi("private", {
                method: "GET",
                path: "/question",
                headers: { "session-id": sessionId },
            });

            let questionStatus = questionResponse.status;

            assert(questionStatus === 200);

            // 204 response status from question API indicates no further questions
            while (questionStatus === 200) {
                assert(questionResponse.body);

                const questionInfo: {
                    text: string;
                    tooltip: string;
                    questionID: string;
                    answerFormat: { identifier: string; fieldType: string; answerList: string[] };
                } = JSON.parse(questionResponse.body);

                const answerResponse = await invokeApi("private", {
                    method: "POST",
                    path: "/answer",
                    headers: { "session-id": sessionId },
                    jsonBody: {
                        questionId: questionInfo.questionID,
                        answer: kennethAnswers[questionInfo.questionID],
                    },
                });

                assert(answerResponse.status === 200);

                questionResponse = await invokeApi("private", {
                    method: "GET",
                    path: "/question",
                    headers: { "session-id": sessionId },
                });

                questionStatus = questionResponse.status;
            }
        },
    },
};
