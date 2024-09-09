import { VerifierOptions, Verifier } from "@pact-foundation/pact";
import { Logger } from "@aws-lambda-powertools/logger";
import { LogLevel, Provider, Constants } from "../utils/constants";
import path from "path";

const { EXPERIAN_KBV_CRI_TOKEN_PROVIDER } = Provider;
const { LOCAL_HOST, LOCAL_APP_PORT } = Constants;

const logger = new Logger({
    logLevel: LogLevel.DEBUG,
    serviceName: EXPERIAN_KBV_CRI_TOKEN_PROVIDER,
});

const verifierOptions: VerifierOptions = {
    provider: EXPERIAN_KBV_CRI_TOKEN_PROVIDER,
    providerBaseUrl: `${LOCAL_HOST}:${LOCAL_APP_PORT}`,
    // pactBrokerUrl: "https://" + process.env.PACT_BROKER_HOST,
    // pactBrokerUsername: process.env.PACT_BROKER_USERNAME,
    // pactBrokerPassword: process.env.PACT_BROKER_PASSWORD,
    pactUrls: [path.resolve(process.cwd(), "tests/unit/handlers/contract/pact/experian-kbv-cri/pact.json")],
    //consumerVersionSelectors: [{ mainBranch: true }, { deployedOrReleased: true }],
    //publishVerificationResult: true,
    providerVersion: process.env.PACT_PROVIDER_VERSION,
    logLevel: "debug",
};

describe("Pact Verification", () => {
    it("tests against potential new contracts", async () => {
        logger.debug("Starting Pact Verification");

        try {
            const output = await new Verifier(verifierOptions).verifyProvider();
            logger.info("Pact Verification Complete!");
            logger.info("Output: ", output);

            const mismatchCount = Number(output.match(/\d+/)?.[0]);
            expect(mismatchCount).toBe(0);
        } catch (error) {
            logger.error("Pact verification failed :(", { error });

            throw new Error("Pact verification failed.");
        }
    }, 60000);
});
