import { VerifierOptions, Verifier } from "@pact-foundation/pact";
import { Logger } from "@aws-lambda-powertools/logger";
import { LogLevel, Constants } from "./utils/constants";
import path from "path";

const { LOCAL_HOST, LOCAL_APP_PORT } = Constants;

const CRI_UNDER_TEST = process.env.CRI_UNDER_TEST || "TokenProviderPactTest";

const logger = new Logger({
    logLevel: LogLevel.DEBUG,
    serviceName: CRI_UNDER_TEST,
});

describe("Pact Verification", () => {
    let componentId: string;
    const experianStates = {
        "dummyExperianKbvComponentId is the experianKbv CRI component ID": async () => {
            componentId = "dummyExperianKbvComponentId";
            return Promise.resolve({ description: "ComponentId set" });
        },
        "ExperianKbv CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures": async () =>
            Promise.resolve(),
    };
    const checkHmrcNinoStates = {
        "dummyNinoComponentId is the NINO CRI component ID": async () => {
            componentId = "dummyNinoComponentId";
            return Promise.resolve({ description: "ComponentId set" });
        },
        "NINO CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures": async () => Promise.resolve(),
    };

    const verifierOptions: VerifierOptions = {
        provider: CRI_UNDER_TEST,
        providerBaseUrl: `${LOCAL_HOST}:${LOCAL_APP_PORT}`,
        // pactBrokerUrl: "https://" + process.env.PACT_BROKER_HOST,
        // pactBrokerUsername: process.env.PACT_BROKER_USERNAME,
        // pactBrokerPassword: process.env.PACT_BROKER_PASSWORD,
        pactUrls: [
            path.resolve(process.cwd(), "tests/unit/handlers/contract/pact/experian-kbv-cri/pact.json"),
            path.resolve(process.cwd(), "tests/unit/handlers/contract/pact/check-hmrc-cri/pact.json"),
        ],
        //consumerVersionSelectors: [{ mainBranch: true }, { deployedOrReleased: true }],
        //publishVerificationResult: true,
        stateHandlers: {
            ...experianStates,
            ...checkHmrcNinoStates,
        },
        requestFilter: (req, _res, next) => {
            req.headers["component-id"] = componentId;
            // This should not be required, but we were seeing a strange bug where pact was not generating the request with the correct content-length
            req.headers["content-length"] = JSON.stringify(req.body).length.toString();
            next();
        },
        providerVersion: "3.0.0",
        logLevel: "info",
    };

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
    });
});
