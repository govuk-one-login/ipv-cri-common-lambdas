import { VerifierOptions, Verifier } from "@pact-foundation/pact";
import { Logger } from "@aws-lambda-powertools/logger";
import { LogLevel, Constants } from "./utils/constants";

const { LOCAL_HOST, LOCAL_APP_PORT } = Constants;

const CRI_UNDER_TEST = process.env.CRI_UNDER_TEST;

const logger = new Logger({
    logLevel: LogLevel.DEBUG,
    serviceName: CRI_UNDER_TEST,
});

describe("Pact Verification", () => {
    let componentId: string;
    const stateHandlers = {
        "dummyExperianKbvComponentId is the experianKbv CRI component ID": async () => {
            componentId = "dummyExperianKbvComponentId";
            return { description: "ComponentId set" };
        },
        "dummyNinoComponentId is the NINO CRI component ID": async () => {
            componentId = "dummyNinoComponentId";
            return { description: "ComponentId set" };
        },
        "dummyAddressComponentId is the address CRI component ID": async () => {
            componentId = "dummyAddressComponentId";
            return { description: "ComponentId set" };
        },
    };

    const verifierOptions: VerifierOptions = {
        provider: CRI_UNDER_TEST,
        providerBaseUrl: `${LOCAL_HOST}:${LOCAL_APP_PORT}`,
        pactBrokerUrl: `https://${process.env.PACT_BROKER_HOST}?testSource=${
            process.env.PACT_BROKER_SOURCE_SECRET ?? ""
        }`,
        pactBrokerUsername: process.env.PACT_BROKER_USERNAME,
        pactBrokerPassword: process.env.PACT_BROKER_PASSWORD,
        consumerVersionSelectors: [{ mainBranch: true }, { deployedOrReleased: true }],
        publishVerificationResult: true,
        stateHandlers,
        requestFilter: (req, _res, next) => {
            req.headers["component-id"] = componentId;
            // This should not be required, but we were seeing a strange bug where pact was not generating the request with the correct content-length
            req.headers["content-length"] = JSON.stringify(req.body).length.toString();
            next();
        },
        providerVersion: "3.0.0",
        logLevel: "info",
    };

    it(`should verify ${CRI_UNDER_TEST}`, async () => {
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
