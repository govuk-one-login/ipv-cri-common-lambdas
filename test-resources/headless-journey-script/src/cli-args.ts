import { parseArgs } from "node:util";

const cliOptions = {
    // REQUIRED ARGUMENTS
    // ------------------

    // The 10-character alphanumeric ID of the public APIGW
    publicApiGatewayId: { type: "string", short: "b" /* puBlic */ },

    // The 10-character alphanumeric ID of the private APIGW
    privateApiGatewayId: { type: "string", short: "v" /* priVate */ },

    // The identifier for the intended CRI journey. Look in ./journey-config.ts to see available options.
    journeyIdentifier: { type: "string", short: "j" },

    // The subdomain of the CRI. Looks like 'review-z' usually. Used to construct the test harness API Gateway URL.
    criSubdomain: { type: "string", short: "s" },

    // OPTIONAL ARGUMENTS
    // ------------------

    // The subdomain for the test-resources API Gateway. Used to construct the test harness API Gateway URL.
    testResourcesSubdomain: { type: "string", default: "test-resources" },

    // The environment of the AWS account in which the CRI resides. Used to construct the test harness API Gateway URL.
    awsAccountEnvironment: { type: "string", short: "a", default: "dev" },

    // The AWS region in which the CRI resides.
    awsRegion: { type: "string", short: "r", default: "eu-west-2" },

    // Whether to log requests, responses and other useful debug information.
    verbose: { type: "boolean", default: false },
} as const;

const { values } = parseArgs({
    options: cliOptions,
});

for (const o of Object.keys(cliOptions)) {
    if (!(o in values) || (values as Record<string, unknown>)[o] === undefined) {
        throw new Error(`Missing command line option: ${o}`);
    }
}

export { values as input };
