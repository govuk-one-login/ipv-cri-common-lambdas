type Config = {
    commonParameterPrefix: string;
    testResourcesParameterPrefix: string;
    sessionTableName: string;
};
const config: Config = {
    commonParameterPrefix: process.env.AWS_STACK_NAME || "common-cri-api",
    testResourcesParameterPrefix: process.env.TEST_RESOURCES_STACK_NAME || "test-resources",
    sessionTableName: process.env.SESSION_TABLE || "session-common-cri-api",
};

export default config;
