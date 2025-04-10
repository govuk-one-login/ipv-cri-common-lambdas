type Config = {
    commonParameterPrefix: string;
    testResourcesParameterPrefix: string;
};
const config: Config = {
    commonParameterPrefix: process.env.AWS_STACK_NAME || "common-cri-api",
    testResourcesParameterPrefix: process.env.TEST_RESOURCES_STACK_NAME || "test-resources",
};

export default config;
