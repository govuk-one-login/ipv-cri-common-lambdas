type Config = {
    commonStackName: string;
    testResourcesStackName: string;
};
const config: Config = {
    commonStackName: process.env.COMMON_STACK_NAME || "common-cri-api",
    testResourcesStackName: process.env.TEST_RESOURCES_STACK_NAME || "test-resources",
};

export default config;
