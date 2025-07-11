const config = {
    commonStackName: process.env.COMMON_STACK_NAME || "common-cri-api",
    testResourcesStackName: process.env.TEST_RESOURCES_STACK_NAME || "test-resources",
    coreInfrastructureStackName: process.env.CORE_INFRA_STACK_NAME || "core-infrastructure",
};

export default config;
