# Test Resources Integration Tests

To run integration tests against a deployed stack, ensure that you are authenticated for the correct account and run:

```
cd integration-tests
STACK_NAME=test-resources COMMON_STACK_NAME=common-cri-api INFRA_STACK_NAME=core-infrastructure npm run test
```