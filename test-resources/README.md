# Test Resources



This directory contains resources to support automated testing in a common way. This includes:
- [Audit events test harness](audit-events-test-harness/README.md): for testing of audit events sent to SQS

## Using the test resources

To start using the test resources to an account of your choosing follow these steps:
1. Add the relevant deployment pipeline in [identity-common-infra](https://github.com/govuk-one-login/identity-common-infra)
2. Add `{CRI}_ARTIFACTS_BUCKET_NAME`, `{CRI}_ENABLED`, `{CRI}_ROLE_ARN`, `{CRI}_SIGNING_PROFILE_NAME` environment variables to github for the relevant `test-resources-{env}` environments
3. Update the matrix in [package-test-resources workflow](../.github/workflows/package-test-resources.yml) to include your CRI in the `cri` and `include` sections so that it works for your CRI
4. Update the `TestHarnessUrl` mapping in [the template file](./infrastructure/template.yaml) to include your CRI and the dev, build and staging domains. This will be used to created a test harness domain for your account



