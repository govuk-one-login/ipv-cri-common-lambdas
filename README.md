# di-ipv-cri-common-lambdas
DI IPV Credential Issuer Common Lambdas

This code runs inside its own Repo

This repository is the home for common CRI Lambdas supporting Cloud Formation infrastructure which is shared or sensitive.

The code in this repository is deployed and promoted through the environments using GitHub actions and
the dev platform team implementation.

The automated deployments are triggered on a push to main after PR approval.

GitHub secrets are required for deployment.

Required GitHub secrets:

Common CRI secrets for dev environments:

| Secret                                             | Description            |
|----------------------------------------------------|------------------------|
| ADDRESS_DEV_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME | Upload artifact bucket |
| ADDRESS_DEV_COMMON_CRI_GH_ACTIONS_ROLE_ARN         | Assumed role IAM ARN   |
| ADDRESS_DEV_SIGNING_PROFILE_NAME                   | Signing profile name   |
| FRAUD_DEV_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME   | Upload artifact bucket |
| FRAUD_DEV_COMMON_CRI_GH_ACTIONS_ROLE_ARN           | Assumed role IAM ARN   |
| FRAUD_DEV_SIGNING_PROFILE_NAME                     | Signing profile name   |
| KBV_DEV_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME     | Upload artifact bucket |
| KBV_DEV_COMMON_CRI_GH_ACTIONS_ROLE_ARN             | Assumed role IAM ARN   |
| KBV_POC_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME     | Upload artifact bucket |
| KBV_POC_COMMON_CRI_GH_ACTIONS_ROLE_ARN             | Assumed role IAM ARN   |
| KBV_POC_SIGNING_PROFILE_NAME                       | Signing profile name   |

Common CRI secrets for Build environments:

| Secret                                               | Description            |
|------------------------------------------------------|------------------------|
| ADDRESS_BUILD_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME | Upload artifact bucket |
| ADDRESS_BUILD_COMMON_CRI_GH_ACTIONS_ROLE_ARN         | Assumed role IAM ARN   |
| ADDRESS_BUILD_SIGNING_PROFILE_NAME                   | Signing profile name   |
| FRAUD_BUILD_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME   | Upload artifact bucket |
| FRAUD_BUILD_COMMON_CRI_GH_ACTIONS_ROLE_ARN           | Assumed role IAM ARN   |
| FRAUD_BUILD_SIGNING_PROFILE_NAME                     | Signing profile name   |
| KBV_BUILD_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME     | Upload artifact bucket |
| KBV_BUILD_COMMON_CRI_GH_ACTIONS_ROLE_ARN             | Assumed role IAM ARN   |
| KBV_BUILD_SIGNING_PROFILE_NAME                       | Signing profile name   |

## Repository variables

Each deployment requires a repository variable in the form CRINAME_DEST_ENABLED
with the value set to true i.e. FRAUD_DEV_ENABLED KBV_BUILD_ENABLED

## Hooks

**important:** One you've cloned the repo, run `pre-commit install` to install the pre-commit hooks.
If you have not installed `pre-commit` then please do so [here](https://pre-commit.com/).

## Run Cucumber tests

`STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://di-ipv-core-stub.london.cloudapps.digital" gradle integration-tests:cucumber
`
You can run against local host as follows:

Run the either KBV or ADDRESS front-end and ensure the you start the stub as well

`STACK_NAME=di-ipv-cri-common-api-your-stack-name CRI_DEV=kbv-cri-dev ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="http://localhost:8085" DEFAULT_REDIRECT_URI="http://localhost:8085/callback" gradle integration-tests:cucumber
`
