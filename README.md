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
| -------------------------------------------------- | ---------------------- |
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
| ---------------------------------------------------- | ---------------------- |
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

Below runs by using the AWS stub, with the following defaults:

- DEFAULT_CLIENT_ID="ipv-core-stub-aws-build"
- ENVIRONMENT=DEV
- CRI_DEV=common-lambda-dev

NOTE: Since this is defaulting `CRI_DEV=common-lambda-dev`
`common-lambda-dev` is configured in https://github.com/govuk-one-login/ipv-config/blob/main/stubs/di-ipv-core-stub/cris-dev.yaml#L42
and contains keys configured for the common lambda account `di-ipv-cri-common-dev`the `API_GATEWAY_ID_PRIVATE` can be found
in the output of the common lambda stack being targeted i.e the value of `PreMergeDevOnlyApiId` output.

`
STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://cri.core.build.stubs.account.gov.uk" gradle integration-tests:cucumber
`

Run in KBV CRI specify `CRI_DEV=kbv-cri-dev` allows the command below to use keys in `ipv-config` pointing to keys in `di-ipv-cri-kbv-dev` for a common lambda stack deploy in that account.

`CRI_DEV=kbv-cri-dev STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://cri.core.build.stubs.account.gov.uk" gradle integration-tests:cucumber

Run in ADDRESS CRI specify `CRI_DEV=address-cri-dev` allow the command below to use keys in `ipv-config` pointing to keys in `di-ipv-cri-address-dev` for a common lambda stack deploy in that account.

`CRI_DEV=address-cri-dev STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://cri.core.build.stubs.account.gov.uk" gradle integration-tests:cucumber

You can run against localhost as follows:

`
STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="http://localhost:8085" gradle integration-tests:cucumber
`

NOTE: The common-lambda stack has an extra `/pre-merge-create-auth-code` endpoint which it uses to create an authorization code which it needs as prerequisite to test certain paths, since it is not a CRI itself (since it just a collection of common endpoints used by CRI's).

## Check repo for secrets

Run `detect-secrets scan --baseline .secrets.baseline` to check for potential leaked secrets.

Use the keyword and secret exclusion lists in the baseline file to prevent the utility from flagging up specific strings.