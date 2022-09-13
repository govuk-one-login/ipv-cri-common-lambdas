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

| Secret                                         | Description            |
|------------------------------------------------|------------------------|
| KBV_DEV_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME | Upload artifact bucket |
| KBV_DEV_COMMON_CRI_GH_ACTIONS_ROLE_ARN         | Assumed role IAM ARN   |
| KBV_POC_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME | Upload artifact bucket |
| KBV_POC_COMMON_CRI_GH_ACTIONS_ROLE_ARN         | Assumed role IAM ARN   |

Common CRI secrets for Build environments:

| Secret                                           | Description            |
|--------------------------------------------------|------------------------|
| KBV_BUILD_COMMON_CRI_ARTIFACT_SOURCE_BUCKET_NAME | Upload artifact bucket |
| KBV_BUILD_COMMON_CRI_GH_ACTIONS_ROLE_ARN         | Assumed role IAM ARN   |

