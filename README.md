# di-ipv-cri-oauth-common: DI IPV Credential Issuer Common OAuth Stack

This repository is the home for a shared stack containing resources that handle the OAuth relationship with IPV Core.

## Stack Parameters

> **Note:** All example values are taken from the `ipv-cri-check-hmrc-api` dev environment.

| Parameter | Required | Default | Description | Example |
|----------|----------|---------|-------------|---------|
| AuditEventNamePrefix | Yes | - | The audit event name prefix | `IPV_HMRC_RECORD_CHECK_CRI` |
| AuditTxmaStackName | No | `txma-infrastructure` | The stack containing the TXMA infrastructure | `txma-infrastructure` |
| CSLSDestinationArn | No | `none` | ARN of the CSLSEGRESS destination | `arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython-2` |
| CriIdentifier | Yes | - | The unique credential issuer identifier | `di-ipv-cri-check-hmrc-api` |
| CriAudience | Yes | - | Audience for the CRI | `https://review-hc.dev.account.gov.uk` |
| CriVcIssuer | Yes | - | Issuer for the CRI | `https://review-hc.dev.account.gov.uk` |
| CriPrivateApiGwName | Yes | - | The private API GW name, for Canary alarms | `check-hmrc-cri-api-private` |
| CriPublicApiGwName | Yes | - | The public API GW name, for Canary alarms | `check-hmrc-cri-api-public` |
| DbSessionTTL | No | 7200 | TTL for the Session Table, default 2 hours | 7200 |
| DbCustomerManagedKey | No | `true` | Use a CustomerManagedKey for the DynamoDB Tables | `false` |
| Environment | Yes | - | The deployed environment | `dev` |
| IPVCoreRedirectURI | Yes | - | Redirect URL to IPV CORE | `dev` |
| IPVCoreStubJwksEndpoint | No | `""` (empty string) | Stubbed JWKS endpoint for non-prod environments | `https://test-resources.review-hc.dev.account.gov.uk/.well-known/jwks.json` |
| KeyRotation | No | `true` | Feature flag for ENV_VAR_FEATURE_FLAG_KEY_ROTATION | `false` |
| KeyRotationFallback | No | `false` | Feature flag for ENV_VAR_FEATURE_FLAG_KEY_ROTATION_LEGACY_KEY_FALLBACK | `true` |
| LambdaCodeSigningConfigArn | No | `none` | The ARN of the Code Signing Config to use, provided by the deployment pipeline | `An AWS ARN` |
| LambdaDeploymentPreference | No | `AllAtOnce` | Stubbed JWKS endpoint for non-prod environments | `AllAtOnce` |
| LambdaProvisionedConcurrentExecutions | No | 0 | Stubbed JWKS endpoint for non-prod environments | 1 |
| LambdaVpcConfiguration | Yes | - | Stubbed JWKS endpoint for non-prod environments | `di-devplatform-deploy` |
| PermissionsBoundaryArn | No | `none` | The ARN of the permissions boundary to apply when creating IAM roles | `An AWS ARN` |

## Stack Outputs

> **Note:** Where possible, stack outputs should be consumed instead of the SSM parameters.  
> The SSM parameters are deprecated and will be removed in a future version (exc. clients SSM parameters, these are not being moved into outputs)

| Output Name | Description |
|------------|-------------|
| DbCustomerManagedKeyID | The ID of the CMK used to encrypt DynamoDB tables at rest. Only present if `IsCustomerManagedKeyEnabled` |
| DbSessionTTL | Time to live for a session item (seconds)|
| DbSessionTableName | The name of the session table in DynamoDB |
| DbPersonIdentityTableName | The name of the person identity table in DynamoDB |
| LambdaSessionFunctionName | The name of the session function |
| LambdaAuthorizationFunctionName | The name of the authorisation function |
| LambdaAccessTokenFunctionName | The name of the access token function |
| PreMergeDevOnlyApiId | ID of the dev-only OAuth Common API. Only present if `isDev` |
| VCSigningKeyID | The ID of the KMS key used to sign VCs |

## Hooks

**important:** One you've cloned the repo, run `pre-commit install` to install the pre-commit hooks.
If you have not installed `pre-commit` then please do so [here](https://pre-commit.com/).

## Run Cucumber tests

Below runs and uses the core stub, with the following defaults:

- DEFAULT_CLIENT_ID="ipv-core-stub-aws-build"
- ENVIRONMENT=DEV
- CRI_DEV=common-lambda-dev

NOTE: Since this is defaulting `CRI_DEV=common-lambda-dev`
`common-lambda-dev` is configured in https://github.com/govuk-one-login/ipv-config/blob/main/stubs/di-ipv-core-stub/cris-dev.yaml#L42
and contains keys configured for the common lambda account `di-ipv-cri-common-dev`the `API_GATEWAY_ID_PRIVATE` can be found
in the output of the common lambda stack being targeted i.e the value of `PreMergeDevOnlyApiId` output.

```sh
STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://cri.core.stubs.account.gov.uk" gradle integration-tests:cucumber`
```

Below runs overriding default stub by using the AWS stub

```sh
STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://cri.core.build.stubs.account.gov.uk" DEFAULT_CLIENT_ID=ipv-core-stub-aws-prod gradle integration-tests:cucumber
```

You can run against localhost as follows:

NOTE: Since this is defaulting `CRI_DEV=common-lambda-dev`
`common-lambda-dev` is configured in https://github.com/govuk-one-login/ipv-config/blob/main/stubs/di-ipv-core-stub/cris-dev.yaml#L42
and contains keys configured for the common lambda account `di-ipv-cri-common-dev`the `API_GATEWAY_ID_PRIVATE` can be found
in the output of the common lambda stack being targeted i.e the value of `PreMergeDevOnlyApiId` output.

```sh
STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://cri.core.build.stubs.account.gov.uk" gradle integration-tests:cucumber
```

Run in KBV CRI specify `CRI_DEV=kbv-cri-dev` allows the command below to use keys in `ipv-config` pointing to keys in `di-ipv-cri-kbv-dev` for a common lambda stack deploy in that account.

```sh
CRI_DEV=kbv-cri-dev STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://cri.core.build.stubs.account.gov.uk" gradle integration-tests:cucumber
```

Run in ADDRESS CRI specify `CRI_DEV=address-cri-dev` allow the command below to use keys in `ipv-config` pointing to keys in `di-ipv-cri-address-dev` for a common lambda stack deploy in that account.

```sh
CRI_DEV=address-cri-dev STACK_NAME=di-ipv-cri-common-api-your-stack-name ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="https://cri.core.build.stubs.account.gov.uk" gradle integration-tests:cucumber
```

You can run against localhost as follows:

```sh
STACK_NAME=di-ipv-cri-common-api-your-stack-name CRI_DEV=kbv-cri-dev ENVIRONMENT=dev API_GATEWAY_ID_PRIVATE=xxxx IPV_CORE_STUB_BASIC_AUTH_USER=xxxx IPV_CORE_STUB_BASIC_AUTH_PASSWORD=xxxx IPV_CORE_STUB_URL="http://localhost:8085" gradle integration-tests:cucumber
```

NOTE: The common-lambda stack has an extra `/pre-merge-create-auth-code` endpoint which it uses to create an authorization code which it needs as prerequisite to test certain paths, since it is not a CRI itself (since it just a collection of common endpoints used by CRI's).

## Check repo for secrets

Run `detect-secrets scan --baseline .secrets.baseline` to check for potential leaked secrets.

Use the keyword and secret exclusion lists in the baseline file to prevent the utility from flagging up specific strings.
