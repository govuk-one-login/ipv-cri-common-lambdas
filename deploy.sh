#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")"
set -eu

stack_name="${1:-}"
audit_event_name_prefix="${2:-}"
cri_identifier="${3:-}"

if ! [[ "$stack_name" ]]; then
  [[ $(aws sts get-caller-identity --query Arn --output text) =~ \/([^\/\.]+)\. ]] && user="${BASH_REMATCH[1]}" || exit
  stack_name="$user-oauth-common"
  echo "» Using stack name '$stack_name'"
fi

sam validate -t infrastructure/template.yaml
sam validate -t infrastructure/template.yaml --lint

sam build -t infrastructure/template.yaml --cached --parallel

sam deploy --stack-name "$stack_name" \
  --no-fail-on-empty-changeset \
  --no-confirm-changeset \
  --resolve-s3 \
  --s3-prefix "$stack_name" \
  --region "${AWS_REGION:-eu-west-2}" \
  --capabilities CAPABILITY_IAM \
  --tags \
  cri:component=ipv-cri-oauth-common \
  cri:deployment-source=manual \
  cri:stack-type=dev \
  --parameter-overrides \
  AuditEventNamePrefix=IPV_COMMON_CRI \
  CriIdentifier=di-ipv-cri-check-hmrc-api \
  CriAudience=https://review-hc.dev.account.gov.uk \
  CriVcIssuer=https://review-hc.dev.account.gov.uk \
  CriPrivateApiGwName=check-hmrc-cri-api-private \
  CriPublicApiGwName=check-hmrc-cri-api-private \
  Environment=dev \
  IPVCoreRedirectURI=https://identity.staging.account.gov.uk/credential-issuer/callback?id=nino \
  IPVCoreStubJwksEndpoint=https://test-resources.review-hc.dev.account.gov.uk/.well-known/jwks.json \
  KeyRotationFallback=true \
  LambdaVpcConfiguration=di-devplatform-deploy
