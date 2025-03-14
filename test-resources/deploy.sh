#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")"
set -eu

stack_name="${1:-}"
common_stack_name="${2:-}"

if ! [[ "$stack_name" ]]; then
  [[ $(aws sts get-caller-identity --query Arn --output text) =~ \/([^\/\.]+)\. ]] && user="${BASH_REMATCH[1]}" || exit
  stack_name="$user-test-resources"
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
  cri:component=ipv-cri-common-test-harness \
  cri:deployment-source=manual \
  cri:stack-type=dev \
  --parameter-overrides \
  Environment=dev \
  ${common_stack_name:+CommonStackName=$common_stack_name}



