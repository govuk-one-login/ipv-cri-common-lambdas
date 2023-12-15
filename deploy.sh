#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")"
set -eu

stack_name="${1:-}"
audit_event_name_prefix="${2:-}"
cri_identifier="${3:-}"

if ! [[ "$stack_name" ]]; then
  [[ $(aws sts get-caller-identity --query Arn --output text) =~ \/([^\/\.]+)\. ]] && user="${BASH_REMATCH[1]}" || exit
  stack_name="$user-common-lambdas"
  echo "» Using stack name '$stack_name'"
fi

sam validate -t infrastructure/lambda/template.yaml
sam validate -t infrastructure/lambda/template.yaml --lint

sam build -t infrastructure/lambda/template.yaml --cached --parallel

sam deploy --stack-name "$stack_name" \
  --no-fail-on-empty-changeset \
  --no-confirm-changeset \
  --resolve-s3 \
  --s3-prefix "$stack_name" \
  --region "${AWS_REGION:-eu-west-2}" \
  --capabilities CAPABILITY_IAM \
  --tags \
  cri:component=ipv-cri-common-lambdas \
  cri:stack-type=dev \
  cri:application=Orange \
  cri:deployment-source=manual \
  --parameter-overrides \
  Environment=dev \
  ${audit_event_name_prefix:+AuditEventNamePrefix=$audit_event_name_prefix} \
  ${cri_identifier:+CriIdentifier=$cri_identifier}
