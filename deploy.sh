#!/usr/bin/env bash
set -e

stack_name="$1"

if [ -z "$stack_name" ]
then
echo "😱 stack name expected as first argument, e.g. ./deploy kbv-common-cri-api-local or address-common-cri-api-local or fraud-common-cri-api-local"
echo "gds aws di-ipv-cri-dev -- ./deploy.sh {{StackName}}"
exit 1
fi

camelCasePrefix=''
if [[ "$stack_name" == *"kbv"* ]]; then
  camelCasePrefix='Kbv'
fi

if [[ "$stack_name" == *"address"* ]]; then
  camelCasePrefix='Address'
fi

if [[ "$stack_name" == *"fraud"* ]]; then
  camelCasePrefix='Fraud'
fi

./gradlew clean
sam validate -t infrastructure/lambda/template.yaml
./gradlew
sam build -t infrastructure/lambda/template.yaml
sam deploy --stack-name "$stack_name" \
   --no-fail-on-empty-changeset \
   --no-confirm-changeset \
   --resolve-s3 \
   --region eu-west-2 \
   --capabilities CAPABILITY_IAM \
   --parameter-overrides \
   CodeSigningEnabled=false \
   Environment=dev \
   AuditEventNamePrefix=/common-cri-parameters/${camelCasePrefix}AuditEventNamePrefix \
   CriIdentifier=/common-cri-parameters/${camelCasePrefix}CriIdentifier 

