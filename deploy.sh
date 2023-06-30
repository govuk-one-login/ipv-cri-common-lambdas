#!/usr/bin/env bash
set -e

RED="\033[1;31m"
GREEN="\033[1;32m"
NOCOLOR="\033[0m"

stack_name="$1"
audit_event_name_prefix="$2"
cri_identifier="$3"

if [ -z "$stack_name" ]
then
echo -e "😱 ${RED}stack name expected as first argument, e.g. ${GREEN}./deploy.sh common-lambdas-my-name${NOCOLOR}"
exit 1
fi

if [ -z "$audit_event_name_prefix" ]
then
  audit_event_name_prefix="/common-cri-parameters/KbvAuditEventNamePrefix"
fi

if [ -z "$cri_identifier" ]
then
  cri_identifier="/common-cri-parameters/KbvCriIdentifier"
fi


echo -e "👉 deploying common lambdas with:"
echo -e "\tstack name: ${GREEN}$stack_name${NOCOLOR}"
echo -e "\tAuditEventNamePrefix SSM key ${GREEN}$audit_event_name_prefix${NOCOLOR}"
echo -e "\tCriIdentifier SSM key ${GREEN}$cri_identifier${NOCOLOR}"

./gradlew clean
sam validate -t infrastructure/lambda/template.yaml
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
   AuditEventNamePrefix=$audit_event_name_prefix \
   CriIdentifier=$cri_identifier
