#!/usr/bin/env bash

set -e

export AWS_PROFILE="common-dev-admin"

# log into sso if no valid session currently exists
aws sts get-caller-identity || aws sso login

SRC_TEMPLATE="infrastructure/lambda/template.yaml" # used for the build steps
BUILT_TEMPLATE=".aws-sam/build/template.yaml" # output from the build step, used for the package step
PKG_TEMPLATE="packaged.yaml" # output from the package step, used for the publish step

BUCKET_NAME="barnaby-serverless-app-repo-test-bucket"
REGION="eu-west-2"
APPLICATION_NAME="bc-test-commonlambdas-2025-12"
DEV_ACCOUNT_NUMBER="486210938254"
APPLICATION_ARN="arn:aws:serverlessrepo:$REGION:$DEV_ACCOUNT_NUMBER:applications/$APPLICATION_NAME"

sam validate --template $SRC_TEMPLATE --lint

echo "validated"

sam build --template $SRC_TEMPLATE --cached --parallel

echo "built"

sam package --template $BUILT_TEMPLATE --output-template-file $PKG_TEMPLATE --s3-bucket $BUCKET_NAME

echo "packaged"

sam publish --template $PKG_TEMPLATE --region $REGION

echo "published"

read -p "First publish? y/n: " FIRST_PUBLISH

if [[ $FIRST_PUBLISH == "y" ]]; then
  echo "Setting application as public..."
  aws serverlessrepo put-application-policy --region $REGION --application-id $APPLICATION_ARN --statements Principals=*,Actions=Deploy
else
  echo "Received '$FIRST_PUBLISH'. Skipping publishing."
fi

