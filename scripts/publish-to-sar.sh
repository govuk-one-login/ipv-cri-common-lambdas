#!/usr/bin/env bash

set -e

export AWS_PROFILE="common-dev-admin"

aws sso login

SRC_TEMPLATE="infrastructure/lambda/template.yaml"
PKG_TEMPLATE="packaged.yaml"
BUCKET_NAME="barnaby-serverless-app-repo-test-bucket"
REGION="eu-west-2"
APPLICATION_NAME="bc-test-commonlambdas-2025-12"
DEV_ACCOUNT_NUMBER="486210938254"
APPLICATION_ARN="arn:aws:serverlessrepo:$REGION:$DEV_ACCOUNT_NUMBER:applications/$APPLICATION_NAME"

sam validate --template $SRC_TEMPLATE --lint

echo "validated"

sam build --template $SRC_TEMPLATE --cached --parallel

echo "built"

sam package --template $SRC_TEMPLATE --output-template-file $PKG_TEMPLATE --s3-bucket $BUCKET_NAME

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

