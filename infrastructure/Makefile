MKDIR_P = mkdir -p
STACK = common-vc-app
accountIDs := 404250751813 #,562670266496, 

.PHONY: out
out:
	$(MKDIR_P) .out/
apply-sar-policy:
	aws serverlessrepo put-application-policy \
	--application-id $$($(call get_applicationId)) \
	--statements Principals="$(subst $(space),$(comma),$(accountIDs))",Actions=Deploy ; \

sar: out deploy package
	aws serverlessrepo create-application \
	--author "GOVUK One Login CRI" \
	--description "Re-usable Common Issue Credential VC Workflow Resources" \
	--name "common-vc-application" \
	--semantic-version "0.1.0" \
	--template-body file://.out/template.yml

package:
	sam package \
	--template-file statemachine/template.yaml \
	--output-template-file .out/template.yml \
	--s3-bucket $$($(call get_bucket)) \
	--s3-prefix $(STACK)

deploy:
	aws cloudformation deploy --stack-name $(STACK) --template-file statemachine/app-bucket/template.yaml --capabilities CAPABILITY_NAMED_IAM

destroy:
	sam delete --stack-name $(STACK) --no-prompts

clean:
	rm -rf .out/

### Helpers ###
define get_bucket
aws cloudformation describe-stacks \
	--stack-name $(STACK) \
	--query 'Stacks[].Outputs[?OutputKey == `CommonVcAppBucketName`].OutputValue' \
	--output text
endef

define get_applicationId
aws serverlessrepo list-applications \
	--query 'Applications[0].ApplicationId' --output text
endef