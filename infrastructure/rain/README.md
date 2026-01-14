# Pre-req
CLI is authenticated with AWS for Rain CLI to work. The CLI will create an S3 bucket in AWS and upload the code there prior to deploy.
The template.yaml will then reference the code from S3.

# Step 1: Merge mappings

```bash
rain merge mappings/cri-config.yaml mappings/environment-config.yaml mappings/ipv-core-stubs.yaml -o mappings/all-mappings.yaml
```

# Step 2: Merge resources

```bash
rain merge resources/lambda-functions.yaml resources/dynamo-tables.yaml resources/ssm-params.yaml resources/iam-kms.yaml resources/dev-resources.yaml -o resources/all-resources.yaml
```

# Step 3: Package and deploy

```bash
rain pkg template-rain.yaml -o template.yaml
```

```bash
sam build --t template.yaml
```

```bash
sam deploy
```