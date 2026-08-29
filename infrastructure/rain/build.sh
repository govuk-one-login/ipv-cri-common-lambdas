#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Merging mapping files"
rain merge \
  mappings/cri-config.yaml \
  mappings/environment-config.yaml \
  mappings/ipv-core-stubs.yaml \
  -o mappings/all-mappings.yaml

echo "Merging resource files"
rain merge \
  resources/lambda-functions.yaml \
  resources/dynamo-tables.yaml \
  resources/ssm-params.yaml \
  resources/iam-kms.yaml \
  resources/dev-resources.yaml \
  -o resources/all-resources.yaml

echo "Assembling template.yaml"

# Extract everything before Mappings line
sed -n '1,/^Mappings:/p' template-rain.yaml | sed '$d' > template.yaml

# Add Mappings section
echo "Mappings:" >> template.yaml
sed 's/^/  /' mappings/all-mappings.yaml >> template.yaml

# Add Resources section
echo "" >> template.yaml
echo "Resources:" >> template.yaml
sed 's/^/  /' resources/all-resources.yaml >> template.yaml

# Add Outputs section (everything after Resources line in original)
echo "" >> template.yaml
sed -n '/^Outputs:/,$p' template-rain.yaml >> template.yaml

echo "Building"
sam build -t template.yaml

echo "Done!"