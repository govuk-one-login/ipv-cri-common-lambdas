set -eu

: "${DICTIONARY}" # The dictionary containing the keys to select
: "${KEY_REGEX}"  # The filter to apply to the keys

echo keys="$(
  jq --compact-output --arg keyFilter "$KEY_REGEX" \
    'to_entries| map(select(.key | match($keyFilter)) | .key)' <<< "$DICTIONARY"
)" >> "$GITHUB_OUTPUT"
