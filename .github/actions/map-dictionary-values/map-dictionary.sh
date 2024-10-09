set -eu

: "${DICTIONARY}"  # The dictionary containing the values to map
: "${VALUE_MAP}"   # The mapping of values to the new values
: "${KEY_REGEX:-}" # The filter to apply to the keys

jq --compact-output --arg keyFilter "$KEY_REGEX" --argjson map "$VALUE_MAP" \
  'with_entries(
    if $keyFilter != "" then
      select(.key | match($keyFilter))
    else . end |

    .value = ($map[.value] // .value)
  )' <<< "$DICTIONARY"
