CRIS="ADDRESS CHECK_HMRC"

read -ra array <<< "$CRIS"
read -ra array <<< "${array[@]/#/\"}"
read -ra array <<< "${array[@]/%/\"}"
array=$(IFS="," && echo "${array[*]}")

echo "${array[@]}"

read -ra array < <(xargs <<< "$CRIS")
array=("${array[@]/#/\"}") && array=("${array[@]/%/\"}") && json="[$(IFS="," && echo "${array[*]}")]"

echo "${array[@]}"
echo "$json"

tr "${DELIMITER:-$IFS}" '\n' < <(xargs <<< "$STRING")

read -ra values < <(tr '\n' ' ' <<< "$STRING")
jq --raw-input < <(IFS=$'\n' && echo "${values[*]}") | jq --slurp

read -ra cris <<< "$(tr '\n' ' ' <<< "$CRIS")"
regex=$(IFS="|" && echo "${cris[*]}")
echo "regex=$regex" >> "$GITHUB_OUTPUT"

read -ra cris <<< "$(tr '\n' ' ' <<< "$CRIS")"
echo "${cris[*]/%/_ENABLED}"
