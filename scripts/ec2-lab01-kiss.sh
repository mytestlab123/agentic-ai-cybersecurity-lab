#!/usr/bin/bash
set -euo pipefail
umask 077

alias_name=DEV_EC2_LAB_01
rule_name=ec2-imdsv2-check-rnd-lab01
map_root="${HOME:?}/.AGENTS-temp/agentic-ai-cybersecurity-lab"
map_file="${SECCOP_EC2_LAB01_MAP:-$map_root/ec2-lab01-map.json}"

fail() { printf 'BLOCKED: %s\n' "$1" >&2; exit 1; }
usage() {
  printf 'Usage: %s {status|reset --confirm|reopen --confirm}\n' "$0" >&2
  exit 2
}

[[ "$map_file" = /* && "$map_file" == "$map_root"/* ]] || fail 'mapping file must stay under the private SecCop temp directory'
[[ -f "$map_file" ]] || fail 'private LAB_01 mapping file is missing'
[[ "$(stat -c '%a' "$map_file")" == 600 ]] || fail 'mapping file must have mode 600'
command -v jq >/dev/null 2>&1 || fail 'jq is required'
profile=$(jq -er 'select(type == "object" and ([keys[]] | sort | join(",")) == "instance_id,profile,region") | .profile | select(. == "ihis_dev")' "$map_file") || fail 'mapping profile or keys are invalid'
region=$(jq -er '.region | select(. == "ap-southeast-1")' "$map_file") || fail 'mapping region is invalid'
instance_id=$(jq -er '.instance_id | select(type == "string" and test("^i-[0-9a-f]{8,17}$"))' "$map_file") || fail 'mapping instance is invalid'

aws_json() {
  AWS_PROFILE="$profile" AWS_DEFAULT_PROFILE="$profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region" \
    aws --profile "$profile" --region "$region" "$@" --output json
}

instance_tokens() {
  aws_json ec2 describe-instances --instance-ids "$instance_id" |
    jq -er '[.Reservations[].Instances[]] | select(length == 1) | .[0] | select(.InstanceId == $id and .State.Name == "running") | .MetadataOptions.HttpTokens' --arg id "$instance_id"
}

config_state() {
  aws_json configservice get-compliance-details-by-resource \
    --resource-type AWS::EC2::Instance --resource-id "$instance_id" |
    jq -r --arg rule "$rule_name" '[.EvaluationResults[] | select(.EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName == $rule)] | .[0].ComplianceType // "UNKNOWN"'
}

status() {
  local tokens state
  tokens=$(instance_tokens)
  state=$(config_state)
  jq -cn --arg alias "$alias_name" --arg tokens "$tokens" --arg state "$state" \
    '{status:"READY",reason_code:"SECCOP_EC2_LAB01_STATUS",resource_alias:$alias,metadata_http_tokens:$tokens,config_state:$state,mutation_performed:false}'
}

action() {
  local command=$1 desired expected result reason tokens state
  [[ "${2:-}" == --confirm && -z "${3:-}" ]] || usage
  if [[ "$command" == reset ]]; then
    desired=required; expected=COMPLIANT; result=RESET; reason=SECCOP_EC2_LAB01_ALREADY_RESET
  else
    desired=optional; expected=NON_COMPLIANT; result=REOPENED; reason=FINDING_ALREADY_OPEN
  fi
  tokens=$(instance_tokens)
  state=$(config_state)
  if [[ "$tokens" == "$desired" && "$state" == "$expected" ]]; then
    jq -cn --arg alias "$alias_name" --arg state "$state" --arg tokens "$tokens" --arg reason "$reason" \
      '{status:"NOOP",reason_code:$reason,resource_alias:$alias,metadata_http_tokens:$tokens,config_state:$state,mutation_performed:false}'
    return
  fi
  aws_json ec2 modify-instance-metadata-options --instance-id "$instance_id" --http-tokens "$desired" >/dev/null
  aws_json configservice start-config-rules-evaluation --config-rule-names "$rule_name" >/dev/null
  for _ in $(seq 1 36); do
    tokens=$(instance_tokens)
    state=$(config_state)
    if [[ "$tokens" == "$desired" && "$state" == "$expected" ]]; then
      jq -cn --arg alias "$alias_name" --arg state "$state" --arg tokens "$tokens" --arg reason "SECCOP_EC2_LAB01_${result}" \
        '{status:$reason,reason_code:$reason,resource_alias:$alias,metadata_http_tokens:$tokens,config_state:$state,mutation_performed:true}'
      return
    fi
    sleep 10
  done
  fail "LAB_01 did not reach the requested $result state"
}

case "${1:-}" in
  status) [[ -z "${2:-}" ]] || usage; status ;;
  reset|reopen) action "$1" "${2:-}" "${3:-}" ;;
  *) usage ;;
esac
