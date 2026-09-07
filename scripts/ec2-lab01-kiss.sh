#!/usr/bin/bash
set -euo pipefail
umask 077

alias_name=DEV_EC2_LAB_01
rule_name=ec2-imdsv2-check-rnd-lab01
map_root="${HOME:?}/.AGENTS-temp/agentic-ai-cybersecurity-lab"
map_file="${SECCOP_EC2_LAB01_MAP:-$map_root/ec2-lab01-map.json}"

fail() { printf 'BLOCKED: %s\n' "$1" >&2; exit 1; }
usage() {
  printf 'Usage: %s {configure --instance-id <id>|status|reset --confirm|reopen --confirm}\n' "$0" >&2
  exit 2
}

map_hint() { printf '%s configure --instance-id <private-lab01-instance-id>' "$0"; }

validate_map_path() {
  [[ "$map_file" = /* && "$map_file" == "$map_root"/* ]] || fail 'mapping file must stay under the private SecCop temp directory'
}

load_mapping() {
  validate_map_path
  [[ -f "$map_file" ]] || fail "LAB_01 mapping is missing; run: $(map_hint)"
  [[ "$(stat -c '%a' "$map_file")" == 600 ]] || fail "LAB_01 mapping must have mode 600; run chmod 600 or: $(map_hint)"
  command -v jq >/dev/null 2>&1 || fail 'jq is required'
  local keyset candidate
  keyset=$(jq -er 'if type == "object" then ([keys[]] | sort | join(",")) else empty end' "$map_file") || fail "LAB_01 mapping JSON is invalid; run: $(map_hint)"
  [[ "$keyset" == 'instance_id,profile,region' ]] || fail "LAB_01 mapping must contain only instance_id, profile, and region; run: $(map_hint)"
  profile=$(jq -er '.profile | strings' "$map_file") || fail "LAB_01 mapping has no profile; run: $(map_hint)"
  [[ "$profile" == 'ihis_dev' ]] || fail "LAB_01 mapping profile must be ihis_dev; run: $(map_hint)"
  region=$(jq -er '.region | strings' "$map_file") || fail "LAB_01 mapping has no region; run: $(map_hint)"
  [[ "$region" == 'ap-southeast-1' ]] || fail "LAB_01 mapping region must be ap-southeast-1; run: $(map_hint)"
  candidate=$(jq -er '.instance_id | strings' "$map_file") || fail "LAB_01 mapping has no instance_id; run: $(map_hint)"
  [[ "$candidate" != 'REPLACE_WITH_PRIVATE_LAB_01_INSTANCE_ID' ]] || fail "LAB_01 mapping still contains the public example placeholder; run: $(map_hint)"
  [[ "$candidate" =~ ^i-[0-9a-f]{8,17}$ ]] || fail "LAB_01 mapping instance_id is invalid; run: $(map_hint)"
  instance_id=$candidate
}

configure() {
  [[ "${2:-}" == '--instance-id' && -n "${3:-}" && -z "${4:-}" ]] || usage
  validate_map_path
  command -v jq >/dev/null 2>&1 || fail 'jq is required'
  local requested_id=$3 parent tmp
  [[ "$requested_id" =~ ^i-[0-9a-f]{8,17}$ ]] || fail 'configure requires a private EC2 instance ID in i-xxxxxxxx format; the ID is never printed'
  parent=$(dirname -- "$map_file")
  [[ -d "$map_root" ]] || install -d -m 700 "$map_root"
  [[ -d "$parent" ]] || install -d -m 700 "$parent"
  tmp=$(mktemp "$map_file.tmp.XXXXXX") || fail 'could not create the private LAB_01 mapping file'
  jq -cn --arg instance_id "$requested_id" '{profile:"ihis_dev",region:"ap-southeast-1",instance_id:$instance_id}' > "$tmp"
  chmod 600 "$tmp"
  mv -- "$tmp" "$map_file"
  printf 'LAB_01 mapping configured at %s (profile=ihis_dev region=ap-southeast-1; instance ID withheld)\n' "$map_file"
}

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
  configure) configure "$@" ;;
  status) [[ -z "${2:-}" ]] || usage; load_mapping; status ;;
  reset|reopen) load_mapping; action "$1" "${2:-}" "${3:-}" ;;
  *) usage ;;
esac
