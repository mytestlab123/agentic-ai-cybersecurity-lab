#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

# Corrected Issue #55 EC2 IMDSv2 path.  Keep this in the existing trusted
# runner so the S3 journey below remains unchanged and no parallel harness is
# introduced.
if [[ ${SECCOP_EC2_IMDSV2_E2E:-0} == 1 ]]; then
  profile=${AWS_PROFILE:-amit}
  region=${AWS_REGION:-ap-southeast-1}
  port=${SECCOP_API_PORT:-2225}
  evidence_dir=${SECCOP_EC2_EVIDENCE_DIR:?SECCOP_EC2_EVIDENCE_DIR must be private}
  state=${SECCOP_EC2_STATE:?SECCOP_EC2_STATE must be private}
  ami_pattern=${SECCOP_EC2_AMI_NAME_PATTERN:-al2023-ami-2023.12.20260831.0-kernel-6.18-x86_64}
  mkdir -p "$evidence_dir"; chmod 700 "$evidence_dir"
  export AWS_PROFILE="$profile" AWS_DEFAULT_PROFILE="$profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region"
  export SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" SECCOP_EC2_STATE="$state"
  [[ "$profile" == amit && "$region" == ap-southeast-1 ]] || { echo 'explicit amit/ap-southeast-1 is required' >&2; exit 1; }
  [[ "$port" =~ ^[0-9]+$ && "$port" != 2222 ]] || { echo 'EC2 rehearsal port is invalid or reserved' >&2; exit 1; }
  if ss -ltn 2>/dev/null | awk -v port=":$port" '$4 == port {found=1} END {exit found}'; then
    :
  else
    echo "EC2 rehearsal port $port is already in use" >&2
    exit 1
  fi
  aws sts get-caller-identity >"$evidence_dir/e2e-sts.json"
  aws ec2 describe-images --owners amazon --filters "Name=name,Values=$ami_pattern" "Name=state,Values=available" >"$evidence_dir/ami-preflight.json"
  jq -e '.Images | length == 1 and .[0].State == "available"' "$evidence_dir/ami-preflight.json" >/dev/null || {
    echo 'The approved current Amazon Linux AMI was not uniquely available' >&2
    exit 1
  }
  aws configservice describe-configuration-recorders >"$evidence_dir/recorder-before.json"
  aws configservice describe-delivery-channels >"$evidence_dir/delivery-before.json"
  jq -e '[.ConfigurationRecorders[] | select(.name == "seccop-issue55-s3-recorder")] | length == 1' "$evidence_dir/recorder-before.json" >/dev/null || { echo 'Approved Config recorder is not exact' >&2; exit 1; }
  jq -e '[.DeliveryChannels[] | select(.name == "seccop-issue55-s3-delivery")] | length == 1' "$evidence_dir/delivery-before.json" >/dev/null || { echo 'Approved delivery channel is not exact' >&2; exit 1; }

  server_pid=
  cleanup_done=0
  cleanup_ec2() {
    local cleanup_rc=0
    if [[ -n "${server_pid:-}" ]]; then
      kill "$server_pid" 2>/dev/null || true
      wait "$server_pid" 2>/dev/null || true
      server_pid=
    fi
    if [[ "$cleanup_done" != 1 && -f "$state" ]]; then
      SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" SECCOP_EC2_STATE="$state" \
        /usr/bin/python3 "$repo_dir/scripts/issue47_s3_compliance.py" ec2-cleanup --profile "$profile" --region "$region" >"$evidence_dir/cleanup-on-exit.json" 2>>"$evidence_dir/cleanup-on-exit.stderr" || cleanup_rc=$?
    fi
    # Keep the EXIT trap from masking the evidence file; callers assert the
    # repo-owned cleanup result and independently verify every resource.
    return 0
  }
  trap cleanup_ec2 EXIT

  SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" SECCOP_EC2_STATE="$state" SECCOP_EC2_AMI_NAME_PATTERN="$ami_pattern" \
    /usr/bin/python3 "$repo_dir/scripts/issue47_s3_compliance.py" ec2-setup --profile "$profile" --region "$region" >"$evidence_dir/setup.json"
  jq -e '.status == "READY" and .reason_code == "SECCOP_EC2_IMDSV2_SETUP_READY"' "$evidence_dir/setup.json" >/dev/null

  cd "$repo_dir"
  SECCOP_DEMO_BACKEND=AWS SECCOP_EC2_IMDSV2_E2E=1 SECCOP_PROFILE="$profile" SECCOP_REGION="$region" AWS_PROFILE="$profile" AWS_REGION="$region" SECCOP_EC2_STATE="$state" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" POC_PORT="$port" \
    .venv/bin/python -m secure_agent_harness.poc_server >"$evidence_dir/server.log" 2>&1 &
  server_pid=$!
  for _ in {1..30}; do
    if curl -fsS --max-time 2 "http://127.0.0.1:$port/api/health" >"$evidence_dir/health.json"; then break; fi
    sleep 1
  done
  jq -e '.review_mode == "EC2_IMDSV2" and .demo_backend == "AWS" and (.enabled_sources | index("ec2"))' "$evidence_dir/health.json" >/dev/null
  post() { curl --fail-with-body --max-time 500 -sS -X POST "http://127.0.0.1:$port$1" -H 'Content-Type: application/json' --data-binary "$2"; }
  post /api/demo/fix '{"source":"ec2","confirm":true}' >"$evidence_dir/before-approval.json"
  jq -e '.result.status == "BLOCKED"' "$evidence_dir/before-approval.json" >/dev/null
  post /api/scan '{"mode":"DEMO","source":"ec2","request_text":"Review the EC2 IMDSv2 compliance finding"}' >"$evidence_dir/scan-non-compliant.json"
  jq -e '.result.reason_code == "SECCOP_EC2_IMDSV2_NON_COMPLIANT" and (.result.proposal_id | startswith("SECCOP_PROPOSAL_")) and (.result.findings[0].source_type == "EC2_CONFIG")' "$evidence_dir/scan-non-compliant.json" >/dev/null
  proposal_id=$(jq -r '.result.proposal_id' "$evidence_dir/scan-non-compliant.json")
  proposal_hash=$(jq -r '.result.proposal_hash' "$evidence_dir/scan-non-compliant.json")
  post /api/demo/fix "$(jq -nc --arg id "$proposal_id" '{source:"ec2",confirm:true,proposal_id:$id,proposal_hash:"wrong"}')" >"$evidence_dir/wrong-proposal.json"
  jq -e '.result.status == "BLOCKED"' "$evidence_dir/wrong-proposal.json" >/dev/null
  post /api/demo/fix "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"s3",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/cross-source.json"
  jq -e '.result.status == "BLOCKED"' "$evidence_dir/cross-source.json" >/dev/null
  post /api/demo/reject "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"ec2",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/reject.json"
  jq -e '.result.status == "REJECTED" and .result.mutation_performed == false and .result.state == "NON_COMPLIANT"' "$evidence_dir/reject.json" >/dev/null
  post /api/scan '{"mode":"DEMO","source":"ec2","request_text":"Recheck the EC2 IMDSv2 compliance finding"}' >"$evidence_dir/scan-before-remediation.json"
  jq -e '.result.reason_code == "SECCOP_EC2_IMDSV2_NON_COMPLIANT"' "$evidence_dir/scan-before-remediation.json" >/dev/null
  proposal_id=$(jq -r '.result.proposal_id' "$evidence_dir/scan-before-remediation.json")
  proposal_hash=$(jq -r '.result.proposal_hash' "$evidence_dir/scan-before-remediation.json")
  post /api/demo/fix "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"ec2",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/remediate.json"
  jq -e '.result.status == "VERIFIED" and .result.state == "COMPLIANT" and .result.metadata_http_tokens == "required" and .result.automation_status == "Success"' "$evidence_dir/remediate.json" >/dev/null
  post /api/demo/fix "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"ec2",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/replay-proposal.json"
  jq -e '.result.status == "BLOCKED"' "$evidence_dir/replay-proposal.json" >/dev/null
  post /api/scan '{"mode":"DEMO","source":"ec2","request_text":"Verify the EC2 IMDSv2 protected state"}' >"$evidence_dir/scan-compliant.json"
  jq -e '.result.reason_code == "SECCOP_EC2_IMDSV2_COMPLIANT" and .result.state == "COMPLIANT" and (.result.findings | length) == 0' "$evidence_dir/scan-compliant.json" >/dev/null

  cleanup_ec2
  cleanup_done=1
  jq -e '.status == "CLEANED" and .reason_code == "SECCOP_EC2_CLEANUP_VERIFIED"' "$evidence_dir/cleanup-on-exit.json" >/dev/null
  aws ec2 describe-instances --filters 'Name=tag:Name,Values=seccop-amit-inspector-host-r01' 'Name=tag:Repo,Values=agentic-ai-cybersecurity-lab' 'Name=instance-state-name,Values=pending,running,stopping,stopped' >"$evidence_dir/target-after.json"
  jq -e '.Reservations | map(.Instances[]) | length == 0' "$evidence_dir/target-after.json" >/dev/null
  aws configservice describe-config-rules --config-rule-names ec2-imdsv2-check >"$evidence_dir/rule-after.json" 2>"$evidence_dir/rule-after.stderr" || true
  [[ ! -s "$evidence_dir/rule-after.json" ]] || jq -e '(.ConfigRules // []) | length == 0' "$evidence_dir/rule-after.json" >/dev/null
  aws configservice describe-remediation-configurations --config-rule-names ec2-imdsv2-check >"$evidence_dir/remediation-after.json" 2>"$evidence_dir/remediation-after.stderr" || true
  [[ ! -s "$evidence_dir/remediation-after.json" ]] || jq -e '(.RemediationConfigurations // []) | length == 0' "$evidence_dir/remediation-after.json" >/dev/null
  aws configservice describe-configuration-recorders >"$evidence_dir/recorder-after.json"
  aws configservice describe-delivery-channels >"$evidence_dir/delivery-after.json"
  jq -e '[.ConfigurationRecorders[] | select(.name == "seccop-issue55-s3-recorder") | .recordingGroup.resourceTypes] | flatten | index("AWS::S3::Bucket") != null' "$evidence_dir/recorder-after.json" >/dev/null
  recorder_shape='[.ConfigurationRecorders[] | select(.name == "seccop-issue55-s3-recorder") | {name, roleARN, recordingGroup: {allSupported: .recordingGroup.allSupported, includeGlobalResourceTypes: .recordingGroup.includeGlobalResourceTypes, resourceTypes: ((.recordingGroup.resourceTypes // []) | map(select(. != "AWS::EC2::Instance")) | sort)} }]'
  cmp -s <(jq -S "$recorder_shape" "$evidence_dir/recorder-before.json") <(jq -S "$recorder_shape" "$evidence_dir/recorder-after.json") || {
    echo 'Config recorder changed outside the approved EC2 resource type extension' >&2
    exit 1
  }
  cmp -s <(jq -S . "$evidence_dir/delivery-before.json") <(jq -S . "$evidence_dir/delivery-after.json") || { echo 'Delivery channel changed unexpectedly' >&2; exit 1; }
  jq -n '{status:"PASS",health:"EC2_IMDSV2",finding:"NON_COMPLIANT",wrong_proposal:"BLOCKED",cross_source:"BLOCKED",reject:"REJECTED_NO_MUTATION",remediation:"VERIFIED",automation:"SUCCESS",metadata:"HttpTokens=required",compliant:"COMPLIANT",replay:"BLOCKED",cleanup:"VERIFIED",recorder:"S3_PRESERVED_EC2_ADDED",delivery:"UNCHANGED",resources_retained:["CONFIG_RECORDER","CONFIG_DELIVERY","S3","ECR"],old_package_and_cve_path:"EXCLUDED",aws_profile:"amit",region:"ap-southeast-1"}'
  exit 0
fi

profile=${AWS_PROFILE:-amit}
region=${AWS_REGION:-ap-southeast-1}
port=${SECCOP_API_PORT:-18768}
bucket=${SECCOP_S3_BUCKET:?SECCOP_S3_BUCKET must be a private runtime value}
delivery_bucket=${SECCOP_S3_DELIVERY_BUCKET:?SECCOP_S3_DELIVERY_BUCKET must be a private runtime value}
protected_buckets=${SECCOP_S3_PROTECTED_BUCKETS:?SECCOP_S3_PROTECTED_BUCKETS must be private runtime values}
evidence_dir=${SECCOP_S3_EVIDENCE_DIR:?SECCOP_S3_EVIDENCE_DIR must be private}
state=${SECCOP_S3_STATE:?SECCOP_S3_STATE must be private}
mkdir -p "$evidence_dir"; chmod 700 "$evidence_dir"

export AWS_PROFILE="$profile" AWS_DEFAULT_PROFILE="$profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region"
export SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_S3_EVIDENCE_DIR="$evidence_dir" SECCOP_S3_STATE="$state"
[[ "$profile" == amit && "$region" == ap-southeast-1 ]] || { echo 'explicit amit/ap-southeast-1 is required' >&2; exit 1; }
aws sts get-caller-identity >"$evidence_dir/e2e-sts.json"
SECCOP_S3_EVIDENCE_DIR="$evidence_dir" SECCOP_S3_STATE="$state" \
  /usr/bin/python3 "$repo_dir/scripts/issue47_s3_compliance.py" setup --profile "$profile" --region "$region" --bucket "$bucket" --delivery-bucket "$delivery_bucket" >"$evidence_dir/setup.json"

export SECCOP_DEMO_BACKEND=AWS SECCOP_S3_COMPLIANCE_E2E=1 SECCOP_S3_BUCKET="$bucket" SECCOP_S3_PROTECTED_BUCKETS="$protected_buckets" POC_PORT="$port"
cd "$repo_dir"
.venv/bin/python -m secure_agent_harness.poc_server >"$evidence_dir/server.log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
for _ in {1..30}; do curl -fsS "http://127.0.0.1:$port/api/health" >"$evidence_dir/health.json" && break || sleep 1; done
jq -e '.review_mode == "S3_COMPLIANCE" and .demo_backend == "AWS"' "$evidence_dir/health.json" >/dev/null

post() { curl --fail-with-body --max-time 500 -sS -X POST "http://127.0.0.1:$port$1" -H 'Content-Type: application/json' --data-binary "$2"; }
post /api/demo/fix '{"source":"s3","confirm":true}' >"$evidence_dir/before-approval.json"
jq -e '.result.status == "BLOCKED"' "$evidence_dir/before-approval.json" >/dev/null
post /api/scan '{"request_text":"Review the S3 exposure risk"}' >"$evidence_dir/scan-non-compliant.json"
jq -e '.result.reason_code == "SECCOP_S3_NON_COMPLIANT" and (.result.proposal_id | startswith("SECCOP_PROPOSAL_"))' "$evidence_dir/scan-non-compliant.json" >/dev/null
proposal_id=$(jq -r '.result.proposal_id' "$evidence_dir/scan-non-compliant.json")
proposal_hash=$(jq -r '.result.proposal_hash' "$evidence_dir/scan-non-compliant.json")
post /api/demo/reject "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"s3",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/reject.json"
jq -e '.result.status == "REJECTED" and .result.mutation_performed == false' "$evidence_dir/reject.json" >/dev/null
post /api/scan '{"request_text":"Review the S3 exposure risk again"}' >"$evidence_dir/scan-before-remediation.json"
proposal_id=$(jq -r '.result.proposal_id' "$evidence_dir/scan-before-remediation.json")
proposal_hash=$(jq -r '.result.proposal_hash' "$evidence_dir/scan-before-remediation.json")
post /api/demo/fix "$(jq -nc --arg id "$proposal_id" '{source:"s3",confirm:true,proposal_id:$id,proposal_hash:"wrong"}')" >"$evidence_dir/wrong-proposal.json"
jq -e '.result.status == "BLOCKED"' "$evidence_dir/wrong-proposal.json" >/dev/null
post /api/demo/fix "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"s3",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/remediate.json"
jq -e '.result.status == "VERIFIED" and .result.state == "COMPLIANT"' "$evidence_dir/remediate.json" >/dev/null
post /api/scan '{"request_text":"Verify protected S3 state"}' >"$evidence_dir/scan-compliant.json"
jq -e '.result.reason_code == "SECCOP_S3_COMPLIANT" and (.result.findings | length) == 0' "$evidence_dir/scan-compliant.json" >/dev/null
post /api/demo/reset '{"confirm":true}' >"$evidence_dir/reset.json"
jq -e '.result.reason_code == "SECCOP_S3_RESET_READY"' "$evidence_dir/reset.json" >/dev/null
post /api/scan '{"request_text":"Reopen the S3 finding"}' >"$evidence_dir/scan-reopened.json"
jq -e '.result.reason_code == "SECCOP_S3_NON_COMPLIANT"' "$evidence_dir/scan-reopened.json" >/dev/null
jq -n '{health:"S3_COMPLIANCE", before_approval:"BLOCKED", reject:"REJECTED_NO_MUTATION", finding:"NON_COMPLIANT", remediation:"VERIFIED", compliant:"COMPLIANT", reset:"READY", reopened:"NON_COMPLIANT", aws_profile:"amit", region:"ap-southeast-1", resources_retained:true, ec2_started:false}'
