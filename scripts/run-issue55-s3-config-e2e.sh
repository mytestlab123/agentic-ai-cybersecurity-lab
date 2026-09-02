#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
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
