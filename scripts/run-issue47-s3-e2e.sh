#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
run_id=$(date '+%Y%m%dT%H%M%S%z')
evidence_root="${AGENTS_TEMP_ROOT:-$HOME/.AGENTS-temp}/agentic-ai-cybersecurity-lab/issue47-s3-compliance-e2e/aws/${run_id}"
install -d -m 700 "$evidence_root"
profile=${SECCOP_PROFILE:-amit}
region=${AWS_REGION:-ap-southeast-1}
bucket="seccop-i47-bpa-${run_id//[^0-9]/}"
bucket=${bucket:0:63}
export SECCOP_S3_CONFIG="$evidence_root/public-access-block.json"
export SECCOP_S3_TAGS="$evidence_root/tags.json"
export SECCOP_S3_BUCKET="$bucket"
export SECCOP_S3_COMPLIANCE_E2E=1
export SECCOP_DEMO_BACKEND=AWS
export SECCOP_PROFILE="$profile"
export AWS_REGION="$region"
api_port=${SECCOP_API_PORT:-18767}
api_pid=''

cleanup_done=false
cleanup() {
  if [[ -n "$api_pid" ]] && kill -0 "$api_pid" 2>/dev/null; then
    kill "$api_pid" 2>/dev/null || true
    wait "$api_pid" 2>/dev/null || true
  fi
  if ! $cleanup_done; then
    "$repo_dir/.venv/bin/python" "$repo_dir/scripts/issue47_s3_compliance.py" cleanup --profile "$profile" --region "$region" --bucket "$bucket" >"$evidence_root/cleanup.json" || true
  fi
}
trap 'status=$?; cleanup; exit "$status"' EXIT

"$repo_dir/.venv/bin/python" "$repo_dir/scripts/issue47_s3_compliance.py" create --profile "$profile" --region "$region" --bucket "$bucket" >"$evidence_root/create.json"
if ss -ltnH "sport = :${api_port}" | grep -q .; then
  printf 'refusing busy API smoke port: %s\n' "$api_port" >&2
  exit 1
fi
(
  cd "$repo_dir"
  POC_PORT="$api_port" uv run python -m secure_agent_harness.poc_server
) >"$evidence_root/api-server.log" 2>&1 &
api_pid=$!
for attempt in $(seq 1 40); do
  if curl --fail --silent --show-error "http://127.0.0.1:${api_port}/api/health" >"$evidence_root/api-health.json"; then break; fi
  sleep 0.25
done
jq -e '.status == "OK" and .demo_backend == "AWS"' "$evidence_root/api-health.json" >/dev/null
curl --fail --silent --show-error -X POST -H 'Content-Type: application/json' --data '{"source":"s3","confirm":true}' "http://127.0.0.1:${api_port}/api/demo/fix" >"$evidence_root/api-bypass.json"
jq -e '.result.reason_code == "APPROVAL_REQUIRED"' "$evidence_root/api-bypass.json" >/dev/null
curl --fail --silent --show-error -X POST -H 'Content-Type: application/json' --data '{"mode":"DEMO"}' "http://127.0.0.1:${api_port}/api/scan" >"$evidence_root/api-before.json"
jq -e '.result.reason_code == "SECCOP_S3_NON_COMPLIANT" and .result.findings[0].resource_alias == "S3_BUCKET_01"' "$evidence_root/api-before.json" >/dev/null
curl --fail --silent --show-error -X POST -H 'Content-Type: application/json' --data '{"source":"s3","confirm":true}' "http://127.0.0.1:${api_port}/api/demo/fix" >"$evidence_root/api-approve-once.json"
jq -e '.result.status == "VERIFIED" and .result.state == "COMPLIANT"' "$evidence_root/api-approve-once.json" >/dev/null
curl --fail --silent --show-error -X POST -H 'Content-Type: application/json' --data '{"mode":"DEMO"}' "http://127.0.0.1:${api_port}/api/scan" >"$evidence_root/api-after.json"
jq -e '.result.reason_code == "SECCOP_S3_COMPLIANT" and (.result.findings | length == 0)' "$evidence_root/api-after.json" >/dev/null
curl --fail --silent --show-error -X POST -H 'Content-Type: application/json' --data '{"source":"s3","bucket":"S3_BUCKET_OTHER","confirm":true}' "http://127.0.0.1:${api_port}/api/demo/fix" >"$evidence_root/api-target-swap.json"
jq -e '.result.reason_code == "APPROVAL_REQUIRED"' "$evidence_root/api-target-swap.json" >/dev/null
kill "$api_pid"; wait "$api_pid" 2>/dev/null || true; api_pid=''
"$repo_dir/.venv/bin/python" "$repo_dir/scripts/issue47_s3_compliance.py" cleanup --profile "$profile" --region "$region" --bucket "$bucket" >"$evidence_root/cleanup.json"
cleanup_done=true
if aws --profile "$profile" --region "$region" s3api head-bucket --bucket "$bucket" >"$evidence_root/cleanup-head.json" 2>"$evidence_root/cleanup-head.stderr"; then
  printf 'cleanup verification failed: bucket still exists\n' >&2
  exit 1
fi
printf 'PASS: Issue 47 S3 exposure-risk E2E\nEvidence: %s\n' "$evidence_root"
