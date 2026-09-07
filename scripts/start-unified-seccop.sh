#!/usr/bin/bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
runtime_env=${SECCOP_RUNTIME_ENV:-"$HOME/.AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-unified/runtime.env"}
python_bin=${SECCOP_PYTHON:-"$repo_dir/.venv/bin/python3"}
allowed_names=(
  AWS_DEFAULT_PROFILE AWS_DEFAULT_REGION AWS_PROFILE AWS_REGION POC_PORT
  SECCOP_DEMO_BACKEND SECCOP_EC2_IMDSV2_E2E SECCOP_EC2_PROFILE
  SECCOP_EC2_REGION SECCOP_EC2_RND_REARM SECCOP_EC2_RND_TARGET_MAP
  SECCOP_ECR_APP_SERVER SECCOP_ECR_FIXTURE SECCOP_ECR_OPERATOR_MVP
  SECCOP_ECR_SCANNER SECCOP_ECR_S3_COMBINED SECCOP_PROFILE SECCOP_S3_BUCKET
  SECCOP_S3_COMPLIANCE_E2E SECCOP_S3_EVIDENCE_DIR
  SECCOP_S3_PROTECTED_BUCKETS SECCOP_S3_STATE
)
required_names=(
  AWS_DEFAULT_PROFILE AWS_DEFAULT_REGION AWS_PROFILE AWS_REGION
  SECCOP_DEMO_BACKEND SECCOP_EC2_IMDSV2_E2E SECCOP_EC2_PROFILE
  SECCOP_EC2_REGION SECCOP_EC2_RND_REARM SECCOP_EC2_RND_TARGET_MAP
  SECCOP_ECR_APP_SERVER SECCOP_ECR_OPERATOR_MVP SECCOP_ECR_SCANNER
  SECCOP_ECR_S3_COMBINED SECCOP_PROFILE SECCOP_S3_BUCKET
  SECCOP_S3_COMPLIANCE_E2E SECCOP_S3_EVIDENCE_DIR
  SECCOP_S3_PROTECTED_BUCKETS SECCOP_S3_STATE
)

fail() {
  printf '%s\n' "RUNTIME_CONFIG_INVALID:$1" >&2
  exit 2
}

[[ -f "$runtime_env" && ! -L "$runtime_env" ]] || fail SECCOP_RUNTIME_ENV
[[ $(stat -c '%a' "$runtime_env") =~ ^[0-6][0-7][0-7]$ ]] || fail SECCOP_RUNTIME_ENV
(( (8#$(stat -c '%a' "$runtime_env") & 8#077) == 0 )) || fail SECCOP_RUNTIME_ENV
[[ -x "$python_bin" ]] || fail SECCOP_PYTHON
for name in "${allowed_names[@]}"; do
  unset "$name"
done
declare -A loaded_names=()

while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" == *=* ]] || fail SECCOP_RUNTIME_ENV
  name=${line%%=*}
  value=${line#*=}
  case "$name" in
    AWS_DEFAULT_PROFILE|AWS_DEFAULT_REGION|AWS_PROFILE|AWS_REGION|POC_PORT|SECCOP_DEMO_BACKEND|SECCOP_EC2_IMDSV2_E2E|SECCOP_EC2_PROFILE|SECCOP_EC2_REGION|SECCOP_EC2_RND_REARM|SECCOP_EC2_RND_TARGET_MAP|SECCOP_ECR_APP_SERVER|SECCOP_ECR_FIXTURE|SECCOP_ECR_OPERATOR_MVP|SECCOP_ECR_SCANNER|SECCOP_ECR_S3_COMBINED|SECCOP_PROFILE|SECCOP_S3_BUCKET|SECCOP_S3_COMPLIANCE_E2E|SECCOP_S3_EVIDENCE_DIR|SECCOP_S3_PROTECTED_BUCKETS|SECCOP_S3_STATE)
      export "$name=$value"
      loaded_names["$name"]=1
      ;;
    *) fail SECCOP_RUNTIME_ENV ;;
  esac
done <"$runtime_env"

for name in "${required_names[@]}"; do
  [[ ${loaded_names[$name]:-} == 1 ]] || fail "$name"
done

export POC_PORT=${POC_PORT:-2222}
export PYTHONPATH="$repo_dir/src${PYTHONPATH:+:$PYTHONPATH}"
case "${1:-}" in
  '') exec "$python_bin" -m secure_agent_harness.poc_server --unified-runtime-preflight ;;
  --check) exec "$python_bin" -m secure_agent_harness.poc_server --unified-runtime-check ;;
  *) fail COMMAND ;;
esac
