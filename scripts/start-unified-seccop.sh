#!/usr/bin/bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
runtime_env=${SECCOP_RUNTIME_ENV:-"$HOME/.AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-unified/runtime.env"}
python_bin=${SECCOP_PYTHON:-"$repo_dir/.venv/bin/python3"}
session_name=seccop-unified-2222
app_url=http://127.0.0.1:2222
allowed_names=(
  AWS_DEFAULT_PROFILE AWS_DEFAULT_REGION AWS_PROFILE AWS_REGION
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
[[ $(stat -c '%a' "$runtime_env") == 600 && -r "$runtime_env" ]] || fail SECCOP_RUNTIME_ENV
[[ -x "$python_bin" ]] || fail SECCOP_PYTHON
unset POC_PORT
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
    AWS_DEFAULT_PROFILE|AWS_DEFAULT_REGION|AWS_PROFILE|AWS_REGION|SECCOP_DEMO_BACKEND|SECCOP_EC2_IMDSV2_E2E|SECCOP_EC2_PROFILE|SECCOP_EC2_REGION|SECCOP_EC2_RND_REARM|SECCOP_EC2_RND_TARGET_MAP|SECCOP_ECR_APP_SERVER|SECCOP_ECR_FIXTURE|SECCOP_ECR_OPERATOR_MVP|SECCOP_ECR_SCANNER|SECCOP_ECR_S3_COMBINED|SECCOP_PROFILE|SECCOP_S3_BUCKET|SECCOP_S3_COMPLIANCE_E2E|SECCOP_S3_EVIDENCE_DIR|SECCOP_S3_PROTECTED_BUCKETS|SECCOP_S3_STATE)
      export "$name=$value"
      loaded_names["$name"]=1
      ;;
    *) fail SECCOP_RUNTIME_ENV ;;
  esac
done <"$runtime_env"

for name in "${required_names[@]}"; do
  [[ ${loaded_names[$name]:-} == 1 ]] || fail "$name"
done

export POC_PORT=2222
export PYTHONPATH="$repo_dir/src${PYTHONPATH:+:$PYTHONPATH}"
case "${1:-}" in
  --check) exec "$python_bin" -m secure_agent_harness.poc_server --unified-runtime-check ;;
  --serve) exec "$python_bin" -m secure_agent_harness.poc_server --unified-runtime-preflight ;;
  '') ;;
  *) fail COMMAND ;;
esac

for command_name in curl jq readlink sed sort ss tmux tr; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name"
done

listener_pids() {
  ss -H -ltnp '( sport = :2222 )' | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u
}

health_ready() {
  curl -fsS "$app_url/api/health" 2>/dev/null | jq -e '
    .status == "OK"
    and .review_mode == "ECR_S3_EC2_COMBINED"
    and .enabled_sources == ["ec2", "ecr", "s3"]
  ' >/dev/null
}

verify_owned_listener() {
  local listener_pid=$1 pane_pid listener_command
  [[ $(readlink -f "/proc/$listener_pid/cwd") == "$repo_dir" ]] || return 1
  listener_command=$(tr '\0' ' ' <"/proc/$listener_pid/cmdline")
  [[ "$listener_command" == *'secure_agent_harness.poc_server --unified-runtime-preflight'* ]] || return 1
  tmux has-session -t "$session_name" 2>/dev/null || return 1
  pane_pid=$(tmux list-panes -t "$session_name" -F '#{pane_pid}' 2>/dev/null)
  [[ "$pane_pid" == "$listener_pid" ]] || return 1
  health_ready
}

mapfile -t pids < <(listener_pids)
if ((${#pids[@]} > 0)); then
  [[ ${#pids[@]} -eq 1 ]] || fail LISTENER_COUNT
  verify_owned_listener "${pids[0]}" || fail LISTENER_NOT_OWNED
  printf 'SECCOP_RUNTIME_RUNNING URL=%s TMUX=%s PID=%s\n' "$app_url/" "$session_name" "${pids[0]}"
  exit 0
fi

tmux has-session -t "$session_name" 2>/dev/null && fail SESSION_CONFLICT
printf -v serve_command 'exec %q --serve' "$repo_dir/scripts/start-unified-seccop.sh"
tmux new-session -d -s "$session_name" -c "$repo_dir" "$serve_command" || fail TMUX_START

for _ in {1..100}; do
  mapfile -t pids < <(listener_pids)
  if [[ ${#pids[@]} -eq 1 ]] && verify_owned_listener "${pids[0]}"; then
    printf 'SECCOP_RUNTIME_STARTED URL=%s TMUX=%s PID=%s\n' "$app_url/" "$session_name" "${pids[0]}"
    exit 0
  fi
  ((${#pids[@]} <= 1)) || break
  tmux has-session -t "$session_name" 2>/dev/null || break
  sleep 0.1
done

tmux kill-session -t "$session_name" 2>/dev/null || true
fail START_FAILED
