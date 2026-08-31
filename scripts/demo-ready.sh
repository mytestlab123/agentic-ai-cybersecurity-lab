#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# One-command Project1 DEMO preparation. Invoking this script authorizes only
# the bounded startup contract documented in SPEC.md. It never remediates or
# cleans up a resource.
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
profile=vagent
region=ap-southeast-1
target_name=seccop-project1-old-ami-host-r01
app_port=8766
app_url="http://127.0.0.1:${app_port}"
tmux_session=agentic-ai-cybersecurity-lab
tmux_window=aws-demo

if (($#)); then
  printf '%s\n' 'usage: ./scripts/demo-ready.sh' >&2
  exit 2
fi

for command_name in aws curl jq ss terraform tmux uv; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'missing command: %s\n' "$command_name" >&2
    exit 1
  }
done

run_id=$(date '+%Y%m%dT%H%M%S%z')
evidence_dir="${SECCOP_EVIDENCE_ROOT:-$HOME/.AGENTS-temp/agentic-ai-cybersecurity-lab/demo-ready}/$run_id"
install -d -m 700 "$evidence_dir"
cd "$repo_dir"

./scripts/start-demo.sh \
  --profile "$profile" \
  --region "$region" \
  --target-name "$target_name" \
  --confirm \
  >"$evidence_dir/start.json" \
  2>"$evidence_dir/start.stderr"

jq -e '
  .status == "READY" and
  (.sources | length) == 3 and
  all(.sources[]; .state == "NON_COMPLIANT")
' "$evidence_dir/start.json" >/dev/null || {
  printf '%s\n' 'DEMO preparation did not return three non-compliant sources.' >&2
  exit 1
}

uv run python scripts/seccop_demo.py scan \
  --profile "$profile" \
  --region "$region" \
  --target-name "$target_name" \
  >"$evidence_dir/scan.json" \
  2>"$evidence_dir/scan.stderr"

jq -e '
  .status == "READY" and
  (.sources | length) == 3 and
  all(.sources[]; .state == "NON_COMPLIANT")
' "$evidence_dir/scan.json" >/dev/null || {
  printf '%s\n' 'DEMO scan did not verify three non-compliant sources.' >&2
  exit 1
}

tmux_window_exists() {
  tmux has-session -t "$tmux_session" 2>/dev/null &&
    tmux list-windows -t "$tmux_session" -F '#{window_name}' | grep -Fxq "$tmux_window"
}

health_is_ready() {
  curl --fail --silent --show-error --max-time 2 \
    "$app_url/api/health" >"$evidence_dir/health.json" 2>/dev/null &&
    jq -e '.status == "OK" and .mode == "AWS_DEMO" and .demo_backend == "AWS"' \
      "$evidence_dir/health.json" >/dev/null
}

pid_is_descendant_of() {
  local child=$1 ancestor=$2 parent
  while [[ "$child" =~ ^[0-9]+$ ]] && ((child > 1)); do
    [[ "$child" == "$ancestor" ]] && return 0
    parent=$(ps -o ppid= -p "$child" 2>/dev/null | tr -d ' ')
    [[ -n "$parent" && "$parent" != "$child" ]] || break
    child=$parent
  done
  return 1
}

listener_pid() {
  ss -ltnp "sport = :${app_port}" 2>/dev/null |
    sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' |
    head -n 1
}

start_gui_in_tmux() {
  local uv_bin gui_command pane_path
  uv_bin=$(command -v uv)
  gui_command=$(printf \
    'exec env AWS_PROFILE=%q AWS_REGION=%q SECCOP_DEMO_BACKEND=AWS POC_PORT=%q %q run python -m secure_agent_harness.poc_server >>%q 2>&1' \
    "$profile" "$region" "$app_port" "$uv_bin" "$evidence_dir/gui.log")

  if ! tmux has-session -t "$tmux_session" 2>/dev/null; then
    tmux new-session -d -s "$tmux_session" -n "$tmux_window" -c "$repo_dir" \
      /usr/bin/bash -lc "$gui_command"
  elif tmux_window_exists; then
    pane_path=$(tmux display-message -p -t "$tmux_session:$tmux_window" '#{pane_current_path}')
    [[ "$pane_path" == "$repo_dir" ]] || {
      printf '%s\n' 'The owned AWS DEMO tmux window is in an unexpected directory.' >&2
      exit 1
    }
    tmux respawn-pane -k -t "$tmux_session:$tmux_window" -c "$repo_dir" \
      /usr/bin/bash -lc "$gui_command"
  else
    tmux new-window -d -t "$tmux_session:" -n "$tmux_window" -c "$repo_dir" \
      /usr/bin/bash -lc "$gui_command"
  fi
}

if ss -ltnH "sport = :${app_port}" | grep -q .; then
  health_is_ready || {
    printf 'port %s is busy but is not the SecCop AWS DEMO\n' "$app_port" >&2
    exit 1
  }
else
  start_gui_in_tmux
  for _ in {1..60}; do
    health_is_ready && break
    sleep 0.25
  done
  health_is_ready || {
    printf '%s\n' 'The SecCop AWS DEMO GUI did not become ready.' >&2
    exit 1
  }
fi

tmux_window_exists || {
  printf '%s\n' 'The SecCop AWS DEMO GUI is not in its owned tmux window.' >&2
  exit 1
}
gui_pid=$(listener_pid)
pane_pid=$(tmux display-message -p -t "$tmux_session:$tmux_window" '#{pane_pid}')
[[ -n "$gui_pid" ]] && pid_is_descendant_of "$gui_pid" "$pane_pid" || {
  printf '%s\n' 'The process on the DEMO port is not owned by the expected tmux window.' >&2
  exit 1
}

jq -n \
  --arg url "$app_url" \
  --arg tmux "$tmux_session:$tmux_window" \
  --arg evidence "$evidence_dir" \
  --slurpfile scan "$evidence_dir/scan.json" \
  '{
    status: "READY",
    reason_code: "SECCOP_DEMO_READY",
    url: $url,
    tmux: $tmux,
    sources: ($scan[0].sources | map({alias, state, reason_code})),
    remediation_performed: false,
    cleanup_performed: false,
    evidence: $evidence
  }' | tee "$evidence_dir/result.json"
