#!/usr/bin/bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
app_url='http://localhost:2222'
runner="$repo_dir/scripts/live-codex-gui-e2e.mjs"
powershell_bin=${POWERSHELL_WSL:-'/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'}
chrome_bin=${CHROME_WSL:-'/mnt/c/Program Files/Google/Chrome/Application/chrome.exe'}
node_bin=${WINDOWS_NODE:-'/mnt/c/Program Files/nodejs/node.exe'}
playwright_core=${PLAYWRIGHT_CORE:-"$repo_dir/node_modules/playwright-core/index.mjs"}
review_dir=${REVIEW_DIR:-}
chrome_pid=''
profile_dir=''
profile_windows=''

fail() {
  printf 'LIVE_CODEX_GUI_E2E_FAILED:%s\n' "$1" >&2
  exit 1
}

cleanup() {
  local profile_pattern
  if [[ -n "$chrome_pid" ]] && kill -0 "$chrome_pid" 2>/dev/null; then
    kill "$chrome_pid" 2>/dev/null || true
  fi
  if [[ -n "$profile_windows" ]]; then
    profile_pattern=${profile_windows//\'/\'\'}
    "$powershell_bin" -NoProfile -NonInteractive -Command \
      "\$profile = [Regex]::Escape('$profile_pattern'); Get-CimInstance Win32_Process -Filter \"Name = 'chrome.exe'\" | Where-Object { \$_.CommandLine -match \$profile } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$profile_dir" && -d "$profile_dir" ]]; then
    find "$profile_dir" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

for command_path in "$powershell_bin" "$chrome_bin" "$node_bin"; do
  [[ -x "$command_path" ]] || fail MISSING_RUNTIME
done
for command_name in curl jq readlink sed ss tr wslpath; do
  command -v "$command_name" >/dev/null 2>&1 || fail MISSING_RUNTIME
done
[[ -r "$playwright_core" && -r "$runner" ]] || fail 'MISSING_PLAYWRIGHT_RUN_NPM_CI'

mapfile -t listener_pids < <(ss -ltnp '( sport = :2222 )' | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p')
[[ ${#listener_pids[@]} -eq 1 ]] || fail LISTENER_COUNT
listener_pid=${listener_pids[0]}
[[ $(readlink -f "/proc/$listener_pid/cwd") == "$repo_dir" ]] || fail LISTENER_WRONG_CHECKOUT
listener_command=$(tr '\0' ' ' <"/proc/$listener_pid/cmdline")
[[ "$listener_command" == *'secure_agent_harness.poc_server --unified-runtime-preflight'* ]] || fail LISTENER_WRONG_COMMAND
printf 'Run started: %s\n' "$(date --iso-8601=seconds)"
ps -o pid=,ppid=,lstart=,etime=,args= -p "$listener_pid"
curl -fsS "$app_url/api/health" | jq -e \
  '.status == "OK" and .review_mode == "ECR_S3_EC2_COMBINED" and .enabled_sources == ["ec2","ecr","s3"]' \
  >/dev/null || fail HEALTH

if [[ -z "$review_dir" ]]; then
  pictures_native=$("$powershell_bin" -NoProfile -NonInteractive -Command '[Environment]::GetFolderPath("MyPictures")' | tr -d '\r\n')
  review_dir="$(wslpath -u "$pictures_native")/Screenshots"
fi
install -d "$review_dir"

windows_temp_native=$("$powershell_bin" -NoProfile -NonInteractive -Command '[System.IO.Path]::GetTempPath()' | tr -d '\r\n')
windows_temp_wsl=$(wslpath -u "$windows_temp_native")
profile_dir=$(mktemp -d "$windows_temp_wsl/seccop-live-codex.XXXXXX")
profile_windows=$(wslpath -w "$profile_dir")

"$chrome_bin" \
  --headless=new \
  --disable-gpu \
  --disable-background-networking \
  --disable-component-update \
  --hide-scrollbars \
  --no-first-run \
  --no-default-browser-check \
  --remote-debugging-address=localhost \
  --remote-debugging-port=0 \
  "--user-data-dir=$profile_windows" \
  --window-size=1920,1080 \
  about:blank \
  >"$profile_dir/chrome.log" 2>&1 &
chrome_pid=$!

devtools_file="$profile_dir/DevToolsActivePort"
for _ in {1..100}; do
  [[ -s "$devtools_file" ]] && break
  kill -0 "$chrome_pid" 2>/dev/null || fail CHROME_START
  sleep 0.1
done
[[ -s "$devtools_file" ]] || fail CHROME_TIMEOUT
debug_port=$(sed -n '1p' "$devtools_file" | tr -d '\r')
[[ "$debug_port" =~ ^[0-9]+$ ]] || fail CHROME_PORT

APP_URL=$app_url
CDP_URL="http://localhost:$debug_port"
OUTPUT_DIR=$(wslpath -w "$review_dir")
PLAYWRIGHT_CORE=$(wslpath -w "$playwright_core")
export APP_URL CDP_URL OUTPUT_DIR PLAYWRIGHT_CORE
export WSLENV='APP_URL:CDP_URL:OUTPUT_DIR:PLAYWRIGHT_CORE'
"$node_bin" "$(wslpath -w "$runner")"

printf 'PASS: real localhost:2222 Codex GUI E2E\n'
printf 'Run finished: %s\n' "$(date --iso-8601=seconds)"
printf 'Screenshots: %s\n' "$review_dir"
