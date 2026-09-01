#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
app_port=${APP_PORT:-18765}
app_url="http://localhost:${app_port}"
run_id=$(date '+%Y%m%dT%H%M%S%z')
temp_root=${AGENTS_TEMP_ROOT:-${TMPDIR:-/tmp}}
evidence_dir="${EVIDENCE_ROOT:-${temp_root}/agentic-ai-cybersecurity-lab/browser-e2e}/${run_id}"
review_dir=${REVIEW_DIR:-}
live_advisory=${LIVE_ADVISORY:-}
live_scan_only=${LIVE_SCAN_ONLY:-0}
node_runner="$repo_dir/scripts/browser-e2e.mjs"
app_pid=''
chrome_pid=''
profile_dir=''
profile_windows=''
debug_port=''

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing command: %s\n' "$1" >&2
    exit 1
  }
}

for command_name in curl jq ss wslpath; do
  require_command "$command_name"
done
[[ -r "$node_runner" ]] || {
  printf 'missing browser runner: %s\n' "$node_runner" >&2
  exit 1
}
if ss -ltnH "sport = :${app_port}" | grep -q .; then
  printf 'refusing busy port: %s\n' "$app_port" >&2
  exit 1
fi
install -d -m 700 "$evidence_dir"

powershell_bin=${POWERSHELL_WSL:-'/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'}
[[ -x "$powershell_bin" ]] || {
  printf 'Windows PowerShell not found: %s\n' "$powershell_bin" >&2
  exit 1
}
if [[ -z "$review_dir" ]]; then
  windows_pictures_native=$("$powershell_bin" -NoProfile -NonInteractive -Command '[Environment]::GetFolderPath("MyPictures")' | tr -d '\r\n')
  review_dir="$(wslpath -u "$windows_pictures_native")/Screenshots"
fi
install -d "$review_dir"

cleanup() {
  local attempt profile_pattern
  if [[ -n "$chrome_pid" ]] && kill -0 "$chrome_pid" 2>/dev/null; then
    kill "$chrome_pid" 2>/dev/null || true
    for ((attempt = 1; attempt <= 30; attempt++)); do
      kill -0 "$chrome_pid" 2>/dev/null || break
      sleep 0.1
    done
  fi
  # The WSL launcher PID is not the complete Windows Chrome process tree.
  # Stop only Chrome processes whose command line contains this run's profile.
  if [[ -n "$profile_windows" ]]; then
    profile_pattern=${profile_windows//\'/\'\'}
    "$powershell_bin" -NoProfile -NonInteractive -Command \
      "\$profile = [Regex]::Escape('$profile_pattern'); Get-CimInstance Win32_Process -Filter \"Name = 'chrome.exe'\" | Where-Object { \$_.CommandLine -match \$profile } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$app_pid" ]] && kill -0 "$app_pid" 2>/dev/null; then
    kill "$app_pid" 2>/dev/null || true
    wait "$app_pid" 2>/dev/null || true
  fi
  if [[ -n "$profile_dir" && -d "$profile_dir" ]]; then
    find "$profile_dir" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

(
  cd "$repo_dir"
  POC_PORT="$app_port" LIVE_SCAN_ONLY="$live_scan_only" uv run python -m secure_agent_harness.poc_server
) >"$evidence_dir/app.log" 2>&1 &
app_pid=$!

for ((attempt = 1; attempt <= 40; attempt++)); do
  if curl --fail --silent --show-error --max-time 2 "$app_url/api/health" >"$evidence_dir/health.json" 2>/dev/null; then
    break
  fi
  kill -0 "$app_pid" 2>/dev/null || {
    cat "$evidence_dir/app.log" >&2
    exit 1
  }
  sleep 0.25
done
if [[ "$live_scan_only" == 1 ]]; then
  jq -e '.status == "OK" and .demo_backend == "AWS"' "$evidence_dir/health.json" >/dev/null
else
  jq -e '.status == "OK" and .mode == "LOCAL_SYNTHETIC"' "$evidence_dir/health.json" >/dev/null
fi
printf '%s\n' "$app_url" >"$evidence_dir/app-url.txt"
printf '%s\n' "$app_pid" >"$evidence_dir/app-pid.txt"

chrome_bin=${CHROME_WSL:-'/mnt/c/Program Files/Google/Chrome/Application/chrome.exe'}
[[ -x "$chrome_bin" ]] || {
  printf 'Windows Chrome not found: %s\n' "$chrome_bin" >&2
  exit 1
}
windows_temp_native=$("$powershell_bin" -NoProfile -NonInteractive -Command '[System.IO.Path]::GetTempPath()' | tr -d '\r\n')
windows_temp_wsl=$(wslpath -u "$windows_temp_native")
profile_dir=$(mktemp -d "$windows_temp_wsl/seccop-e2e.XXXXXX")
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
  >"$evidence_dir/chrome.log" 2>&1 &
chrome_pid=$!
devtools_file="$profile_dir/DevToolsActivePort"
for ((attempt = 1; attempt <= 100; attempt++)); do
  [[ -s "$devtools_file" ]] && break
  kill -0 "$chrome_pid" 2>/dev/null || {
    cat "$evidence_dir/chrome.log" >&2
    exit 1
  }
  sleep 0.1
done
[[ -s "$devtools_file" ]] || {
  printf 'Chrome DevTools endpoint was not ready\n' >&2
  exit 1
}
debug_port=$(sed -n '1p' "$devtools_file" | tr -d '\r')
[[ "$debug_port" =~ ^[0-9]+$ ]] || {
  printf 'Chrome reported invalid debug port\n' >&2
  exit 1
}
cdp_url="http://localhost:${debug_port}"
evidence_dir_windows=$(wslpath -w "$evidence_dir")
runner_windows=$(wslpath -w "$node_runner")
playwright_core=${PLAYWRIGHT_CORE:-}
if [[ -z "$playwright_core" ]]; then
  for candidate in \
    "$repo_dir/../AgentCore/frontend/node_modules/playwright-core/index.mjs" \
    "$repo_dir/node_modules/playwright-core/index.mjs"; do
    if [[ -r "$candidate" ]]; then
      playwright_core=$candidate
      break
    fi
  done
fi
[[ -n "$playwright_core" && -r "$playwright_core" ]] || {
  printf 'playwright-core module not found; set PLAYWRIGHT_CORE\n' >&2
  exit 1
}
playwright_windows=$(wslpath -w "$playwright_core")
live_advisory_windows=
if [[ -n "$live_advisory" ]]; then
  [[ -r "$live_advisory" ]] || { printf 'live advisory not readable: %s\n' "$live_advisory" >&2; exit 1; }
  live_advisory_windows=$(wslpath -w "$live_advisory")
fi
node_windows=${WINDOWS_NODE:-'/mnt/c/Program Files/nodejs/node.exe'}
[[ -x "$node_windows" ]] || {
  printf 'Windows Node.js not found: %s\n' "$node_windows" >&2
  exit 1
}

APP_URL="$app_url" CDP_URL="$cdp_url" EVIDENCE_DIR="$evidence_dir_windows" \
  REVIEW_DIR="$(wslpath -w "$review_dir")" PLAYWRIGHT_CORE="$playwright_windows" \
  LIVE_ADVISORY="$live_advisory_windows" LIVE_SCAN_ONLY="$live_scan_only" export APP_URL CDP_URL EVIDENCE_DIR REVIEW_DIR PLAYWRIGHT_CORE LIVE_ADVISORY LIVE_SCAN_ONLY
export WSLENV='APP_URL:CDP_URL:EVIDENCE_DIR:REVIEW_DIR:PLAYWRIGHT_CORE:LIVE_ADVISORY:LIVE_SCAN_ONLY'
"$node_windows" "$runner_windows"

screenshots=(
  SecCop-Scan-01.png \
  SecCop-CVE-01.png \
  SecCop-CVE-01-slide.png \
  SecCop-Scan-02.png \
  SecCop-Approval-01-slide.png \
  SecCop-Scan-02-live-review.png \
  SecCop-Scan-03.png \
  SecCop-Scan-04.png \
  SecCop-Scan-05-blocked.png
)
if [[ "$live_scan_only" == 1 ]]; then
  screenshots=(SecCop-Live-Workspace.png SecCop-Live-Finding.png SecCop-Live-Approval.png)
elif [[ -n "$live_advisory" ]]; then
  screenshots=(SecCop-Live-Finding.png SecCop-Live-Approval.png SecCop-Live-After.png)
fi
for screenshot in "${screenshots[@]}"; do
  test -s "$evidence_dir/$screenshot"
done

cleanup
trap - EXIT INT TERM
if ss -ltnH "sport = :${app_port}" | grep -q .; then
  printf 'owned app port was not released: %s\n' "$app_port" >&2
  exit 1
fi
if [[ -n "$debug_port" ]] && curl --silent --max-time 1 "http://localhost:${debug_port}/json/version" >/dev/null 2>&1; then
  printf 'owned Chrome CDP endpoint was not released: %s\n' "$debug_port" >&2
  exit 1
fi
jq -e '.status == "PASS" and .externalRequests == 0 and .consoleErrors == 0' \
  "$evidence_dir/result.json" >/dev/null
if [[ ${SECCOP_E2E_FAIL_BEFORE_PUBLISH:-0} == 1 ]]; then
  printf '%s\n' 'intentional failure before screenshot publication' >&2
  exit 9
fi
publish_dir="$evidence_dir/publish"
install -d -m 700 "$publish_dir"
for screenshot in "${screenshots[@]}"; do
  install -m 600 "$evidence_dir/$screenshot" "$publish_dir/$screenshot"
done
for screenshot in "${screenshots[@]}"; do
  install -m 600 "$publish_dir/$screenshot" "$review_dir/$screenshot"
done
printf 'PASS: SecCop browser screenshot evidence\n'
printf 'Evidence: %s\n' "$evidence_dir"
printf 'Screenshots: %s\n' "$review_dir"
