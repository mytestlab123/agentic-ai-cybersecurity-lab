#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tf_dir="$repo_dir/infra/project1-seccop-ec2"
profile=${SECCOP_PROFILE:-vagent}
region=${SECCOP_REGION:-ap-southeast-1}
target_name=${SECCOP_TARGET_NAME:-seccop-project1-old-ami-host-r01}
ami_name_pattern=${SECCOP_AMI_NAME_PATTERN:-amzn2-ami-hvm-2.0.20260608.0-x86_64-gp2}
created=$(date '+%Y-%m-%d')
ttl=${SECCOP_TTL:-$(date -d '+1 day' '+%d-%m-%y')}
confirm=0
forward_args=()

while (($#)); do
  case "$1" in
    --confirm)
      confirm=1
      forward_args+=("$1")
      shift
      ;;
    --profile|--region|--target-name)
      [[ $# -ge 2 ]] || { printf '%s needs a value\n' "$1" >&2; exit 2; }
      case "$1" in
        --profile) profile=$2 ;;
        --region) region=$2 ;;
        --target-name) target_name=$2 ;;
      esac
      forward_args+=("$1" "$2")
      shift 2
      ;;
    *)
      forward_args+=("$1")
      shift
      ;;
  esac
done

if ((confirm == 0)); then
  printf '%s\n' '{"status":"BLOCKED","reason_code":"CONFIRM_REQUIRED","message":"Use --confirm to prepare the SecCop DEMO."}'
  exit 2
fi

for command_name in terraform aws jq uv; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'missing command: %s\n' "$command_name" >&2
    exit 1
  }
done

run_id=$(date '+%Y%m%dT%H%M%S%z')
evidence_dir="${SECCOP_EVIDENCE_ROOT:-$HOME/.AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-demo-start}/$run_id"
install -d -m 700 "$evidence_dir"
cd "$repo_dir"

AWS_PROFILE="$profile" AWS_REGION="$region" aws sts get-caller-identity >"$evidence_dir/identity.json"
caller_arn=$(jq -r '.Arn // empty' "$evidence_dir/identity.json")
[[ "$caller_arn" == */project1 ]] || {
  printf '%s\n' 'The selected profile is not the Project1 operator identity.' >&2
  exit 1
}

terraform -chdir="$tf_dir" init -input=false >"$evidence_dir/terraform-init.txt"
terraform -chdir="$tf_dir" plan -input=false -out="$evidence_dir/terraform-apply.tfplan" \
  -var="profile=$profile" \
  -var="region=$region" \
  -var="name=$target_name" \
  -var="created=$created" \
  -var="ttl=$ttl" \
  -var="ami_name_pattern=$ami_name_pattern" >"$evidence_dir/terraform-plan.txt"
terraform -chdir="$tf_dir" show -no-color "$evidence_dir/terraform-apply.tfplan" >"$evidence_dir/terraform-plan-expanded.txt"
terraform -chdir="$tf_dir" show -json "$evidence_dir/terraform-apply.tfplan" >"$evidence_dir/terraform-plan.json"
jq -e '
  ([.resource_changes[]?.address] - ["aws_instance.target", "aws_security_group.target"] | length) == 0 and
  all(.resource_changes[]?;
    .mode == "managed" and
    (.change.actions == ["no-op"] or
     .change.actions == ["create"] or
     .change.actions == ["update"]))
' "$evidence_dir/terraform-plan.json" >/dev/null || {
  printf '%s\n' 'Terraform plan widened beyond the bounded SecCop DEMO startup scope.' >&2
  exit 1
}
terraform -chdir="$tf_dir" apply -input=false "$evidence_dir/terraform-apply.tfplan" >"$evidence_dir/terraform-apply.txt"

instance_id=$(terraform -chdir="$tf_dir" output -raw instance_id)
printf '%s\n' "$instance_id" >"$evidence_dir/instance-id.txt"

wait_for_patch_state() {
  local selected_instance_id=$1 phase=$2 phase_dir scan_started ping_status
  phase_dir="$evidence_dir/$phase"
  install -d -m 700 "$phase_dir"
  scan_started=0
  for _ in {1..60}; do
    if ((scan_started == 0)) && ping_status=$(AWS_PROFILE="$profile" AWS_REGION="$region" \
        aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$selected_instance_id" \
        --query 'InstanceInformationList[0].PingStatus' --output text 2>"$phase_dir/ssm-info.stderr"); then
      if [[ "$ping_status" == "Online" ]]; then
        if AWS_PROFILE="$profile" AWS_REGION="$region" aws ssm send-command \
            --document-name AWS-RunPatchBaseline --instance-ids "$selected_instance_id" \
            --parameters Operation=Scan --comment "SecCop DEMO read-only readiness scan" \
            --query 'Command.CommandId' --output text >"$phase_dir/patch-scan-command-id.txt" \
            2>"$phase_dir/patch-scan-command.stderr"; then
          scan_started=1
        fi
      fi
    fi
    if AWS_PROFILE="$profile" AWS_REGION="$region" aws ssm describe-instance-patch-states \
        --instance-ids "$selected_instance_id" --output json >"$phase_dir/patch-state.json" 2>"$phase_dir/patch-state.stderr" \
        && jq -e '.InstancePatchStates | length == 1' "$phase_dir/patch-state.json" >/dev/null 2>&1; then
      cp "$phase_dir/patch-state.json" "$evidence_dir/patch-state.json"
      return 0
    fi
    sleep 5
  done
  printf '%s\n' 'SSM Patch Manager state was not ready after the launch wait.' >&2
  return 1
}

# SSM registration and Patch Manager state can lag a successful EC2 launch.
# Start a scan-only Patch Manager operation once SSM is online, then wait for
# the patch summary before the Python DEMO baseline check.
wait_for_patch_state "$instance_id" initial

missing_count=$(jq -r '.InstancePatchStates[0].MissingCount // -1' "$evidence_dir/patch-state.json")
security_count=$(jq -r '.InstancePatchStates[0].SecurityNonCompliantCount // -1' "$evidence_dir/patch-state.json")
[[ "$missing_count" =~ ^[0-9]+$ && "$security_count" =~ ^[0-9]+$ ]] || {
  printf '%s\n' 'SSM returned an invalid Patch Manager summary.' >&2
  exit 1
}

# A previously remediated disposable target cannot demonstrate the finding.
# The one-command startup contract permits recycling only this exact EC2
# resource; the dedicated security group and all shared infrastructure remain.
if ((missing_count == 0 && security_count == 0)); then
  terraform -chdir="$tf_dir" plan -input=false -replace=aws_instance.target \
    -out="$evidence_dir/terraform-reset.tfplan" \
    -var="profile=$profile" \
    -var="region=$region" \
    -var="name=$target_name" \
    -var="created=$created" \
    -var="ttl=$ttl" \
    -var="ami_name_pattern=$ami_name_pattern" >"$evidence_dir/terraform-reset-plan.txt"
  terraform -chdir="$tf_dir" show -no-color "$evidence_dir/terraform-reset.tfplan" >"$evidence_dir/terraform-reset-plan-expanded.txt"
  terraform -chdir="$tf_dir" show -json "$evidence_dir/terraform-reset.tfplan" >"$evidence_dir/terraform-reset-plan.json"
  jq -e '
    ([.resource_changes[]?.address] - ["aws_instance.target", "aws_security_group.target"] | length) == 0 and
    any(.resource_changes[]?;
      .address == "aws_instance.target" and
      (.change.actions == ["delete", "create"] or .change.actions == ["create", "delete"])) and
    all(.resource_changes[]?;
      .mode == "managed" and
      (.change.actions == ["no-op"] or
       .change.actions == ["delete", "create"] or
       .change.actions == ["create", "delete"]))
  ' "$evidence_dir/terraform-reset-plan.json" >/dev/null || {
    printf '%s\n' 'Terraform reset plan widened beyond the one disposable EC2 target.' >&2
    exit 1
  }
  terraform -chdir="$tf_dir" apply -input=false "$evidence_dir/terraform-reset.tfplan" >"$evidence_dir/terraform-reset-apply.txt"
  instance_id=$(terraform -chdir="$tf_dir" output -raw instance_id)
  printf '%s\n' "$instance_id" >"$evidence_dir/instance-id.txt"
  wait_for_patch_state "$instance_id" recycled
fi

SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_TARGET_NAME="$target_name" \
  uv run python scripts/seccop_demo.py start "${forward_args[@]}" \
  >"$evidence_dir/seccop-start.json"
cat "$evidence_dir/seccop-start.json"
printf 'Evidence: %s\n' "$evidence_dir" >&2
