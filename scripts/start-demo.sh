#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tf_dir="$repo_dir/infra/project1-seccop-ec2"
profile=${SECCOP_PROFILE:-vagent}
region=${SECCOP_REGION:-ap-southeast-1}
target_name=${SECCOP_TARGET_NAME:-seccop-project1-old-ami-host-r01}
ami_name_pattern=${SECCOP_AMI_NAME_PATTERN:-amzn2-ami-hvm-2.0.20260608.0-x86_64-gp2}
expected_principal=project1
instance_profile=seccop-project1-ssm-r01
subnet_id=
ec2_only=0
confirm=0
forward_args=()

while (($#)); do
  case "$1" in
    --confirm)
      confirm=1
      forward_args+=("$1")
      shift
      ;;
    --ec2-only)
      ec2_only=1
      shift
      ;;
    --profile|--region|--target-name|--expected-principal|--instance-profile|--subnet-id)
      [[ $# -ge 2 ]] || { printf '%s needs a value\n' "$1" >&2; exit 2; }
      case "$1" in
        --profile) profile=$2 ;;
        --region) region=$2 ;;
        --target-name) target_name=$2 ;;
        --expected-principal) expected_principal=$2 ;;
        --instance-profile) instance_profile=$2 ;;
        --subnet-id) subnet_id=$2 ;;
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
[[ "$caller_arn" == */"$expected_principal" ]] || {
  printf '%s\n' 'The selected profile does not match the expected operator identity.' >&2
  exit 1
}

tf_args=(
  -var="profile=$profile"
  -var="region=$region"
  -var="name=$target_name"
  -var="ami_name_pattern=$ami_name_pattern"
)
if ((ec2_only == 1)); then
  [[ "$profile" == amit && "$expected_principal" == amit && "$region" == ap-southeast-1 ]] || {
    printf '%s\n' 'The EC2-only lane is restricted to the approved amit identity.' >&2
    exit 1
  }
  [[ "$target_name" == seccop-amit-inspector-host-r01 ]] || {
    printf '%s\n' 'The EC2-only target name is not allowlisted.' >&2
    exit 1
  }
  [[ "$instance_profile" == AmazonSSMRoleForInstancesQuickSetup && "$subnet_id" == subnet-* ]] || {
    printf '%s\n' 'The EC2-only reuse inputs are not allowlisted.' >&2
    exit 1
  }
  ttl=$(date '+%d-%m-%y')
  created=$(date '+%Y-%m-%d')
  expires_at=$(date --iso-8601=seconds --date='+2 hours')
  tf_args+=(
    -var="operator=amit"
    -var="issue=40"
    -var="created=$created"
    -var="ttl=$ttl"
    -var="expires_at=$expires_at"
    -var="subnet_id=$subnet_id"
    -var="instance_profile_name=$instance_profile"
  )
fi

terraform -chdir="$tf_dir" init -input=false >"$evidence_dir/terraform-init.txt"
terraform -chdir="$tf_dir" plan -input=false -out="$evidence_dir/terraform-apply.tfplan" \
  "${tf_args[@]}" >"$evidence_dir/terraform-plan.txt"
terraform -chdir="$tf_dir" show -no-color "$evidence_dir/terraform-apply.tfplan" >"$evidence_dir/terraform-plan-expanded.txt"
terraform -chdir="$tf_dir" show -json "$evidence_dir/terraform-apply.tfplan" >"$evidence_dir/terraform-plan.json"
if ((ec2_only == 1)); then
  jq -e '
    [.resource_changes[] | select(.change.actions != ["no-op"]) | {address, actions: .change.actions}]
    | sort_by(.address)
    == [
      {"address":"aws_instance.target","actions":["create"]},
      {"address":"aws_security_group.target","actions":["create"]}
    ]
  ' "$evidence_dir/terraform-plan.json" >/dev/null || {
    printf '%s\n' 'The EC2-only Terraform plan exceeded the two-resource allowlist.' >&2
    exit 1
  }
fi
terraform -chdir="$tf_dir" apply -input=false "$evidence_dir/terraform-apply.tfplan" >"$evidence_dir/terraform-apply.txt"

instance_id=$(terraform -chdir="$tf_dir" output -raw instance_id)
printf '%s\n' "$instance_id" >"$evidence_dir/instance-id.txt"

if ((ec2_only == 1)); then
  jq -nc '{status:"CREATED",reason_code:"SECCOP_EC2_ONLY_CREATED",resource_alias:"EC2_RESOURCE_01",mutation_performed:true}'
  printf 'Evidence: %s\n' "$evidence_dir" >&2
  exit 0
fi

# SSM registration and Patch Manager state can lag a successful EC2 launch.
# Start a scan-only Patch Manager operation once SSM is online, then wait for
# the read-only patch summary before the Python DEMO baseline check.
scan_started=0
for attempt in {1..60}; do
  if ((scan_started == 0)) && ping_status=$(AWS_PROFILE="$profile" AWS_REGION="$region" \
      aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$instance_id" \
      --query 'InstanceInformationList[0].PingStatus' --output text 2>"$evidence_dir/ssm-info.stderr"); then
    if [[ "$ping_status" == "Online" ]]; then
      if AWS_PROFILE="$profile" AWS_REGION="$region" aws ssm send-command \
          --document-name AWS-RunPatchBaseline --instance-ids "$instance_id" \
          --parameters Operation=Scan --comment "SecCop DEMO read-only readiness scan" \
          --query 'Command.CommandId' --output text >"$evidence_dir/patch-scan-command-id.txt" \
          2>"$evidence_dir/patch-scan-command.stderr"; then
        scan_started=1
      fi
    fi
  fi
  if AWS_PROFILE="$profile" AWS_REGION="$region" aws ssm describe-instance-patch-states \
      --instance-ids "$instance_id" --output json >"$evidence_dir/patch-state.json" 2>"$evidence_dir/patch-state.stderr" \
      && jq -e '.InstancePatchStates | length == 1' "$evidence_dir/patch-state.json" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
jq -e '.InstancePatchStates | length == 1' "$evidence_dir/patch-state.json" >/dev/null || {
  printf '%s\n' 'SSM Patch Manager state was not ready after the launch wait.' >&2
  exit 1
}

SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_TARGET_NAME="$target_name" \
  uv run python scripts/seccop_demo.py start "${forward_args[@]}" \
  >"$evidence_dir/seccop-start.json"
cat "$evidence_dir/seccop-start.json"
printf 'Evidence: %s\n' "$evidence_dir" >&2
