#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tf_dir="$repo_dir/infra/project1-seccop-ec2"
profile=${SECCOP_PROFILE:-}
region=${SECCOP_REGION:-ap-southeast-1}
ami_name_pattern=${SECCOP_AMI_NAME_PATTERN:-amzn2-ami-hvm-2.0.20260608.0-x86_64-gp2}
expected_principal=project1
target_name=seccop-project1-old-ami-host-r01
instance_profile=seccop-project1-ssm-r01
subnet_id=
ec2_only=0
confirm=0

while (($#)); do
  case "$1" in
    --confirm)
      confirm=1
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
      shift 2
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

[[ -n "$profile" ]] || { printf '%s\n' 'explicit --profile or SECCOP_PROFILE is required' >&2; exit 2; }

if ((confirm == 0)); then
  printf '%s\n' '{"status":"BLOCKED","reason_code":"CONFIRM_REQUIRED","message":"Use --confirm to clean the SecCop DEMO."}'
  exit 2
fi

for command_name in terraform aws jq uv; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'missing command: %s\n' "$command_name" >&2
    exit 1
  }
done

run_id=$(date '+%Y%m%dT%H%M%S%z')
evidence_dir="${SECCOP_EVIDENCE_ROOT:-$HOME/.AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-demo-cleanup}/$run_id"
install -d -m 700 "$evidence_dir"
aws=(aws --profile "$profile" --region "$region")

"${aws[@]}" sts get-caller-identity >"$evidence_dir/identity.json"
caller_arn=$(jq -r '.Arn // empty' "$evidence_dir/identity.json")
[[ "$caller_arn" == */"$expected_principal" ]] || {
  printf '%s\n' 'The selected profile does not match the expected operator identity.' >&2
  exit 1
}

if ((ec2_only == 1)); then
  [[ "$profile" == amit && "$expected_principal" == amit && "$region" == ap-southeast-1 ]] || {
    printf '%s\n' 'The EC2-only cleanup is restricted to the approved amit identity.' >&2
    exit 1
  }
  [[ "$target_name" == seccop-amit-inspector-host-r01 ]] || {
    printf '%s\n' 'The EC2-only cleanup target is not allowlisted.' >&2
    exit 1
  }
  [[ "$instance_profile" == AmazonSSMRoleForInstancesQuickSetup && "$subnet_id" == subnet-* ]] || {
    printf '%s\n' 'The EC2-only cleanup reuse inputs are not allowlisted.' >&2
    exit 1
  }
  ttl=$(date '+%d-%m-%y')
  created=$(date '+%Y-%m-%d')
  expires_at=$(date --iso-8601=seconds --date='+2 hours')
  instance_id=$(terraform -chdir="$tf_dir" output -raw instance_id 2>/dev/null || true)
  volume_id=
  group_id=
  if [[ -n "$instance_id" ]]; then
    "${aws[@]}" ec2 describe-instances --instance-ids "$instance_id" >"$evidence_dir/instance-before.json"
    jq -e --arg name "$target_name" '
      .Reservations[0].Instances[0] as $i
      | any($i.Tags[]?; .Key == "Name" and .Value == $name)
      and any($i.Tags[]?; .Key == "Repo" and .Value == "agentic-ai-cybersecurity-lab")
      and ($i.SecurityGroups | length == 1)
    ' "$evidence_dir/instance-before.json" >/dev/null || {
      printf '%s\n' 'The EC2-only cleanup ownership gate failed.' >&2
      exit 1
    }
    volume_id=$(jq -r '.Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId // empty' "$evidence_dir/instance-before.json")
    group_id=$(jq -r '.Reservations[0].Instances[0].SecurityGroups[0].GroupId // empty' "$evidence_dir/instance-before.json")
    "${aws[@]}" ec2 describe-security-groups --group-ids "$group_id" >"$evidence_dir/security-group-before.json"
    jq -e '.SecurityGroups | length == 1 and .[0].IpPermissions == []' "$evidence_dir/security-group-before.json" >/dev/null || {
      printf '%s\n' 'The EC2-only cleanup security-group gate failed.' >&2
      exit 1
    }
  fi
  tf_args=(
    -var="profile=$profile"
    -var="region=$region"
    -var="name=$target_name"
    -var="ami_name_pattern=$ami_name_pattern"
    -var="operator=amit"
    -var="issue=40"
    -var="created=$created"
    -var="ttl=$ttl"
    -var="expires_at=$expires_at"
    -var="subnet_id=$subnet_id"
    -var="instance_profile_name=$instance_profile"
  )
  if [[ -n "$instance_id" ]]; then
    terraform -chdir="$tf_dir" plan -destroy -input=false -out="$evidence_dir/terraform-destroy.tfplan" \
      "${tf_args[@]}" >"$evidence_dir/terraform-destroy-plan.txt"
    terraform -chdir="$tf_dir" show -json "$evidence_dir/terraform-destroy.tfplan" >"$evidence_dir/terraform-destroy-plan.json"
    jq -e '
      [.resource_changes[] | select(.change.actions != ["no-op"]) | {address, actions: .change.actions}]
      | sort_by(.address)
      == [
        {"address":"aws_instance.target","actions":["delete"]},
        {"address":"aws_security_group.target","actions":["delete"]}
      ]
    ' "$evidence_dir/terraform-destroy-plan.json" >/dev/null || {
      printf '%s\n' 'The EC2-only destroy plan exceeded the two-resource allowlist.' >&2
      exit 1
    }
    terraform -chdir="$tf_dir" apply -input=false "$evidence_dir/terraform-destroy.tfplan" >"$evidence_dir/terraform-destroy-apply.txt"
    "${aws[@]}" ec2 wait instance-terminated --instance-ids "$instance_id"
  fi
  active_count=$("${aws[@]}" ec2 describe-instances --filters \
    "Name=tag:Name,Values=$target_name" \
    'Name=tag:Repo,Values=agentic-ai-cybersecurity-lab' \
    'Name=instance-state-name,Values=pending,running,stopping,stopped' \
    --query 'length(Reservations[].Instances[])' --output text)
  [[ "$active_count" == 0 ]] || {
    printf '%s\n' 'The EC2-only target remains active after cleanup.' >&2
    exit 1
  }
  if [[ -n "$volume_id" ]]; then
    [[ $("${aws[@]}" ec2 describe-volumes --filters "Name=volume-id,Values=$volume_id" --query 'length(Volumes)' --output text) == 0 ]] || {
      printf '%s\n' 'The EC2-only root volume remains after cleanup.' >&2
      exit 1
    }
  fi
  if [[ -n "$group_id" ]]; then
    ! "${aws[@]}" ec2 describe-security-groups --group-ids "$group_id" >"$evidence_dir/security-group-after.json" 2>"$evidence_dir/security-group-after.stderr" || {
      printf '%s\n' 'The EC2-only security group remains after cleanup.' >&2
      exit 1
    }
  fi
  jq -nc '{status:"CLEANED",reason_code:"SECCOP_EC2_ONLY_CLEANED",resource_alias:"EC2_RESOURCE_01"}'
  printf 'Evidence: %s\n' "$evidence_dir" >&2
  exit 0
fi

expected_names=(
  seccop-project1-inspector-host-r01
  seccop-project1-old-ami-host-r01
  seccop-project1-old-ami-host-r02
)
"${aws[@]}" ec2 describe-instances \
  --filters \
    'Name=tag:Project,Values=Security Copilot' \
    'Name=tag:Repo,Values=agentic-ai-cybersecurity-lab' \
    'Name=tag:Cleanup,Values=terminate-ec2-only' \
    'Name=instance-state-name,Values=pending,running,stopping,stopped' \
  --output json >"$evidence_dir/instances.json"

instance_ids=()
instance_names=()
security_group_ids=()
for name in "${expected_names[@]}"; do
  instance=$(jq -c --arg name "$name" '[.Reservations[].Instances[] | select(any(.Tags[]?; .Key == "Name" and .Value == $name))] | .[0] // empty' "$evidence_dir/instances.json")
  [[ -n "$instance" ]] || continue
  state=$(jq -r '.State.Name // empty' <<<"$instance")
  [[ "$state" != "terminated" ]] || continue
  instance_id=$(jq -r '.InstanceId // empty' <<<"$instance")
  sg_count=$(jq '.SecurityGroups | length' <<<"$instance")
  [[ -n "$instance_id" && "$sg_count" == 1 ]] || {
    printf 'unexpected SecCop target shape for %s\n' "$name" >&2
    exit 1
  }
  instance_names+=("$name")
  instance_ids+=("$instance_id")
  security_group_ids+=("$(jq -r '.SecurityGroups[0].GroupId' <<<"$instance")")
done

if ((${#instance_ids[@]} > 0)); then
  printf '%s\n' "${instance_ids[@]}" >"$evidence_dir/instance-ids.txt"
  mapfile -t unique_security_groups < <(printf '%s\n' "${security_group_ids[@]}" | sort -u)
  "${aws[@]}" ec2 describe-security-groups --group-ids "${unique_security_groups[@]}" >"$evidence_dir/security-groups.json"
  jq -e 'all(.SecurityGroups[]; (.GroupName | startswith("seccop-project1-")) and (.IpPermissions | length == 0))' "$evidence_dir/security-groups.json" >/dev/null || {
    printf '%s\n' 'A cleanup security group failed the no-ingress ownership gate.' >&2
    exit 1
  }
else
  : >"$evidence_dir/instance-ids.txt"
  : >"$evidence_dir/security-groups.json"
  unique_security_groups=()
fi

terraform -chdir="$tf_dir" init -input=false >"$evidence_dir/terraform-init.txt"

destroy_instance() {
  local name=$1 instance_id=$2 slug state_file plan_file
  slug=${name//[^a-zA-Z0-9]/-}
  state_file="$evidence_dir/$slug.tfstate"
  plan_file="$evidence_dir/$slug.tfplan"
  terraform -chdir="$tf_dir" import -input=false -state="$state_file" \
    -var="profile=$profile" -var="region=$region" -var="name=$name" \
    -var="ami_name_pattern=$ami_name_pattern" aws_instance.target "$instance_id" \
    >"$evidence_dir/$slug-import-instance.txt"
  terraform -chdir="$tf_dir" plan -destroy -input=false -state="$state_file" \
    -out="$plan_file" -var="profile=$profile" -var="region=$region" -var="name=$name" \
    -var="ami_name_pattern=$ami_name_pattern" >"$evidence_dir/$slug-destroy-plan.txt"
  terraform -chdir="$tf_dir" show -no-color "$plan_file" >"$evidence_dir/$slug-destroy-plan-expanded.txt"
  grep -Eq 'will be destroyed' "$evidence_dir/$slug-destroy-plan-expanded.txt" || {
    printf 'Terraform did not produce a destroy plan for %s\n' "$name" >&2
    exit 1
  }
  terraform -chdir="$tf_dir" apply -input=false -state="$state_file" "$plan_file" \
    >"$evidence_dir/$slug-destroy-apply.txt"
  "${aws[@]}" ec2 wait instance-terminated --instance-ids "$instance_id"
}

for index in "${!instance_ids[@]}"; do
  destroy_instance "${instance_names[$index]}" "${instance_ids[$index]}"
done

destroy_security_group() {
  local group_id=$1 slug state_file plan_file
  slug=${group_id//[^a-zA-Z0-9]/-}
  state_file="$evidence_dir/$slug.tfstate"
  plan_file="$evidence_dir/$slug.tfplan"
  terraform -chdir="$tf_dir" import -input=false -state="$state_file" \
    -var="profile=$profile" -var="region=$region" -var="name=seccop-project1-old-ami-host-r01" \
    -var="ami_name_pattern=$ami_name_pattern" aws_security_group.target "$group_id" \
    >"$evidence_dir/$slug-import-security-group.txt"
  terraform -chdir="$tf_dir" plan -destroy -input=false -state="$state_file" \
    -out="$plan_file" -var="profile=$profile" -var="region=$region" \
    -var="name=seccop-project1-old-ami-host-r01" -var="ami_name_pattern=$ami_name_pattern" \
    >"$evidence_dir/$slug-destroy-plan.txt"
  terraform -chdir="$tf_dir" show -no-color "$plan_file" >"$evidence_dir/$slug-destroy-plan-expanded.txt"
  grep -Eq 'will be destroyed' "$evidence_dir/$slug-destroy-plan-expanded.txt" || {
    printf 'Terraform did not produce a destroy plan for security group %s\n' "$group_id" >&2
    exit 1
  }
  terraform -chdir="$tf_dir" apply -input=false -state="$state_file" "$plan_file" \
    >"$evidence_dir/$slug-destroy-apply.txt"
}

for group_id in "${unique_security_groups[@]}"; do
  destroy_security_group "$group_id"
done

SECCOP_PROFILE="$profile" SECCOP_REGION="$region" \
  uv run python scripts/seccop_demo.py cleanup --profile "$profile" --region "$region" --confirm \
  >"$evidence_dir/artifact-cleanup.json"

for instance_id in "${instance_ids[@]}"; do
  state=$("${aws[@]}" ec2 describe-instances --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].State.Name' --output text)
  [[ "$state" == "terminated" ]] || {
    printf 'instance was not verified terminated: %s\n' "$instance_id" >&2
    exit 1
  }
done
"${aws[@]}" ec2 describe-instances --instance-ids "${instance_ids[@]}" >"$evidence_dir/instances-after.json" 2>"$evidence_dir/instances-after.stderr" || true

printf '{"status":"CLEANED","reason_code":"SECCOP_DEMO_CLEANED","instances":%s,"security_groups":%s,"artifact_result":%s}\n' \
  "$(printf '%s\n' "${instance_names[@]}" | jq -R . | jq -s .)" \
  "$(printf '%s\n' "${unique_security_groups[@]}" | jq -R . | jq -s .)" \
  "$(cat "$evidence_dir/artifact-cleanup.json")"
printf 'Evidence: %s\n' "$evidence_dir" >&2
