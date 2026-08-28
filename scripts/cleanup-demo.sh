#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tf_dir="$repo_dir/infra/project1-seccop-ec2"
profile=${SECCOP_PROFILE:-vagent}
region=${SECCOP_REGION:-ap-southeast-1}
ami_name_pattern=${SECCOP_AMI_NAME_PATTERN:-amzn2-ami-hvm-2.0.20260608.0-x86_64-gp2}
confirm=0

while (($#)); do
  case "$1" in
    --confirm)
      confirm=1
      shift
      ;;
    --profile|--region)
      [[ $# -ge 2 ]] || { printf '%s needs a value\n' "$1" >&2; exit 2; }
      case "$1" in
        --profile) profile=$2 ;;
        --region) region=$2 ;;
      esac
      shift 2
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

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
[[ "$caller_arn" == */project1 ]] || {
  printf '%s\n' 'The selected profile is not the Project1 operator identity.' >&2
  exit 1
}

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
