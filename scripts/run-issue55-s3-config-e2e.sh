#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

# Corrected Issue #55 EC2 IMDSv2 path.  Keep this in the existing trusted
# runner so the S3 journey below remains unchanged and no parallel harness is
# introduced.
if [[ ${SECCOP_EC2_IMDSV2_E2E:-0} == 1 ]]; then
  profile=${AWS_PROFILE:-amit}
  region=${AWS_REGION:-ap-southeast-1}
  port=${SECCOP_API_PORT:-2225}
  evidence_dir=${SECCOP_EC2_EVIDENCE_DIR:?SECCOP_EC2_EVIDENCE_DIR must be private}
  state=${SECCOP_EC2_STATE:?SECCOP_EC2_STATE must be private}
  ami_pattern=${SECCOP_EC2_AMI_NAME_PATTERN:-al2023-ami-2023.12.20260831.0-kernel-6.18-x86_64}
  retain_mode=${SECCOP_EC2_RETAINED_E2E:-0}
  dev_existing_mode=${SECCOP_EC2_DEV_EXISTING_E2E:-0}
  target_id=${SECCOP_EC2_TARGET_ID:-}
  mkdir -p "$evidence_dir"; chmod 700 "$evidence_dir"
  export AWS_PROFILE="$profile" AWS_DEFAULT_PROFILE="$profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region"
  export SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" SECCOP_EC2_STATE="$state"
  if [[ "$dev_existing_mode" == 1 ]]; then
    [[ "$profile" == ihis_dev && "$region" == ap-southeast-1 ]] || { echo 'DEV existing-target mode requires ihis_dev/ap-southeast-1' >&2; exit 1; }
  else
    [[ "$profile" == amit && "$region" == ap-southeast-1 ]] || { echo 'explicit amit/ap-southeast-1 is required' >&2; exit 1; }
  fi
  [[ "$retain_mode" == 0 || "$retain_mode" == 1 ]] || { echo 'SECCOP_EC2_RETAINED_E2E must be 0 or 1' >&2; exit 1; }
  [[ "$dev_existing_mode" == 0 || "$dev_existing_mode" == 1 ]] || { echo 'SECCOP_EC2_DEV_EXISTING_E2E must be 0 or 1' >&2; exit 1; }
  if [[ "$dev_existing_mode" == 1 ]]; then
    [[ "$profile" == ihis_dev && "$region" == ap-southeast-1 && "$target_id" =~ ^i-[0-9a-f]+$ ]] || { echo 'DEV mode requires the exact approved target and profile' >&2; exit 1; }
  fi
  [[ "$port" =~ ^[0-9]+$ && "$port" != 2222 ]] || { echo 'EC2 rehearsal port is invalid or reserved' >&2; exit 1; }
  if ss -ltn 2>/dev/null | awk -v port=":$port" '$4 == port {found=1} END {exit found}'; then
    :
  else
    echo "EC2 rehearsal port $port is already in use" >&2
    exit 1
  fi
  aws sts get-caller-identity >"$evidence_dir/e2e-sts.json"
  if [[ "$dev_existing_mode" == 1 ]]; then
    aws ec2 describe-instances --instance-ids "$target_id" >"$evidence_dir/target-before.json"
    jq -e '.Reservations | map(.Instances[]) | length == 1 and .[0].State.Name == "running" and (. [0].PublicIpAddress == null) and .[0].MetadataOptions.HttpTokens == "optional" and (. [0].SecurityGroups | length == 1)' "$evidence_dir/target-before.json" >/dev/null || { echo 'DEV target preflight is not running/private/optional' >&2; exit 1; }
    group_id=$(jq -r '.Reservations[0].Instances[0].SecurityGroups[0].GroupId' "$evidence_dir/target-before.json")
    aws ec2 describe-security-groups --group-ids "$group_id" >"$evidence_dir/security-group-before.json"
    jq -e '.SecurityGroups | length == 1 and .[0].IpPermissions == []' "$evidence_dir/security-group-before.json" >/dev/null || { echo 'DEV target security group is not zero-ingress' >&2; exit 1; }
    aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$target_id" >"$evidence_dir/ssm-before.json"
    jq -e '.InstanceInformationList | map(select(.InstanceId == "'"$target_id"'" and .PingStatus == "Online")) | length == 1' "$evidence_dir/ssm-before.json" >/dev/null || { echo 'DEV target is not SSM Online' >&2; exit 1; }
    account=$(jq -r '.Account' "$evidence_dir/e2e-sts.json")
    caller_role=$(jq -r '.Arn | capture("assumed-role/(?<name>[^/]+)/") | .name' "$evidence_dir/e2e-sts.json")
    [[ "$caller_role" == u-tf-role ]] || { echo 'DEV caller is not the approved u-tf-role session' >&2; exit 1; }
    caller_arn="arn:aws:iam::$account:role/$caller_role"
    reused_role_arn="arn:aws:iam::$account:role/ami-factory-dev-demo-role"
    aws iam simulate-principal-policy --policy-source-arn "$caller_arn" --action-names iam:PassRole --resource-arns "$reused_role_arn" --context-entries ContextKeyName=iam:PassedToService,ContextKeyValues=ssm.amazonaws.com,ContextKeyType=string >"$evidence_dir/passrole-simulation.json"
    jq -e '.EvaluationResults | map(select(.EvalActionName == "iam:PassRole" and .EvalResourceName == "'"$reused_role_arn"'" and .EvalDecision == "allowed")) | length == 1' "$evidence_dir/passrole-simulation.json" >/dev/null || { echo 'Caller cannot PassRole to the approved reused role for SSM' >&2; exit 1; }
    aws iam get-role --role-name ami-factory-dev-demo-role >"$evidence_dir/reused-role-before.json"
    aws iam list-role-policies --role-name ami-factory-dev-demo-role >"$evidence_dir/reused-role-inline-before.json"
    aws iam list-attached-role-policies --role-name ami-factory-dev-demo-role >"$evidence_dir/reused-role-attached-before.json"
    jq -e '.Role.AssumeRolePolicyDocument.Statement | map(.Principal.Service // empty) | flatten | index("ssm.amazonaws.com") != null' "$evidence_dir/reused-role-before.json" >/dev/null || { echo 'Approved reused role lacks SSM trust' >&2; exit 1; }
    aws configservice describe-config-rules --config-rule-names ec2-imdsv2-check >"$evidence_dir/config-rule-before.json" 2>"$evidence_dir/config-rule-before.stderr" || true
    if [[ -s "$evidence_dir/config-rule-before.json" ]]; then
      jq -e '.ConfigRules | length == 1 and .[0].ConfigRuleName == "ec2-imdsv2-check" and .[0].Source.Owner == "AWS" and .[0].Source.SourceIdentifier == "EC2_IMDSV2_CHECK" and .[0].Scope.ComplianceResourceTypes == ["AWS::EC2::Instance"] and .[0].Scope.ComplianceResourceId == "'"$target_id"'"' "$evidence_dir/config-rule-before.json" >/dev/null || { echo 'Existing DEV Config rule is not the exact approved target' >&2; exit 1; }
    fi
    aws configservice describe-remediation-configurations --config-rule-names ec2-imdsv2-check >"$evidence_dir/remediation-before.json"
    jq -e '(.RemediationConfigurations // []) | length == 0' "$evidence_dir/remediation-before.json" >/dev/null || { echo 'DEV remediation binding already exists unexpectedly' >&2; exit 1; }
  fi
  if [[ "$dev_existing_mode" != 1 ]]; then
    aws ec2 describe-images --owners amazon --filters "Name=name,Values=$ami_pattern" "Name=state,Values=available" >"$evidence_dir/ami-preflight.json"
    jq -e '.Images | length == 1 and .[0].State == "available"' "$evidence_dir/ami-preflight.json" >/dev/null || {
      echo 'The approved current Amazon Linux AMI was not uniquely available' >&2
      exit 1
    }
  fi
  aws configservice describe-configuration-recorders >"$evidence_dir/recorder-before.json"
  aws configservice describe-configuration-recorder-status >"$evidence_dir/recorder-status-before.json"
  if [[ "$dev_existing_mode" == 1 ]]; then
    jq -e '.ConfigurationRecorders | length == 1 and .[0].recordingGroup.allSupported == true' "$evidence_dir/recorder-before.json" >/dev/null || { echo 'DEV Config recorder is not all-supported' >&2; exit 1; }
    jq -e '[.ConfigurationRecordersStatus[] | select(.recording == true)] | length == 1' "$evidence_dir/recorder-status-before.json" >/dev/null || { echo 'DEV Config recorder is not active' >&2; exit 1; }
  else
    aws configservice describe-delivery-channels >"$evidence_dir/delivery-before.json"
    jq -e '[.ConfigurationRecorders[] | select(.name == "seccop-issue55-s3-recorder")] | length == 1' "$evidence_dir/recorder-before.json" >/dev/null || { echo 'Approved Config recorder is not exact' >&2; exit 1; }
    jq -e '[.DeliveryChannels[] | select(.name == "seccop-issue55-s3-delivery")] | length == 1' "$evidence_dir/delivery-before.json" >/dev/null || { echo 'Approved delivery channel is not exact' >&2; exit 1; }
  fi

  server_pid=
  cleanup_done=0
  cleanup_ec2() {
    local cleanup_rc=0
    if [[ -n "${server_pid:-}" ]]; then
      kill "$server_pid" 2>/dev/null || true
      wait "$server_pid" 2>/dev/null || true
      server_pid=
    fi
    if [[ "$retain_mode" != 1 && "$dev_existing_mode" != 1 && "$cleanup_done" != 1 && -f "$state" ]]; then
      SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" SECCOP_EC2_STATE="$state" \
        /usr/bin/python3 "$repo_dir/scripts/issue47_s3_compliance.py" ec2-cleanup --profile "$profile" --region "$region" >"$evidence_dir/cleanup-on-exit.json" 2>>"$evidence_dir/cleanup-on-exit.stderr" || cleanup_rc=$?
    fi
    # Keep the EXIT trap from masking the evidence file; callers assert the
    # repo-owned cleanup result and independently verify every resource.
    return 0
  }
  trap cleanup_ec2 EXIT

  if [[ "$dev_existing_mode" == 1 ]]; then
    SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" SECCOP_EC2_STATE="$state" SECCOP_EC2_TARGET_ID="$target_id" SECCOP_EC2_AUTOMATION_ROLE=ami-factory-dev-demo-role SECCOP_EC2_REUSE_ROLE=1 \
      /usr/bin/python3 "$repo_dir/scripts/issue47_s3_compliance.py" ec2-adopt --profile "$profile" --region "$region" --instance-id "$target_id" >"$evidence_dir/setup.json"
  else
    SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" SECCOP_EC2_STATE="$state" SECCOP_EC2_AMI_NAME_PATTERN="$ami_pattern" \
      /usr/bin/python3 "$repo_dir/scripts/issue47_s3_compliance.py" ec2-setup --profile "$profile" --region "$region" >"$evidence_dir/setup.json"
  fi
  if [[ "$dev_existing_mode" == 1 ]]; then
    jq -e '.status == "READY" and .reason_code == "SECCOP_EC2_DEV_TARGET_READY"' "$evidence_dir/setup.json" >/dev/null
  else
    jq -e '.status == "READY" and .reason_code == "SECCOP_EC2_IMDSV2_SETUP_READY"' "$evidence_dir/setup.json" >/dev/null
  fi

  cd "$repo_dir"
  SECCOP_DEMO_BACKEND=AWS SECCOP_EC2_IMDSV2_E2E=1 SECCOP_PROFILE="$profile" SECCOP_REGION="$region" AWS_PROFILE="$profile" AWS_DEFAULT_PROFILE="$profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region" SECCOP_EC2_STATE="$state" SECCOP_EC2_EVIDENCE_DIR="$evidence_dir" SECCOP_EC2_TARGET_ID="$target_id" SECCOP_EC2_AUTOMATION_ROLE=ami-factory-dev-demo-role SECCOP_EC2_REUSE_ROLE=1 POC_PORT="$port" \
    .venv/bin/python -m secure_agent_harness.poc_server >"$evidence_dir/server.log" 2>&1 &
  server_pid=$!
  for _ in {1..30}; do
    if curl -fsS --max-time 2 "http://127.0.0.1:$port/api/health" >"$evidence_dir/health.json"; then break; fi
    sleep 1
  done
  jq -e '.review_mode == "EC2_IMDSV2" and .demo_backend == "AWS" and (.enabled_sources | index("ec2"))' "$evidence_dir/health.json" >/dev/null
  post() { curl --fail-with-body --max-time 500 -sS -X POST "http://127.0.0.1:$port$1" -H 'Content-Type: application/json' --data-binary "$2"; }
  post /api/demo/fix '{"source":"ec2","confirm":true}' >"$evidence_dir/before-approval.json"
  jq -e '.result.status == "BLOCKED"' "$evidence_dir/before-approval.json" >/dev/null
  post /api/scan '{"mode":"DEMO","source":"ec2","request_text":"Review the EC2 IMDSv2 compliance finding"}' >"$evidence_dir/scan-non-compliant.json"
  jq -e '.result.reason_code == "SECCOP_EC2_IMDSV2_NON_COMPLIANT" and (.result.proposal_id | startswith("SECCOP_PROPOSAL_")) and (.result.findings[0].source_type == "EC2_CONFIG")' "$evidence_dir/scan-non-compliant.json" >/dev/null
  proposal_id=$(jq -r '.result.proposal_id' "$evidence_dir/scan-non-compliant.json")
  proposal_hash=$(jq -r '.result.proposal_hash' "$evidence_dir/scan-non-compliant.json")
  post /api/demo/fix "$(jq -nc --arg id "$proposal_id" '{source:"ec2",confirm:true,proposal_id:$id,proposal_hash:"wrong"}')" >"$evidence_dir/wrong-proposal.json"
  jq -e '.result.status == "BLOCKED"' "$evidence_dir/wrong-proposal.json" >/dev/null
  post /api/demo/fix "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"s3",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/cross-source.json"
  jq -e '.result.status == "BLOCKED"' "$evidence_dir/cross-source.json" >/dev/null
  post /api/demo/reject "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"ec2",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/reject.json"
  jq -e '.result.status == "REJECTED" and .result.mutation_performed == false and .result.state == "NON_COMPLIANT"' "$evidence_dir/reject.json" >/dev/null
  post /api/scan '{"mode":"DEMO","source":"ec2","request_text":"Recheck the EC2 IMDSv2 compliance finding"}' >"$evidence_dir/scan-before-remediation.json"
  jq -e '.result.reason_code == "SECCOP_EC2_IMDSV2_NON_COMPLIANT"' "$evidence_dir/scan-before-remediation.json" >/dev/null
  proposal_id=$(jq -r '.result.proposal_id' "$evidence_dir/scan-before-remediation.json")
  proposal_hash=$(jq -r '.result.proposal_hash' "$evidence_dir/scan-before-remediation.json")

  if [[ "$retain_mode" == 1 && "$dev_existing_mode" != 1 ]]; then
    instance_id=$(jq -r '.instance_id' "$state")
    group_id=$(jq -r '.security_group_id' "$state")
    volume_id=$(jq -r '.volume_id // empty' "$state")
    aws ec2 describe-instances --instance-ids "$instance_id" >"$evidence_dir/retained-target.json"
    jq -e '.Reservations | map(.Instances[]) | length == 1 and .[0].State.Name == "running" and .[0].InstanceType == "t3.micro" and .[0].MetadataOptions.HttpTokens == "optional" and (. [0].SecurityGroups | length == 1)' "$evidence_dir/retained-target.json" >/dev/null
    [[ -n "$volume_id" ]] || { echo 'Retained target root volume was not recorded' >&2; exit 1; }
    aws ec2 describe-volumes --volume-ids "$volume_id" >"$evidence_dir/retained-volume.json"
    jq -e '.Volumes | length == 1 and .[0].Encrypted == true and .[0].VolumeType == "gp3"' "$evidence_dir/retained-volume.json" >/dev/null
    aws ec2 describe-security-groups --group-ids "$group_id" >"$evidence_dir/retained-security-group.json"
    jq -e '.SecurityGroups | length == 1 and .[0].IpPermissions == []' "$evidence_dir/retained-security-group.json" >/dev/null
    aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$instance_id" >"$evidence_dir/retained-ssm.json"
    jq -e '.InstanceInformationList | map(select(.InstanceId == "'"$instance_id"'" and .PingStatus == "Online")) | length == 1' "$evidence_dir/retained-ssm.json" >/dev/null
    aws configservice describe-config-rules --config-rule-names ec2-imdsv2-check >"$evidence_dir/retained-config-rule.json"
    jq -e '.ConfigRules | length == 1 and .[0].ConfigRuleName == "ec2-imdsv2-check" and .[0].Source.Owner == "AWS" and .[0].Source.SourceIdentifier == "EC2_IMDSV2_CHECK" and .[0].Scope.ComplianceResourceTypes == ["AWS::EC2::Instance"] and .[0].Scope.ComplianceResourceId == "'"$instance_id"'"' "$evidence_dir/retained-config-rule.json" >/dev/null
    rule_arn=$(jq -r '.ConfigRules[0].ConfigRuleArn' "$evidence_dir/retained-config-rule.json")
    aws configservice describe-remediation-configurations --config-rule-names ec2-imdsv2-check >"$evidence_dir/retained-remediation.json"
    jq -e '.RemediationConfigurations | length == 1 and .[0].TargetType == "SSM_DOCUMENT" and .[0].TargetId == "AWSConfigRemediation-EnforceEC2InstanceIMDSv2" and (. [0].TargetVersion | tostring) == "4" and .[0].Automatic == false and .[0].Parameters.InstanceId.ResourceValue.Value == "RESOURCE_ID"' "$evidence_dir/retained-remediation.json" >/dev/null
    aws configservice list-tags-for-resource --resource-arn "$rule_arn" >"$evidence_dir/retained-config-rule-tags.json"
    jq -e '[.Tags[] | select(.Key == "cleanup" and .Value == "keep")] | length == 1' "$evidence_dir/retained-config-rule-tags.json" >/dev/null
    jq -e '[.Tags[] | select(.Key == "TTL" and .Value == "01-10-26")] | length == 1' "$evidence_dir/retained-config-rule-tags.json" >/dev/null
    aws iam get-role-policy --role-name SecCopIssue55S3Automation --policy-name SecCopIssue55Ec2ImdsV2 >"$evidence_dir/retained-automation-policy.json"
    jq -e '.PolicyVersion.Document.Statement | map(.Action) | flatten | sort == ["ec2:DescribeInstances","ec2:ModifyInstanceMetadataOptions"]' "$evidence_dir/retained-automation-policy.json" >/dev/null
    aws configservice describe-configuration-recorders >"$evidence_dir/retained-recorder.json"
    jq -e '[.ConfigurationRecorders[] | select(.name == "seccop-issue55-s3-recorder") | .recordingGroup.resourceTypes] | flatten | index("AWS::S3::Bucket") != null and index("AWS::EC2::Instance") != null' "$evidence_dir/retained-recorder.json" >/dev/null
    aws configservice describe-configuration-recorder-status >"$evidence_dir/retained-recorder-status.json"
    jq -e '[.ConfigurationRecordersStatus[] | select(.name == "seccop-issue55-s3-recorder" and .recording == true)] | length == 1' "$evidence_dir/retained-recorder-status.json" >/dev/null
    aws configservice describe-delivery-channels >"$evidence_dir/retained-delivery.json"
    cmp -s <(jq -S . "$evidence_dir/delivery-before.json") <(jq -S . "$evidence_dir/retained-delivery.json") || { echo 'Delivery channel changed unexpectedly' >&2; exit 1; }
    if [[ -n "${server_pid:-}" ]]; then
      kill "$server_pid" 2>/dev/null || true
      wait "$server_pid" 2>/dev/null || true
      server_pid=
    fi
    cleanup_done=1
    jq -n '{status:"PASS",health:"EC2_IMDSV2",finding:"NON_COMPLIANT",wrong_proposal:"BLOCKED",cross_source:"BLOCKED",reject:"REJECTED_NO_MUTATION",retention:"KEEP",target:"RUNNING_T3_MICRO",ssm:"ONLINE",metadata:"HttpTokens=optional",config_rule:"EXACT_ACTIVE",remediation:"MANUAL_AWS_MANAGED_V4",recorder:"S3_AND_EC2_RECORDING",delivery:"UNCHANGED",cleanup:"NOT_RUN_BY_POLICY",resources_retained:["EC2_TARGET","DEDICATED_SECURITY_GROUP","ENCRYPTED_ROOT_VOLUME","CONFIG_RULE","REMEDIATION_CONFIGURATION","AUTOMATION_ROLE_POLICY","CONFIG_RECORDER","CONFIG_DELIVERY","S3","ECR"],old_package_and_cve_path:"EXCLUDED",aws_profile:"amit",region:"ap-southeast-1"}'
    exit 0
  fi

  post /api/demo/fix "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"ec2",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/remediate.json"
  jq -e '.result.status == "VERIFIED" and .result.state == "COMPLIANT" and .result.metadata_http_tokens == "required" and .result.automation_status == "Success"' "$evidence_dir/remediate.json" >/dev/null
  post /api/demo/fix "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"ec2",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/replay-proposal.json"
  jq -e '.result.status == "BLOCKED"' "$evidence_dir/replay-proposal.json" >/dev/null
  post /api/scan '{"mode":"DEMO","source":"ec2","request_text":"Verify the EC2 IMDSv2 protected state"}' >"$evidence_dir/scan-compliant.json"
  jq -e '.result.reason_code == "SECCOP_EC2_IMDSV2_COMPLIANT" and .result.state == "COMPLIANT" and (.result.findings | length) == 0' "$evidence_dir/scan-compliant.json" >/dev/null

  if [[ "$dev_existing_mode" == 1 ]]; then
    jq -e '.result.status == "VERIFIED" and .result.metadata_http_tokens == "required" and .result.automation_status == "Success"' "$evidence_dir/remediate.json" >/dev/null
    aws ec2 describe-instances --instance-ids "$target_id" >"$evidence_dir/target-retained.json"
    jq -e '.Reservations | map(.Instances[]) | length == 1 and .[0].InstanceId == "'"$target_id"'" and .[0].State.Name == "running" and .[0].MetadataOptions.HttpTokens == "required"' "$evidence_dir/target-retained.json" >/dev/null
    aws configservice describe-config-rules --config-rule-names ec2-imdsv2-check >"$evidence_dir/config-rule-retained.json"
    jq -e '.ConfigRules | length == 1 and .[0].ConfigRuleName == "ec2-imdsv2-check" and .[0].Source.Owner == "AWS" and .[0].Source.SourceIdentifier == "EC2_IMDSV2_CHECK" and .[0].ConfigRuleState == "ACTIVE"' "$evidence_dir/config-rule-retained.json" >/dev/null
    aws configservice describe-remediation-configurations --config-rule-names ec2-imdsv2-check >"$evidence_dir/remediation-retained.json"
    jq -e '.RemediationConfigurations | length == 1 and .[0].TargetId == "AWSConfigRemediation-EnforceEC2InstanceIMDSv2" and ((.[0].TargetVersion|tostring) == "4") and .[0].Automatic == false' "$evidence_dir/remediation-retained.json" >/dev/null
    aws iam get-role --role-name ami-factory-dev-demo-role >"$evidence_dir/reused-role-after.json"
    aws iam list-role-policies --role-name ami-factory-dev-demo-role >"$evidence_dir/reused-role-inline-after.json"
    aws iam list-attached-role-policies --role-name ami-factory-dev-demo-role >"$evidence_dir/reused-role-attached-after.json"
    cmp -s <(jq -S 'del(.Role.RoleLastUsed)' "$evidence_dir/reused-role-before.json") <(jq -S 'del(.Role.RoleLastUsed)' "$evidence_dir/reused-role-after.json") || { echo 'Approved reused role trust/tags changed unexpectedly' >&2; exit 1; }
    cmp -s <(jq -S '.PolicyNames | sort' "$evidence_dir/reused-role-inline-before.json") <(jq -S '.PolicyNames | sort' "$evidence_dir/reused-role-inline-after.json") || { echo 'Approved reused role inline policies changed unexpectedly' >&2; exit 1; }
    cmp -s <(jq -S '.AttachedPolicies | map({PolicyArn,PolicyName}) | sort_by(.PolicyArn)' "$evidence_dir/reused-role-attached-before.json") <(jq -S '.AttachedPolicies | map({PolicyArn,PolicyName}) | sort_by(.PolicyArn)' "$evidence_dir/reused-role-attached-after.json") || { echo 'Approved reused role managed policies changed unexpectedly' >&2; exit 1; }
    if [[ -n "${server_pid:-}" ]]; then
      kill "$server_pid" 2>/dev/null || true
      wait "$server_pid" 2>/dev/null || true
      server_pid=
    fi
    cleanup_done=1
    jq -n '{status:"PASS",health:"EC2_IMDSV2",finding:"NON_COMPLIANT",wrong_proposal:"BLOCKED",cross_source:"BLOCKED",reject:"REJECTED_NO_MUTATION",remediation:"VERIFIED",automation:"SUCCESS",metadata:"HttpTokens=required",compliant:"COMPLIANT",replay:"BLOCKED",retention:"KEEP",cleanup:"NOT_RUN_BY_POLICY",target_alias:"DEV_EC2_RESOURCE_01",config_rule:"ACTIVE_EXACT",remediation_binding:"MANUAL_AWS_MANAGED_V4",automation_role:"AMI_FACTORY_DEV_DEMO_ROLE_REUSED_UNCHANGED",aws_profile:"ihis_dev",region:"ap-southeast-1"}'
    exit 0
  fi

  cleanup_ec2
  cleanup_done=1
  jq -e '.status == "CLEANED" and .reason_code == "SECCOP_EC2_CLEANUP_VERIFIED"' "$evidence_dir/cleanup-on-exit.json" >/dev/null
  aws ec2 describe-instances --filters 'Name=tag:Name,Values=seccop-amit-inspector-host-r01' 'Name=tag:Repo,Values=agentic-ai-cybersecurity-lab' 'Name=instance-state-name,Values=pending,running,stopping,stopped' >"$evidence_dir/target-after.json"
  jq -e '.Reservations | map(.Instances[]) | length == 0' "$evidence_dir/target-after.json" >/dev/null
  aws configservice describe-config-rules --config-rule-names ec2-imdsv2-check >"$evidence_dir/rule-after.json" 2>"$evidence_dir/rule-after.stderr" || true
  [[ ! -s "$evidence_dir/rule-after.json" ]] || jq -e '(.ConfigRules // []) | length == 0' "$evidence_dir/rule-after.json" >/dev/null
  aws configservice describe-remediation-configurations --config-rule-names ec2-imdsv2-check >"$evidence_dir/remediation-after.json" 2>"$evidence_dir/remediation-after.stderr" || true
  [[ ! -s "$evidence_dir/remediation-after.json" ]] || jq -e '(.RemediationConfigurations // []) | length == 0' "$evidence_dir/remediation-after.json" >/dev/null
  aws configservice describe-configuration-recorders >"$evidence_dir/recorder-after.json"
  aws configservice describe-delivery-channels >"$evidence_dir/delivery-after.json"
  jq -e '[.ConfigurationRecorders[] | select(.name == "seccop-issue55-s3-recorder") | .recordingGroup.resourceTypes] | flatten | index("AWS::S3::Bucket") != null' "$evidence_dir/recorder-after.json" >/dev/null
  recorder_shape='[.ConfigurationRecorders[] | select(.name == "seccop-issue55-s3-recorder") | {name, roleARN, recordingGroup: {allSupported: .recordingGroup.allSupported, includeGlobalResourceTypes: .recordingGroup.includeGlobalResourceTypes, resourceTypes: ((.recordingGroup.resourceTypes // []) | map(select(. != "AWS::EC2::Instance")) | sort)} }]'
  cmp -s <(jq -S "$recorder_shape" "$evidence_dir/recorder-before.json") <(jq -S "$recorder_shape" "$evidence_dir/recorder-after.json") || {
    echo 'Config recorder changed outside the approved EC2 resource type extension' >&2
    exit 1
  }
  cmp -s <(jq -S . "$evidence_dir/delivery-before.json") <(jq -S . "$evidence_dir/delivery-after.json") || { echo 'Delivery channel changed unexpectedly' >&2; exit 1; }
  jq -n '{status:"PASS",health:"EC2_IMDSV2",finding:"NON_COMPLIANT",wrong_proposal:"BLOCKED",cross_source:"BLOCKED",reject:"REJECTED_NO_MUTATION",remediation:"VERIFIED",automation:"SUCCESS",metadata:"HttpTokens=required",compliant:"COMPLIANT",replay:"BLOCKED",cleanup:"VERIFIED",recorder:"S3_PRESERVED_EC2_ADDED",delivery:"UNCHANGED",resources_retained:["CONFIG_RECORDER","CONFIG_DELIVERY","S3","ECR"],old_package_and_cve_path:"EXCLUDED",aws_profile:"amit",region:"ap-southeast-1"}'
  exit 0
fi

profile=${AWS_PROFILE:-amit}
region=${AWS_REGION:-ap-southeast-1}
port=${SECCOP_API_PORT:-18768}
bucket=${SECCOP_S3_BUCKET:?SECCOP_S3_BUCKET must be a private runtime value}
delivery_bucket=${SECCOP_S3_DELIVERY_BUCKET:?SECCOP_S3_DELIVERY_BUCKET must be a private runtime value}
protected_buckets=${SECCOP_S3_PROTECTED_BUCKETS:?SECCOP_S3_PROTECTED_BUCKETS must be private runtime values}
evidence_dir=${SECCOP_S3_EVIDENCE_DIR:?SECCOP_S3_EVIDENCE_DIR must be private}
state=${SECCOP_S3_STATE:?SECCOP_S3_STATE must be private}
mkdir -p "$evidence_dir"; chmod 700 "$evidence_dir"

export AWS_PROFILE="$profile" AWS_DEFAULT_PROFILE="$profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region"
export SECCOP_PROFILE="$profile" SECCOP_REGION="$region" SECCOP_S3_EVIDENCE_DIR="$evidence_dir" SECCOP_S3_STATE="$state"
[[ "$profile" == amit && "$region" == ap-southeast-1 ]] || { echo 'explicit amit/ap-southeast-1 is required' >&2; exit 1; }
aws sts get-caller-identity >"$evidence_dir/e2e-sts.json"
SECCOP_S3_EVIDENCE_DIR="$evidence_dir" SECCOP_S3_STATE="$state" \
  /usr/bin/python3 "$repo_dir/scripts/issue47_s3_compliance.py" setup --profile "$profile" --region "$region" --bucket "$bucket" --delivery-bucket "$delivery_bucket" >"$evidence_dir/setup.json"

export SECCOP_DEMO_BACKEND=AWS SECCOP_S3_COMPLIANCE_E2E=1 SECCOP_S3_BUCKET="$bucket" SECCOP_S3_PROTECTED_BUCKETS="$protected_buckets" POC_PORT="$port"
cd "$repo_dir"
.venv/bin/python -m secure_agent_harness.poc_server >"$evidence_dir/server.log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
for _ in {1..30}; do curl -fsS "http://127.0.0.1:$port/api/health" >"$evidence_dir/health.json" && break || sleep 1; done
jq -e '.review_mode == "S3_COMPLIANCE" and .demo_backend == "AWS"' "$evidence_dir/health.json" >/dev/null

post() { curl --fail-with-body --max-time 500 -sS -X POST "http://127.0.0.1:$port$1" -H 'Content-Type: application/json' --data-binary "$2"; }
post /api/demo/fix '{"source":"s3","confirm":true}' >"$evidence_dir/before-approval.json"
jq -e '.result.status == "BLOCKED"' "$evidence_dir/before-approval.json" >/dev/null
post /api/scan '{"request_text":"Review the S3 exposure risk"}' >"$evidence_dir/scan-non-compliant.json"
jq -e '.result.reason_code == "SECCOP_S3_NON_COMPLIANT" and (.result.proposal_id | startswith("SECCOP_PROPOSAL_"))' "$evidence_dir/scan-non-compliant.json" >/dev/null
proposal_id=$(jq -r '.result.proposal_id' "$evidence_dir/scan-non-compliant.json")
proposal_hash=$(jq -r '.result.proposal_hash' "$evidence_dir/scan-non-compliant.json")
post /api/demo/reject "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"s3",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/reject.json"
jq -e '.result.status == "REJECTED" and .result.mutation_performed == false' "$evidence_dir/reject.json" >/dev/null
post /api/scan '{"request_text":"Review the S3 exposure risk again"}' >"$evidence_dir/scan-before-remediation.json"
proposal_id=$(jq -r '.result.proposal_id' "$evidence_dir/scan-before-remediation.json")
proposal_hash=$(jq -r '.result.proposal_hash' "$evidence_dir/scan-before-remediation.json")
post /api/demo/fix "$(jq -nc --arg id "$proposal_id" '{source:"s3",confirm:true,proposal_id:$id,proposal_hash:"wrong"}')" >"$evidence_dir/wrong-proposal.json"
jq -e '.result.status == "BLOCKED"' "$evidence_dir/wrong-proposal.json" >/dev/null
post /api/demo/fix "$(jq -nc --arg id "$proposal_id" --arg hash "$proposal_hash" '{source:"s3",confirm:true,proposal_id:$id,proposal_hash:$hash}')" >"$evidence_dir/remediate.json"
jq -e '.result.status == "VERIFIED" and .result.state == "COMPLIANT"' "$evidence_dir/remediate.json" >/dev/null
post /api/scan '{"request_text":"Verify protected S3 state"}' >"$evidence_dir/scan-compliant.json"
jq -e '.result.reason_code == "SECCOP_S3_COMPLIANT" and (.result.findings | length) == 0' "$evidence_dir/scan-compliant.json" >/dev/null
post /api/demo/reset '{"confirm":true}' >"$evidence_dir/reset.json"
jq -e '.result.reason_code == "SECCOP_S3_RESET_READY"' "$evidence_dir/reset.json" >/dev/null
post /api/scan '{"request_text":"Reopen the S3 finding"}' >"$evidence_dir/scan-reopened.json"
jq -e '.result.reason_code == "SECCOP_S3_NON_COMPLIANT"' "$evidence_dir/scan-reopened.json" >/dev/null
jq -n '{health:"S3_COMPLIANCE", before_approval:"BLOCKED", reject:"REJECTED_NO_MUTATION", finding:"NON_COMPLIANT", remediation:"VERIFIED", compliant:"COMPLIANT", reset:"READY", reopened:"NON_COMPLIANT", aws_profile:"amit", region:"ap-southeast-1", resources_retained:true, ec2_started:false}'
