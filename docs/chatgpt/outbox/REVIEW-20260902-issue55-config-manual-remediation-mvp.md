# ChatGPT STRICT / FOCUS contract — Issue #55

Canonical Issue:

https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/issues/55

Implementation branch:

```text
chatgpt/config-manual-remediation-mvp
```

This milestone is intentionally small. Reuse the merged PR #54 ECR journey and add only two AWS Config compliance journeys.

## Final MVP

```text
SECURITY COPILOT

VULNERABILITY
  ECR Image CVE
  Amazon Inspector

COMPLIANCE
  S3 Public Access
  AWS S3 Operational Best Practices Conformance Pack

  EC2 IMDSv2
  AWS EC2 Operational Best Practices Conformance Pack
```

No fourth example.

---

# Reuse-first requirements

## Existing ECR journey

Reuse the merged #54 implementation. Do not redesign its Inspector/Codex/approval/promotion authority model.

## S3 compliance

Official baseline:

- https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-amazon-s3.html
- https://github.com/awslabs/aws-config-rules/blob/master/aws-config-conformance-packs/Operational-Best-Practices-for-Amazon-S3.yaml

Use:

```text
ConfigRuleName: s3-bucket-level-public-access-prohibited
SourceIdentifier: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED
```

Reuse AWS-managed remediation document:

```text
AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock
```

## EC2 compliance

Official baseline:

- https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-EC2.html
- https://github.com/awslabs/aws-config-rules/blob/master/aws-config-conformance-packs/Operational-Best-Practices-for-EC2.yaml

Use:

```text
ConfigRuleName: ec2-imdsv2-check
SourceIdentifier: EC2_IMDSV2_CHECK
```

Reuse AWS-managed remediation document:

```text
AWSConfigRemediation-EnforceEC2InstanceIMDSv2
```

Do not create a custom Conformance Pack or custom SSM Automation document.

---

# Manual remediation is mandatory for this MVP

Reference:

- https://docs.aws.amazon.com/config/latest/developerguide/setup-manualremediation.html
- https://docs.aws.amazon.com/config/latest/developerguide/setup-autoremediation.html

The product value is the human control point:

```text
AWS Config NON_COMPLIANT
       ↓
SecCop presents finding
       ↓
Codex may explain/recommend
       ↓
server-owned exact proposal
       ↓
[ Remediate ] [ Reject ]
       ↓
Ops clicks Remediate
       ↓
AWS Config StartRemediationExecution
       ↓
AWS-managed SSM Automation
       ↓
fresh verification
       ↓
COMPLIANT / FAILED / PENDING
```

Do not enable AWS Config automatic remediation.

`Remediate` is the preferred GUI label. `Reject` must perform zero mutation.

---

# Authority boundary

- Codex = explanation/recommendation only.
- AWS Config = compliance truth.
- AWS-managed SSM Automation = deterministic remediation implementation.
- SecCop backend = exact target/rule/document/proposal binding.
- Ops click = human authorization.

The browser and Codex must not be able to supply arbitrary:

- bucket name or instance ID;
- ARN/account ID/profile/Region;
- Config rule name;
- SSM document name;
- Automation parameters;
- AWS command/API;
- remediation target.

Reject, wrong target/action/rule/document, replay, stale/drifted pre-state, or missing proposal must fail closed.

---

# AWS gate before implementation rehearsal

Before any new real Config/SSM mutation, Codex must post on the Draft PR:

1. sanitized profile/account alias + Region;
2. current AWS Config recorder/delivery status;
3. whether the official S3/EC2 Conformance Packs already exist;
4. exact reusable lab resources, aliases only;
5. exact Config rule names/source identifiers;
6. exact AWS-managed Automation document names;
7. required service role/IAM permissions;
8. expected latency and meaningful cost drivers;
9. exact setup/reset/cleanup plan;
10. exact APIs/commands proposed.

Then wait for Amit's explicit `go` before any real AWS mutation.

---

# Minimum meaningful implementation

## S3

```text
S3 Public Access tile
 -> Config NON_COMPLIANT
 -> show alias + official rule/baseline
 -> Remediate / Reject
 -> manual StartRemediationExecution
 -> AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock
 -> verify all four bucket-level BPA controls
 -> fresh compliance/resource verification
 -> COMPLIANT
```

Reuse existing safe S3 demo resources/path where practical.

## EC2

```text
EC2 IMDSv2 tile
 -> Config NON_COMPLIANT
 -> show alias + official rule/baseline
 -> Remediate / Reject
 -> manual StartRemediationExecution
 -> AWSConfigRemediation-EnforceEC2InstanceIMDSv2
 -> verify HttpTokens=required
 -> fresh compliance/resource verification
 -> COMPLIANT
```

One server-owned disposable/test EC2 target only. No EC2 CVE/package patching in this milestone.

---

# Acceptance proof

- existing ECR/Inspector journey from #54 still works;
- S3 finding is sourced from the official AWS Config S3 pack/rule;
- EC2 finding is sourced from the official AWS Config EC2 pack/rule;
- both compliance paths show NON_COMPLIANT before remediation;
- Reject performs zero mutation;
- Remediate starts only the proposal-bound AWS-managed Automation document for that source;
- S3 ends with independently verified Block Public Access controls and truthful compliance state;
- EC2 ends with independently verified `HttpTokens=required` and truthful compliance state;
- cross-source authorization is impossible;
- browser/Git remain alias-only and sanitized;
- no automatic remediation is enabled;
- existing relevant ECR/S3/EC2 safety regressions remain green;
- Amit accepts the visible three-example manager demo.

---

# DO NOT build

- custom Conformance Pack;
- custom SSM Automation document;
- Config auto remediation;
- S3 HTTPS-only;
- S3 versioning;
- EC2 CVE scanning/remediation;
- additional Config controls;
- generic remediation framework;
- AWS MCP/Agent Toolkit expansion;
- Agents SDK/AgentCore/Strands migration;
- RAG/database/memory/multi-agent architecture;
- production redesign.

---

# Terminal stop condition

Stop when exactly these three examples are demonstrable in the existing Security Copilot UI:

```text
ECR Image CVE
 -> Amazon Inspector
 -> existing governed remediation

S3 Public Access
 -> official AWS Config S3 baseline
 -> NON_COMPLIANT
 -> Ops Remediate
 -> AWS-managed Automation
 -> COMPLIANT

EC2 IMDSv2
 -> official AWS Config EC2 baseline
 -> NON_COMPLIANT
 -> Ops Remediate
 -> AWS-managed Automation
 -> COMPLIANT
```

Nothing else is needed for Issue #55.