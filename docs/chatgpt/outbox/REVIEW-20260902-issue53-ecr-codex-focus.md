# ChatGPT STRICT / FOCUS contract — Issue #53

Canonical Issue: https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/issues/53

Collaboration protocol: https://gist.github.com/amitkarpe/c8d29ad89cafe3ba178fcae29de3c238

Implementation branch:

```text
chatgpt/issue53-ecr-codex-focus
```

This file is the anti-drift contract for the implementation PR. The Issue defines **what** must be proven. This PR/branch defines **where Codex must implement it**. Do not create a replacement implementation branch or a second overlapping PR unless Amit explicitly asks.

## One outcome only

Prove exactly one repeatable SecCop operator journey:

```text
real vulnerable ECR image
  -> ECR Enhanced Scanning / Amazon Inspector produces one real finding
  -> current SecCop GUI sends sanitized real BEFORE evidence to one real Codex App Server thread
  -> Codex explains the finding and recommends the existing bounded ECR clean-image action
  -> existing SecCop proposal says APPROVAL REQUIRED
  -> Reject proves zero mutation
  -> fresh proposal + Approve Once
  -> existing bounded ECR promotion/rebuild path runs
  -> fresh AWS-native ECR/Inspector after-state is read
  -> the SAME Codex thread receives sanitized AFTER evidence
  -> Codex explains VERIFIED / PENDING_RESCAN / FAILED truthfully
```

Nothing else is the objective of this PR.

## Non-negotiable architecture

```text
SecCop GUI
    |
    v
existing SecCop Python backend
    |
    +--> narrow real ECR / Inspector evidence adapter
    |        |
    |        +--> sanitized aliases/facts only
    |                  |
    |                  v
    +------------> Codex App Server
    |                  |
    |                  +--> same thread for BEFORE + AFTER
    |
    v
existing exact proposal / deterministic policy
    |
    v
Approve Once / Reject
    |
    v
existing bounded ECR mutation path
    |
    v
fresh AWS-native verification
```

### Authority rule

- **Codex App Server** = reasoning/conversation layer.
- **Amazon ECR Enhanced Scanning / Amazon Inspector** = AWS-native vulnerability evidence source for this milestone.
- **SecCop deterministic proposal + approval + executor** = only mutation authority.

Do not route the ECR write through generic Codex shell, generic AWS MCP, `run_script`, unrestricted AWS CLI, or a new agent framework.

## Critical corrections that MUST survive implementation

1. **PR #52 is not AWS-native scanning proof.** It uses AWS ECR for storage and local Trivy for scanning. Trivy may remain optional secondary evidence, but #53 is not complete until an AWS-native ECR Enhanced Scanning / Inspector finding is proven.

2. **PR #46 is not end-to-end Codex agent proof.** It proves real Codex App Server connectivity plus a knowledge-only AWS MCP lane. Do not present deterministic/server-composed explanation text as if Codex generated it.

3. **AWS MCP is optional for #53.** The previous `--read-only` runtime exposed documentation/skill tools but no useful Inspector/EC2/SSM account-resource reads. Do not make direct AWS MCP reads a blocker and do not credit AWS MCP with the finding unless a real run proves that exact path.

4. **Do not claim Agent Toolkit runtime integration unless actually installed and exercised.** No marketing-by-label.

## STRICT execution order

### Gate 0 — prove scanner truth before GUI/product wiring

Before hard-coding a CVE or changing the GUI around a scanner result, privately prove in the approved personal/test AWS account that:

- the bounded ECR repository/config is covered by Enhanced Scanning;
- Amazon Inspector actually reports one reproducible package CVE for the vulnerable image;
- the clean image does not report that same CVE, or the after-state is truthfully `PENDING_RESCAN`;
- expected scan latency is practical for the demo;
- exact read APIs and any scanner-configuration mutation are known;
- cost and cleanup/restore implications are known.

Start by testing the current urllib3 / `CVE-2019-11324` image only if Inspector Enhanced Scanning actually detects it. **Do not hard-code the UI/tests around that CVE before real proof.** If it is not reproducible, choose one similarly small deterministic package CVE that Inspector reliably detects and record why.

If no practical AWS-native finding can be produced, **STOP** and comment the blocker on #53 and this PR. Do not silently fall back to Trivy and call the milestone complete.

### Gate 1 — map one real AWS-native finding

Add only the narrow adapter needed to map one real ECR/Inspector finding into the existing SecCop finding contract.

Public-safe fields only:

```text
resource_alias
storage_provider = AWS_ECR
scanner_provider = AMAZON_INSPECTOR / ECR_ENHANCED_SCANNING
cve_id
package_name
installed/vulnerable version when available
severity
fixed/clean state when available
```

No account IDs, ARNs, repository URIs, raw image digests, raw Inspector payloads, auth/session tokens, private filesystem paths, or private logs may reach the browser or Git.

### Gate 2 — feed REAL BEFORE evidence to the existing Codex thread

Reuse the App Server bridge from PRs #45/#46. Do not build another agent loop.

The actual Codex turn must receive the sanitized real AWS facts and generate the explanation/recommendation. Remove/avoid any fixed server-generated sentence that could be mistaken for a Codex answer.

The browser should show only sanitized response text and safe state/tool metadata.

### Gate 3 — preserve SecCop approval authority

Reuse the current ECR proposal and mutation path from PR #52.

Required proof:

```text
Reject -> zero ECR mutation
Approve Once -> exact bounded ECR action
wrong/replayed/drifted approval -> denied by existing authority
```

Do not widen the write surface just because Codex is now present.

### Gate 4 — AWS-native after-state + same Codex thread

After the approved action:

- obtain a fresh ECR Enhanced Scanning / Inspector result;
- determine the exact target CVE state;
- return only `VERIFIED`, `PENDING_RESCAN`, or `FAILED`;
- send sanitized AFTER facts to the **same Codex thread**;
- show Codex's after-state explanation in the current GUI.

`VERIFIED` requires AWS-native evidence that the target CVE is absent from the current/promoted image. Local Trivy alone cannot satisfy #53 verification.

## Expected implementation files

Prefer modifying only existing paths already used by #52/#46:

```text
scripts/seccop_demo.py
src/secure_agent_harness/poc_server.py
web/poc_chat.html
tests/test_poc.py
```

A small documentation/config file may be added only if required for truthful ECR Enhanced Scanning setup. File/line counts are warning signals, not rigid limits, but unrelated files are a drift signal.

## Do NOT build in this PR

- AgentGuard work;
- another S3 feature;
- new EC2 lab;
- OpenAI Agents SDK;
- AgentCore or Strands migration;
- Open WebUI/LibreChat replacement;
- custom generic MCP gateway/server;
- direct generic AWS MCP write path;
- unrestricted shell/AWS CLI agent authority;
- RAG/vector DB;
- persistent memory/database;
- multi-agent orchestration;
- second CVE/demo journey;
- production/enterprise platform architecture.

## Hard AWS mutation gate

This PR is allowed to contain implementation code, but a **real AWS scanner/configuration mutation or ECR mutation still requires Amit's explicit approval** under the project protocol.

Before any new scanner/configuration mutation, Codex must present:

1. profile/account alias and Region;
2. exact ECR/Inspector configuration change;
3. whether the change is registry-wide or filter-scoped;
4. exact APIs/commands;
5. expected cost and scan latency;
6. cleanup/restore plan;
7. the candidate CVE and evidence that Inspector actually reports it.

Do not widen IAM to bypass a blocker without separate approval.

## Minimum validation — no test proliferation

Use the smallest meaningful validation:

1. fake Inspector ECR finding -> existing SecCop finding contract;
2. fake clean after-state -> `VERIFIED`;
3. pending scanner refresh -> `PENDING_RESCAN`;
4. Reject -> zero mutation;
5. wrong/replayed approval -> denied using existing controls;
6. fake App Server transport proves BEFORE and AFTER messages use the same thread;
7. unexpected Codex command/filesystem/tool events remain fail-closed;
8. existing relevant EC2/S3/ECR regressions;
9. existing public-safety/build/diff checks.

Then run **one real browser/AWS rehearsal** only after the required approval gates.

## PR completion checklist

Do not mark this PR ready/mergeable until all are true:

- [ ] real ECR Enhanced Scanning / Inspector finding proven;
- [ ] scanner/storage labels are truthful;
- [ ] same real Codex App Server thread receives real sanitized BEFORE evidence;
- [ ] Codex—not a fixed backend sentence—explains/recommends from those facts;
- [ ] Reject proves zero mutation;
- [ ] Approve Once uses only the existing bounded SecCop ECR write path;
- [ ] fresh AWS-native after-state is obtained;
- [ ] same Codex thread receives AFTER evidence;
- [ ] final state is truthful `VERIFIED`, `PENDING_RESCAN`, or `FAILED`;
- [ ] no private AWS/Codex data exposed publicly;
- [ ] no unrelated architecture or feature work added;
- [ ] Amit performs/accepts the visible demo before merge.

## Terminal stop condition

Stop when exactly this is repeatable:

```text
real vulnerable ECR image
+ real Amazon Inspector/ECR Enhanced finding
+ same Codex App Server thread gets sanitized BEFORE
+ Codex explains/recommends
+ exact SecCop proposal
+ human Approve Once
+ existing bounded ECR action
+ fresh AWS-native AFTER
+ same Codex thread explains AFTER
+ VERIFIED / truthful PENDING_RESCAN
```

If any required proof cannot be achieved, leave the PR draft/open and document the blocker. Do not reinterpret the objective to obtain a green checkmark.
