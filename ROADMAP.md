# SecCop Roadmap

## North star

Deliver a manager-ready Security Copilot that demonstrates one governed flow:

`Find -> Explain -> Recommend -> Approve or Stop -> Act -> Verify`

Codex App Server is the bounded reasoning/explanation brain. Deterministic SecCop code owns source binding, proposal validation and policy. The human authorizes mutation. AWS/provider truth executes and verifies the result.

This roadmap does not authorize AWS/cloud mutation. Live AWS changes still require the applicable explicit approval/gate.

## Completed foundation

- **M1 - Three-source governed Security Copilot**: ECR/Inspector vulnerability, S3 Block Public Access compliance, EC2 IMDSv2 compliance.
- **M2 - Unified operator runtime**: one repo-owned startup command, private fail-fast runtime configuration, one fixed loopback listener.
- **M3 - Shared Codex reasoning brain**: source-bound no-tool BEFORE/question/verified-AFTER reasoning for ECR, S3 and EC2.
- **M4 - Visible controllable Codex lifecycle**: public-safe lifecycle status plus explicit New Chat/session reset.

## Remaining implementation: two PRs

### PR A - M5 + M6: live proof + manager governance

Goal: one manager-ready live SecCop journey across all three existing stories.

1. Prove ECR, S3 and EC2 through the same unified operator path with real provider evidence and real bounded Codex App Server reasoning.
2. Prove the existing human-approved remediation path for each current story reaches deterministic/provider verification without widening authority.
3. Show a compact manager-readable governance timeline: **Before -> Recommendation -> Human decision -> Action -> After**, using public-safe aliases and status only.

Owning work: Issue #69.

### PR B - M7 + M8: resilience + v0.1 release

Goal: make the demo repeatable, recoverable and releasable.

1. Handle only the highest-value failure/reconciliation cases: App Server/provider timeout or unknown submission state, verification-pending/eventual consistency, and restart/session-loss with a clear next action.
2. Produce the short operator runbook, architecture diagram and five-minute manager talk track; document startup/reset/cleanup.
3. Run the final public-safety/release check and prepare/tag `v0.1` only when the live demo is repeatable.

## After v0.1

Optional experiments such as Open WebUI or a separate AgentGuard project stay out of the active SecCop MVP unless Amit explicitly activates them.

## Working rule

Use the shared ChatGPT-Codex collaboration protocol: one useful milestone, normally 2-3 related improvements, one Issue/PR, proportional validation, and reuse the same Issue/PR for related corrections. File/line counts are review signals, not hard limits.
