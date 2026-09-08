# SecCop Roadmap

## North star

Deliver a manager-ready Security Copilot that demonstrates one governed flow:

`Find -> Explain -> Recommend -> Approve or Stop -> Act -> Verify`

Codex App Server is the bounded reasoning/explanation brain. Deterministic SecCop code owns source binding, proposal validation and policy. The human authorizes mutation. AWS/provider truth executes and verifies the result.

This roadmap does not authorize AWS/cloud mutation. Live AWS changes still require the applicable explicit approval/gate.

## Completed milestones

- **M1 - Three-source governed Security Copilot**: ECR/Inspector vulnerability, S3 Block Public Access compliance, EC2 IMDSv2 compliance.
- **M2 - Unified operator runtime**: one repo-owned startup command, private fail-fast runtime configuration, one fixed loopback listener.
- **M3 - Shared Codex reasoning brain**: source-bound no-tool BEFORE/question/verified-AFTER reasoning for ECR, S3 and EC2.
- **M4 - Visible controllable Codex lifecycle**: public-safe lifecycle status plus explicit New Chat/session reset.

- **M5 - Live three-source proof**: merged provider-evidence proof for the retained ECR, S3, and EC2 stories, with approval remaining source-bound and human-gated. Evidence: Issue #69 / merged PR #70.
- **M6 - Manager governance timeline**: public-safe five-stage timeline separates provider evidence, recommendation, human decision, deterministic action, and verification. Evidence: Issue #69 / merged PR #70.
- **M7 - Fail-closed recovery and reconciliation**: source timeouts/submission uncertainty stay `PENDING` with `RECONCILE_BEFORE_RETRY`; pending verification does not claim success; New Chat/session reset changes local Codex state only. Evidence: focused API/mock regressions in `tests/test_poc.py`.
- **M8 - Repeatable manager demo and v0.1 readiness**: the manager runbook, architecture/control-boundary diagram, five-minute talk track, and cheap synthetic Playwright golden proof are delivered on PR #72. Evidence: `docs/SECCOP_V01_MANAGER_RUNBOOK.md` and `./scripts/golden-gui-e2e.sh`.

## v0.1 release gate

M1-M8 implementation is complete when the cited evidence passes. The `v0.1`
tag is intentionally **not** created by this roadmap: it requires final
complete-diff review of PR #72, merge of that exact reviewed head, and a
separate explicit human decision. No live AWS mutation is implied by that
release decision.

## After v0.1

Optional experiments such as Open WebUI or a separate AgentGuard project stay out of the active SecCop MVP unless Amit explicitly activates them.

## Working rule

Use the shared ChatGPT-Codex collaboration protocol: one useful milestone, normally 2-3 related improvements, one Issue/PR, proportional validation, and reuse the same Issue/PR for related corrections. File/line counts are review signals, not hard limits.
