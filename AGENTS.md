# AGENTS.md

This is a public personal-learning repository.

## Scope

- Use synthetic local data first.
- Keep one learning objective per change.
- Prefer small typed Python components and deterministic tests.
- Record useful lessons in `docs/LEARNING_LOG.md`.

## KISS POC boundary

- Follow KISS: **Keep It Short and Stupid**. This is a short, demonstrable
  POC, not an enterprise platform.
- Prefer one clear operator journey, small fixtures, and the existing approval
  path over new services, abstractions, or infrastructure.
- Make only the EC2 path real when the issue explicitly requires mutation;
  keep other sources read-only until a separate bounded issue proves the need.
- The approved three-source DEMO may use small, tagged S3/ECR baseline artifacts
  with deterministic scanners. GuardDuty, real malware, AgentCore, and new
  networking are not DEMO requirements.
- Defer AgentCore, multi-agent orchestration, broad IAM, networking, and
  integrations unless a small POC cannot work without them.

## Public safety

- Never add real credentials, tokens, `.env` content, account IDs, ARNs,
  resource IDs, hostnames, IP addresses, DNS names, logs, screenshots, state,
  vulnerabilities, or employer/client material.
- Use aliases such as `ACCOUNT_A`, `EC2_RESOURCE_01`, and `ROLE_READONLY_01`.
- Review every diff for public safety before commit and push.
- Stop when publication safety is uncertain.

## AWS and cost boundary

- Local fixtures and mocks are the default.
- Personal profile `amit` remains the default for future AWS work. The
  explicitly approved Project1 SecCop DEMO uses the existing local `vagent`
  profile only for its tagged Singapore resources.
- Never run `aws sso login`.
- Do not create or mutate AWS resources without explicit approval for the exact
  experiment and a same-day cleanup plan.

## Validation

- Run focused tests, Python compilation, and `git diff --check`.
- Preserve unsafe requests as regression tests.
- A model proposal is never authorization.
