# AGENTS.md

This is a public personal-learning repository.

## Scope

- Use synthetic local data first.
- Keep one learning objective per change.
- Prefer small typed Python components and deterministic tests.
- Record useful lessons in `docs/LEARNING_LOG.md`.

## Public safety

- Never add real credentials, tokens, `.env` content, account IDs, ARNs,
  resource IDs, hostnames, IP addresses, DNS names, logs, screenshots, state,
  vulnerabilities, or employer/client material.
- Use aliases such as `ACCOUNT_A`, `EC2_RESOURCE_01`, and `ROLE_READONLY_01`.
- Review every diff for public safety before commit and push.
- Stop when publication safety is uncertain.

## AWS and cost boundary

- Local fixtures and mocks are the default.
- Personal profile `amit` is the only allowed future AWS profile.
- Never run `aws sso login`.
- Do not create or mutate AWS resources without explicit approval for the exact
  experiment and a same-day cleanup plan.

## Validation

- Run focused tests, Python compilation, and `git diff --check`.
- Preserve unsafe requests as regression tests.
- A model proposal is never authorization.
