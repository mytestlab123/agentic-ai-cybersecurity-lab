# Context

Current objective: Issue 2 local sanitization, one concept at a time.

Issue 1 is complete and merged in PR #4. The current boundary remains local:
the model is scripted, tools are deterministic and read-only, policy is
default-deny, and no AWS or external API is used.

Issue 2 slice: one synthetic AWS-shaped instance response is sanitized into a
typed alias-only result before model visibility. No AWS SDK, credential, live
account, or resource is in scope.

Validation: 8 tests, Python compilation, normal and blocked demos, and
`git diff --check` pass locally.

Next gate: Amit traces the synthetic raw record through the sanitizer and
explains why raw instance, network, DNS, tag, and profile values must not
cross the model boundary before any live read-only adapter is considered.
