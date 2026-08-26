# SecCop ChatGPT communication protocol

This folder is the durable handoff between the local Codex agents and the
external ChatGPT reviewer. ChatGPT cannot read the local Linux filesystem, so
every request must be committed to this public repository before Amit asks
ChatGPT to review it.

## Source of truth

Use the three channels for different purposes:

1. **Inbox Markdown** is the review request and context packet.
2. **Outbox Markdown** is ChatGPT's written review and proposed next work.
3. **GitHub Issue/PR** is the authoritative work record and implementation
   review. Code is not considered complete because a model suggested it.

The repository is public. Packets must contain aliases and design context only.
Never include credentials, API keys, account IDs, ARNs, EC2 instance IDs,
hostnames, IP addresses, raw AWS payloads, private logs, or client material.

## Packet workflow

### Codex -> ChatGPT

Codex creates a dated request under:

```text
docs/chatgpt/inbox/REQUEST-YYYYMMDD-<topic>.md
```

Codex commits and pushes that file to a branch and merges it into `main` (or
provides the GitHub branch URL while the PR is under review). Amit then asks
ChatGPT to read the exact GitHub file URL. Do not ask ChatGPT to read a local
path; it cannot access this filesystem.

### ChatGPT -> Codex

ChatGPT writes its review under:

```text
docs/chatgpt/outbox/REVIEW-YYYYMMDD-<topic>.md
```

ChatGPT may also create one bounded GitHub Issue and one implementation PR.
The response must link those records and must not mix unrelated work into the
same issue.

### Codex acceptance

Codex reads the response from GitHub, checks the repository and live truth,
reviews the proposed diff, runs the smallest meaningful existing validation,
and waits for Amit's `go` before implementation or AWS mutation. The model
proposal is never authorization.

## Required review response

Every outbox review should include:

- recommendation and rejected alternatives;
- one issue title and bounded scope;
- one PR title and expected files;
- operator journey and visible states;
- contracts and stable reason codes;
- safety/no-go gates and AWS cost risks;
- acceptance criteria and a short demo script;
- what is explicitly deferred;
- model selected and any usage information visible in the ChatGPT UI.

## Model and credit rule

Use Instant for a smoke check and Thinking for normal design review. Use Pro or
extra-high reasoning only when Amit explicitly asks for a high-value review.
Local token counters, routing labels, or a model response do not prove portal
billing or remaining credits. Never place a ChatGPT API key in this folder.

## SecCop boundary

The current canonical project is:

```text
https://github.com/mytestlab123/agentic-ai-cybersecurity-lab
```

The existing SecCop flow is the baseline. AgentGuard remains paused until the
SecCop demo is complete. ChatGPT may plan or review AWS work, but deterministic
contracts, policy, exact-target checks, human approval, and repo validation
remain authoritative.
