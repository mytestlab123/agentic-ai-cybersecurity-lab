# Specification

## Current scope

Build a minimal secure Python agent harness with typed contracts and three
deterministic read-only tools backed by synthetic fixtures.

## Required behavior

- The model may only propose tool calls.
- The deterministic policy validates the complete plan before execution.
- Unknown, malformed, or mutation-capable calls block the whole plan.
- Tool results are typed and evidence is returned to the caller.
- Tests cover a normal request and an unsafe mutation request.

## Issue 2 local slice

- A synthetic AWS-shaped instance response is read through an allow-listed
  local tool.
- Deterministic sanitization exposes only an alias, synthetic environment,
  normalized state, and coarse size class.
- Raw instance, network, DNS, tag, and profile values never reach the typed
  result returned to the model boundary.

## Stop gates

- No real LLM or paid API.
- No AWS SDK call or resource.
- No mutation tool.
- No real identifiers or private data.
- Human review is required before widening beyond Issue 1.
