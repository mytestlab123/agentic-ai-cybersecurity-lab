# Context

Current objective: review the completed local proof for Issue 1, a synthetic
secure-agent harness.

Current boundary: the injected model is scripted and local; tools are
read-only in-memory lookups; policy is default-deny; no AWS or external API is
used.

Validation: six focused tests and Python compilation pass locally.

Next gate: Amit explains model vs agent vs harness, typed tool contracts,
probabilistic vs deterministic behavior, and fail-closed execution before the
project moves to personal AWS read-only adapters.
