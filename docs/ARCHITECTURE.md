# Architecture

## Control boundary

```text
UserRequest
    |
    v
Model.plan()                 untrusted runtime output
    |
    v
AgentPlan.model_validate()   deterministic contract boundary
    |
    +---- invalid ---------> BLOCKED + typed AuditEvent
    |
    v
AgentPlan + ToolCallProposal
    |
    v
Policy.authorize()           deterministic, default deny
    |
    +---- any denial ------> BLOCKED + typed AuditEvent, zero tools execute
    |
    v
ToolRegistry.execute()       allow-listed read-only functions
    |
    v
ToolResult                   typed local evidence
```

The harness validates the entire proposed plan before executing its first
tool. This prevents a plan containing one safe read and one unsafe action from
partially executing.

## Components

- `model.py`: protocol for plan producers and a local scripted implementation.
- `contracts.py`: Pydantic request, plan, policy, and result types.
- `policy.py`: exact tool and argument allow-list; everything else is denied.
- `tools.py`: three in-memory readers over synthetic fixtures.
- `harness.py`: deterministic orchestration and evidence collection.

## Trust model

Model output is untrusted even when it matches the user's words or a Python
type annotation. The harness validates the runtime output as an `AgentPlan`
before policy evaluation. A rejected output produces a typed audit event with
fixed stage, outcome, and reason-code values; it does not copy raw model output
into evidence. Policy and tool code are deterministic. Approval, when
introduced later, cannot grant a capability that the tool registry does not
contain.

Policy decisions contain both a stable reason code for automation and a short
human-readable reason. A denied decision produces an audit event from the
stable code. The event excludes the user prompt, model explanation, and tool
arguments.
