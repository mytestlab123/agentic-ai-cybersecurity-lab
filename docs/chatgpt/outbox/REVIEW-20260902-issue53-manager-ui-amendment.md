# Amit-directed scope amendment — PR #54 manager demo consolidation

Canonical Issue: https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/issues/53

Implementation PR: https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/pull/54

This amendment is explicit user authorization to extend the existing PR #54 scope after the original STRICT v2 contract. It does **not** authorize a replacement Issue/PR or unrelated feature work.

It supersedes the old `no S3/UI work` wording **only** for restoring the already-built S3 operator path and cleaning the existing manager UI. It does not authorize a new S3 feature.

## Priority order

1. Preserve/finish the existing #53 App Server reliability + ECR proof.
2. Restore S3 and ECR so both existing operator paths are selectable from the same running SecCop UI/server.
3. Add hide/show for `Ask SecCop`.
4. Remove legacy sidebar/technical-demo clutter.
5. Run one small S3 regression and one small ECR regression. Stop.

Do not add another AWS service or new architecture.

---

# A. S3 + ECR must coexist in one running SecCop

## Current bug / root cause

Current code makes the source modes mutually exclusive:

- `/api/health` returns one singular `review_mode`;
- when `SECCOP_ECR_OPERATOR_MVP=1`, `_run_real_demo()` takes the ECR branch before S3 is considered;
- the HTML statically marks ECR/S3 tabs disabled and mode setup only enables the selected mode.

Do **not** fix this only by removing `aria-disabled` in the browser. Fix the server routing too.

## Required behavior

One server launch must expose the already-built S3 and ECR demos together:

```text
SecCop running
   |
   +--> S3 tab -> existing S3 posture scan / proposal / Approve Once / Reopen
   |
   +--> ECR tab -> Inspector ECR scan / Codex explanation / proposal / Approve Once / Reopen
```

No restart, env-var edit, separate listener, or page reload into a different backend mode should be required just to move between S3 and ECR.

### Routing contract

Use an explicit bounded source selector owned by SecCop, e.g. conceptually:

```text
source = S3 | ECR
```

The source can come from the approved UI tab/request enum, but it must **not** carry an AWS bucket name, repository URI, ARN, digest, command, profile, or other authority from the browser.

Backend maps the enum to the existing server-owned S3/ECR configuration.

Preferred health shape is capability-oriented rather than one mutually exclusive mode, for example conceptually:

```text
available_sources: [S3, ECR]
default_source: ECR
```

Exact JSON names may follow existing style.

### S3 latency

S3 may be slower. That is acceptable.

While an S3 operation is running:

- disable its action button and show an honest busy state;
- do not hide/remove S3 because it is slow;
- prevent unsafe cross-source approval/session mixing while a mutation-sensitive operation is in flight;
- after completion, both S3 and ECR remain selectable.

Concurrent AWS mutations are **not** required. Sequential switching in one server session is enough.

### Approval isolation

S3 approval state must never authorize ECR, and ECR proposal/approval/thread state must never authorize S3.

Keep source-specific proposal/state boundaries and fail closed if the user switches source with an outstanding mutation-sensitive approval.

### EC2 regression

Do not build new EC2 work in this amendment. Preserve the existing EC2 path/regression if it is still present; do not delete it merely to make S3/ECR coexist.

---

# B. Ask SecCop — hide / show

Add one small UI control:

```text
[ Hide Ask SecCop ]
```

When collapsed:

```text
[ Show Ask SecCop ]
```

Requirements:

- collapse/expand only; no backend restart;
- do not destroy an active Codex thread merely because the composer is hidden;
- hiding the composer must not alter approval state;
- ECR can default to Ask SecCop visible;
- S3 may default to hidden/optional if it does not use the Codex conversation path;
- keep the control visually small and manager-friendly.

No new chat framework or persistence layer.

---

# C. Remove legacy left-sidebar clutter

For the manager-facing demo, remove the current full left sidebar and move the small useful controls into a compact top/upper toolbar.

Keep only what the operator needs for the demo:

```text
Security Copilot / current review title
EC2 | S3 | ECR source selector
Scan / Reopen action for selected source
Ask SecCop show/hide control
```

Exact placement may follow the existing visual language, but the main review canvas should get the space currently consumed by the 260px sidebar.

Remove from the manager UI (not merely collapse under another details panel):

- `New investigation` if it has no real behavior;
- `WORKSPACE / SECCOP POC` sidebar block;
- `Technical evidence fallback`;
- `Upload read-only evidence`;
- `OPTIONAL LIVE AWS`;
- advisory-file input;
- AWS region selector;
- `Check live server` legacy panel;
- `Technical Inspector CSV path`;
- Inspector CSV upload;
- EC2 instance ID input;
- CVE/package CSV fields;
- `Compare Inspector CSV`;
- `AI USAGE` panel;
- `GovTech inference: not used` text;
- billing/model-credit explanatory text;
- bottom sidebar backend-note text such as `Live AWS ECR review - Human approval required`.

This is a manager demo, so those technical/debug controls should not compete with the main story.

Do **not** delete useful backend APIs solely because their old UI controls are removed unless they are clearly dead code and removal is tiny/safe. UI cleanup is the objective, not a backend purge.

---

# D. Acceptance proof for this amendment

Do not claim this amendment complete from static HTML tests alone.

Minimum proof:

1. Start one SecCop server once.
2. Confirm S3 and ECR are both presented as available.
3. Select S3 -> run one existing read/scan journey -> get truthful S3 result.
4. Switch to ECR without server restart -> run one Inspector ECR scan -> get truthful ECR result.
5. Switch back to S3 -> source still works.
6. Confirm S3 approval state cannot trigger ECR and vice versa.
7. Hide Ask SecCop -> composer disappears and layout expands/cleans correctly.
8. Show Ask SecCop -> composer returns without losing existing page state; if an ECR Codex thread is active, hiding/showing does not silently replace it.
9. Confirm all listed legacy sidebar sections are absent from manager UI.
10. Existing ECR #53 App Server/approval/verification acceptance remains intact.
11. Existing relevant S3 safety/approval regression remains intact.

No Playwright expansion is required if the existing browser/manual proof mechanism can demonstrate these points cheaply. Do not add a new testing framework just for this amendment.

---

# Stop condition

Stop after this manager demo can do:

```text
one SecCop server
  -> S3 works
  -> switch
  -> ECR works
  -> switch back
  -> S3 still works

Ask SecCop: show / hide

legacy technical sidebar: gone
```

while the original #53 ECR + Codex + approval security contract remains true.

Do not add new AWS resources, a new S3 feature, new EC2 feature, AgentCore, Agents SDK, MCP expansion, database, RAG, multi-agent work, or another UI framework.