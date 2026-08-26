---
marp: true
theme: default
paginate: true
backgroundColor: '#07111f'
color: '#f4f7fb'
style: |
  section {
    font-family: Arial, Helvetica, sans-serif;
    padding: 54px 64px;
  }
  h1, h2 {
    color: #5eead4;
  }
  strong {
    color: #67e8f9;
  }
  img {
    display: block;
    max-height: 560px;
    margin: 18px auto 0;
  }
  footer {
    color: #94a3b8;
  }
---

# Find. Approve. Verify.

Security Copilot helps a team turn a security finding into a clear, controlled decision.

<!-- The promise is speed with accountability, not autonomous change. -->

---

## Why this matters now

- Security tools find more issues, faster.
- Fast action can also mean the wrong server or the wrong change.
- Leaders need a simple record of what was found, approved, changed, and checked.

**Goal:** make safe action easy to explain.

---

## One simple operating loop

<div style="font-size: 2.2em; text-align: center; margin: 70px 0 35px; color: #67e8f9;">
Find &rarr; Recommend &rarr; Approve &rarr; Act &rarr; Verify
</div>

The person stays in control of the sensitive step. The system checks the result afterwards.

---

## What this POC built

| Capability | Evidence | What it means |
| --- | --- | --- |
| One scan for server, file, and image | `DEMO-PROVEN` | One conversation starts the review. |
| Plain-language recommendation | `DEMO-PROVEN` | The operator sees the problem and the safe next step. |
| Typed, deterministic controls | `TEST-PROVEN` | Bad or unknown requests stop before tools run. |
| Small AWS rehearsal | `TEST-PROVEN` | S3 and ECR replacement paths were exercised and rescanned. |

**Current AWS position:** `READ-ONLY PROVEN` for a disposable old-AMI EC2
target with SSM Online; `TEST-PROVEN` for the small S3/ECR scan, approval,
replacement, and rescan path. The EC2 before/after package demonstration is
`PLANNED`.

GuardDuty, real malware, AgentCore, and new networking remain outside this
KISS POC; the shared VPC and SSM profile are unchanged.

---

## The trust boundary

> AI may investigate and recommend.
>
> Trusted controls decide what is allowed.
>
> A person approves a sensitive change.
>
> The system verifies and records the result.

The current POC uses a deterministic Python path. GovTech inference is not required for this proof.

---

## Proof: one scan, three places to look

![SecCop three-source scan](demo-proof/SecCop-Scan-02.png)

`DEMO-PROVEN` — the visible flow shows a server package, a stored artifact, and a container image as separate findings.

---

## Proof: approval is visible

![SecCop approval gate](demo-proof/SecCop-Scan-03.png)

`DEMO-PROVEN` — the proposed change is shown before approval. Rejecting it keeps the system read-only.

---

## Proof: unsafe paths stop

![SecCop blocked request](demo-proof/SecCop-Scan-05-blocked.png)

`DEMO-PROVEN` — an unknown finding stops with a stable reason code and no tool calls.

---

## Value and one next decision

**Value today**

- Faster review of a finding.
- Smaller, explainable changes.
- A human approval record and a follow-up check.

**Next decision**

Approve one exact package update on the disposable old-AMI server so the DEMO can show:

`old package &rarr; approved fix &rarr; verified clean`

This remains a learning POC, not an enterprise remediation platform.

<!-- Ask for one bounded approval, not approval for autonomous remediation. -->
