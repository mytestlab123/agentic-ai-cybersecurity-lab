---
marp: true
theme: default
paginate: true
backgroundColor: '#f7f9fc'
color: '#132238'
style: |
  section {
    font-family: Arial, Helvetica, sans-serif;
    padding: 54px 64px 120px;
  }
  h1, h2 { color: #0f766e; }
  h1 { font-size: 2.2em; }
  h2 { font-size: 1.65em; }
  strong { color: #0369a1; }
  p, li { line-height: 1.35; }
  .promise { color: #0f766e; font-size: 2.8em; font-weight: 700; text-align: center; margin: 130px 0 30px; }
  .subtitle { text-align: center; font-size: 1.25em; }
  .flow { color: #0369a1; font-size: 1.8em; font-weight: 700; text-align: center; margin: 80px 0 45px; }
  .panels { display: flex; gap: 18px; margin-top: 40px; }
  .panel { flex: 1; padding: 22px; background: #e8f1f7; border-left: 6px solid #0f766e; border-radius: 8px; }
  .panel h3 { margin-top: 0; color: #0f766e; }
  img { display: block; max-width: 86%; max-height: 500px; object-fit: contain; margin: 18px auto 0; }
  .caption { text-align: center; color: #475569; font-size: .82em; margin-top: 10px; }
  code { color: #9a3412; }
---

<div class="promise">Find. Approve. Verify.</div>

<div class="subtitle">Security Copilot turns one security concern into a clear, controlled next step.</div>

<!-- Speaker note: The promise is faster review with accountability. This is an operator aid, not autonomous infrastructure access. -->

---

## Why this matters

Security teams receive findings from many places: scanners, advisories, tickets, and messages.

The difficult part is not only finding a CVE. It is answering quickly:

- Is it present in our environment?
- Which source is affected?
- What should happen next?
- Was anything actually changed?

Without one clear record, investigation and hand-offs become slow and inconsistent.

---

## The gap we are closing

<div class="flow">Finding &rarr; Explain &rarr; Recommend &rarr; Approve &rarr; Verify</div>

The POC shortens the distance between a reported vulnerability and a safe decision.

The operator stays in control of the sensitive step. The system keeps the evidence and checks the result.

---

## The proposed experience

<div class="panels">
<div class="panel"><h3>Paste one CVE</h3><p>Copy a CVE from an email, ticket, or advisory into the chat.</p></div>
<div class="panel"><h3>See the scope</h3><p>SecCop checks the server, stored file, and container image together.</p></div>
<div class="panel"><h3>Choose the next step</h3><p>Review a suggested fix. Any server change needs separate approval.</p></div>
</div>

<p><strong>DEMO-PROVEN:</strong> the current browser flow checks one CVE across all three demo sources.</p>

---

## What this POC now shows

<div class="panels">
<div class="panel"><h3>One-CVE lookup</h3><p><strong>DEMO-PROVEN</strong><br>One pasted CVE returns a result for each source.</p></div>
<div class="panel"><h3>Environment scan</h3><p><strong>DEMO-PROVEN</strong><br>One Scan action shows three source findings.</p></div>
<div class="panel"><h3>Safe stopping points</h3><p><strong>TEST-PROVEN</strong><br>Missing or multiple CVEs stop before review.</p></div>
</div>

<p class="caption">The current POC uses deterministic local evidence. No new AWS service or AI model is required for this proof.</p>

---

## Proof: the scan shows the scope

<strong>DEMO-PROVEN</strong> — one Scan action shows the server package, stored artifact, and container image findings.

<img src="demo-proof/SecCop-Scan-02.png" alt="Security Copilot three-source scan">

<div class="caption">The focused pasted-CVE capture is included in the Windows MarkView copy of this deck.</div>

---

## Proof: approval is a separate step

<strong>DEMO-PROVEN</strong> — the guided example shows a human decision before the mock action is recorded.

<img src="demo-proof/SecCop-Scan-03.png" alt="Security Copilot approval gate">

<div class="caption">The demonstration records a no-op approval. It does not claim that an AWS package changed.</div>

---

## Why the direction is controlled

<div class="panels">
<div class="panel"><h3>Least privilege</h3><p>Sources expose aliases and summaries, not raw cloud identifiers.</p></div>
<div class="panel"><h3>Deterministic checks</h3><p>Typed input and stable reason codes make stop/go decisions repeatable.</p></div>
<div class="panel"><h3>Human accountability</h3><p>A suggestion cannot approve itself or widen its authority.</p></div>
<div class="panel"><h3>Evidence</h3><p>Before, action, and outcome remain visible for review.</p></div>
</div>

<p><strong>TEST-PROVEN:</strong> the browser E2E uses Playwright Core, checks the API and DOM, and confirms no external request or console error.</p>

---

## Value and next decision

### Management value

- Faster first review of a reported CVE.
- Fewer hand-offs between security and operations.
- A simple explanation of what is affected and what happens next.
- A visible approval and verification record.

### Honest boundary

Daily scheduling, real S3/ECR remediation, and production rollout are **PLANNED**, not proven by this POC.

### Next decision

Approve the direction for the next small evaluation: reuse this same CVE review experience for a scheduled daily scan, while keeping human approval for every sensitive change.

<!-- Speaker note: Ask for approval to continue the bounded evaluation, not production authorization. -->
