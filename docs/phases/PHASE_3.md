# SecCop Phase 3 - optional GovTech PlatformAI Luna advisory

## Objective

Add a low-cost, optional hosted-model explanation layer after deterministic
evidence and policy gates are already complete. The model explains evidence to
the human; it does not authorize or execute AWS work.

## GovTech boundary

- Use the approved GovTech PlatformAI External route and the inexpensive Luna
  model only when the user requests an explanation.
- Keep the capability key in `~/.config/gtx/config.env` with mode `600`; never
  place it in the repository, browser, prompt transcript, or logs.
- Send only sanitized aliases, package/version projections, stable reason
  codes, and phase status. Do not send raw AWS payloads or secrets.
- Validate model output with the existing Pydantic contracts before policy or
  any tool dispatch. Model output is never authorization.

## Usage card

Every completed task shows one of these honest states:

```text
GovTech inference: not used
```

or, when Luna is actually called:

```text
GovTech model: gpt-5.6-luna
Input tokens: <response usage>
Output tokens: <response usage>
Total tokens: <response usage>
Credits/cost: provider value or unavailable
```

Exact billing remains portal-authoritative if the API returns `cost: null`.

## Demo steps

1. Complete the deterministic evidence and approval flow first; choose the
   **Explain with GovTech Luna** action only after the result is sanitized.
2. Confirm the prompt contains aliases and reason codes, not raw IDs,
   credentials, or untrusted command text.
3. Review the concise Luna explanation and the usage card; do not treat the
   explanation as an approval.
4. Capture a screenshot of the explanation and token/credit status.
5. Confirm the AWS action buttons remain controlled by the deterministic
   policy and human approval path.

## Acceptance

- No GovTech inference is made by the deterministic live comparison.
- A failed or malformed model response stops before policy and tool dispatch.
- The app never invents a credit balance from token counts.

## Evidence

Save captures as:

```text
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-3-01.png
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-3-02.png
```
