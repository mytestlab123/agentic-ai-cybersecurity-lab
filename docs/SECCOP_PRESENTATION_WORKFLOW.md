# SecCop screenshot-to-presentation workflow

The presentation is evidence-first: one short slide per phase, one or two
screenshots, and a plain-language explanation of intent, safety gate, and
result. Screenshots are local manager-demo evidence and must not be committed
to this public repository.

## Naming contract

Use the Windows folder:

```text
C:\Users\ISSUser\Pictures\Screenshots
```

Save each capture with the phase prefix and a two-digit sequence:

```text
SecCop-Phase-2A-01.png
SecCop-Phase-2A-02.png
SecCop-Phase-2B-01.png
```

The script accepts the WSL equivalent `/mnt/c/Users/ISSUser/Pictures/Screenshots`.

## Build or refresh the offline deck

```bash
uv run python scripts/build_seccop_presentation.py \
  --source-dir /mnt/c/Users/ISSUser/Pictures/Screenshots
```

The default output is outside the repository at
`~/.AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-presentation/`. Open the
generated `index.html` in a browser. Existing phase captures are retained and
new captures are copied into `assets/` with normalized names.

## Per-phase handoff

After each phase, Amit runs the three-to-five demo steps in that phase's
charter, saves the requested screenshots, and tells Codex `screenshots ready`.
Codex then runs the builder, checks that the expected files exist, and reports
the presentation path. No screenshot is copied into Git or sent to GovTech.
