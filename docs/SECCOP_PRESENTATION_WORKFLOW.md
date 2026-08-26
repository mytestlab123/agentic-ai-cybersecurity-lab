# SecCop DEMO presentation workflow

The presentation tells a simple story: why the work matters, what SecCop
shows, what a person approves, and what will happen next. Each phase uses
short sentences and screenshots instead of implementation tables. Screenshots
are local DEMO evidence and must not be committed to this public repository.

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

## Build or refresh the DEMO deck

```bash
uv run python scripts/build_seccop_presentation.py \
  --source-dir /mnt/c/Users/ISSUser/Pictures/Screenshots
```

The script creates a Marp source named `seccop-executive-demo.md`, copies
captures into `assets/`, writes a MarkView source named
`seccop-markview-demo.md`, and writes a simple fallback HTML file. When Marp is
available, render the Markdown source to `index.html`; the current Windows
installation can be called with `cmd.exe /d /c marp`.

For the MarkView Chrome extension, open `seccop-markview-demo.md`. It is a
separate plain-Markdown version: it does not use Marp front matter, CSS, or
Marp image sizing. That keeps the screenshots visible when MarkView switches
from reading view to presentation view.

The output is outside the repository at
`~/.AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-presentation/` or the
Windows review folder. Existing phase captures are retained and new captures
are copied with normalized names.

The slide story is intentionally non-technical:

1. Why I built this.
2. The simple journey from finding to decision.
3. What the screenshots show.
4. What this DEMO proved.
5. What comes next.

## Per-phase handoff

After each phase, Amit runs the three-to-five DEMO steps in that phase's
charter, saves the requested screenshots, and tells Codex `screenshots ready`.
Codex then runs the builder, checks that the expected files exist, and reports
the presentation path. No screenshot is copied into Git or sent to GovTech.
