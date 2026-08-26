#!/usr/bin/env python3
"""Build an executive-readable SecCop presentation from local screenshots.

The source deck is Marp-compatible Markdown. A dependency-free HTML fallback is
also written so the evidence remains reviewable when Marp is unavailable.
"""

from __future__ import annotations

import argparse
import html
import re
import shutil
from pathlib import Path


PHASES = ("2A", "2B", "2C", "3")
_SCREENSHOT_RE = re.compile(
    r"^SecCop-Phase-(2A|2B|2C|3)-(\d{2})\.(png|jpg|jpeg)$",
    re.IGNORECASE,
)


def _copy_screenshots(source_dir: Path, assets_dir: Path) -> dict[str, list[Path]]:
    assets_dir.mkdir(parents=True, exist_ok=True)
    found: dict[str, list[Path]] = {phase: [] for phase in PHASES}
    for source in sorted(source_dir.iterdir() if source_dir.exists() else ()):
        if not source.is_file():
            continue
        match = _SCREENSHOT_RE.fullmatch(source.name)
        if not match:
            continue
        phase, sequence, extension = match.groups()
        normalized = assets_dir / f"phase-{phase.lower()}-{sequence}.{extension.lower()}"
        shutil.copy2(source, normalized)
        found[phase].append(normalized)
    for paths in found.values():
        paths.sort()
    return found


def _marp_image(images: list[Path], index: int = 0) -> str:
    if len(images) <= index:
        return "*Screenshot will be added after this demo step.*"
    return f"![w:1050px](assets/{images[index].name})"


def _write_marp(output_dir: Path, images: dict[str, list[Path]]) -> Path:
    """Write a plain-language Marp source beside the copied captures."""

    phase_2a = images["2A"]
    markdown = f"""---
marp: true
theme: default
paginate: true
size: 16:9
style: |
  section {{ font-family: Arial, sans-serif; color: #17212b; background: #f7faf8; padding: 52px 72px; }}
  h1, h2 {{ color: #123b2b; }}
  h1 {{ font-size: 2.2em; }}
  h2 {{ font-size: 1.65em; }}
  p, li {{ font-size: 1.05em; line-height: 1.35; }}
  strong {{ color: #087443; }}
  .small {{ color: #5d6b64; font-size: .8em; }}
---

# Security Copilot

## DEMO

A simple way to move from a security finding to a safe, reviewable decision.

---

# Why I built this

A security scan can find a weakness. The harder part is deciding what to do next:

- Which server is affected?
- What change is being suggested?
- Has a person reviewed it?
- How do we know the change worked?

---

# The idea in one picture

## Finding -> Compare -> Suggest -> Approve -> Check

Security Copilot puts these steps in one guided conversation so the result is easy to explain and review.

---

# Step 1: Start with evidence

The finding is matched to the selected server. At this point, nothing has been changed.

{_marp_image(phase_2a, 0)}

---

# Step 2: Show the suggested fix

The screen explains the current package, the safer version, and whether a restart may be needed.

{_marp_image(phase_2a, 1)}

---

# Step 3: Keep a person in control

A suggestion does not change the server. A person must review it and choose **Approve** or **Reject**.

{_marp_image(phase_2a, 2)}

---

# What this demo showed

- The finding was connected to the correct server.
- A clear fix was prepared for review.
- Approval was recorded.
- **No server change was made in this demo.**

{_marp_image(phase_2a, 3)}

---

# What comes next

1. **Apply one approved fix** to the server.
2. **Check the result independently** with a new security scan.
3. **Show the outcome clearly:** fixed, waiting for scan results, or not fixed.
4. Add the optional low-cost Luna assistant only when a plain-language explanation is useful.

---

# The key message

## Security Copilot turns a security finding into a guided, reviewable decision - and then proves whether the fix worked.

<div class="small">Current demo status: evidence and approval flow complete; server change intentionally deferred to the next phase.</div>
"""
    source = output_dir / "seccop-executive-demo.md"
    source.write_text(markdown, encoding="utf-8")
    return source


def _write_markview(output_dir: Path, images: dict[str, list[Path]]) -> Path:
    """Write a MarkView-friendly source without Marp-only directives.

    MarkView's reading view can display the Marp source, but its presentation
    view is a separate renderer.  Keep this version deliberately plain: no
    YAML front matter, CSS, or ``w:...`` image sizing syntax.  Each capture is
    on its own short slide so the slideshow has room to display it.
    """

    phase_2a = images["2A"]

    def image(index: int) -> str:
        if len(phase_2a) <= index:
            return "_Screenshot will be added after this demo step._"
        return f"![Security Copilot DEMO step {index + 1}](assets/{phase_2a[index].name})"

    markdown = f"""# Security Copilot

## DEMO

A simple way to move from a security finding to a safe, reviewable decision.

---

# Why I built this

A security scan can find a weakness. The harder part is deciding what to do next:

- Which server is affected?
- What change is being suggested?
- Has a person reviewed it?
- How do we know the change worked?

---

# The idea in one picture

## Finding -> Compare -> Suggest -> Approve -> Check

Security Copilot puts these steps in one guided conversation so the result is easy to explain and review.

---

# Step 1: Start with evidence

The finding is matched to the selected server. At this point, nothing has been changed.

{image(0)}

---

# Step 2: Show the suggested fix

The screen explains the current package, the safer version, and whether a restart may be needed.

{image(1)}

---

# Step 3: Keep a person in control

A suggestion does not change the server. A person must review it and choose **Approve** or **Reject**.

{image(2)}

---

# What this demo showed

- The finding was connected to the correct server.
- A clear fix was prepared for review.
- Approval was recorded.
- **No server change was made in this demo.**

{image(3)}

---

# What comes next

1. **Apply one approved fix** to the server.
2. **Check the result independently** with a new security scan.
3. **Show the outcome clearly:** fixed, waiting for scan results, or not fixed.
4. Add the optional low-cost Luna assistant only when a plain-language explanation is useful.

---

# The key message

## Security Copilot turns a security finding into a guided, reviewable decision - and then proves whether the fix worked.

"""
    source = output_dir / "seccop-markview-demo.md"
    source.write_text(markdown, encoding="utf-8")
    return source


def _write_fallback_html(output_dir: Path, images: dict[str, list[Path]]) -> Path:
    """Keep a dependency-free browser deck when Marp is not available."""

    phase_2a = images["2A"]
    image_html = "".join(
        f'<img src="assets/{html.escape(image.name)}" alt="Security Copilot demo capture {index}">'
        for index, image in enumerate(phase_2a, start=1)
    ) or '<div class="placeholder">Screenshot will be added after the demo checkpoint.</div>'
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Security Copilot - DEMO</title><style>
body{{margin:0;background:#f7faf8;color:#17212b;font:20px Arial,sans-serif}}.deck{{scroll-snap-type:y mandatory}}.slide{{min-height:100vh;box-sizing:border-box;padding:7vh 9vw;scroll-snap-align:start}}.slide:nth-child(even){{background:#eaf3ed}}h1,h2{{color:#123b2b}}h1{{font-size:clamp(3rem,8vw,6rem)}}h2{{font-size:clamp(2rem,5vw,4rem)}}p,li{{line-height:1.4;max-width:58rem}}strong{{color:#087443}}.evidence{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}.evidence img{{width:100%;height:34vh;object-fit:contain;background:#fff;border:1px solid #b9cfc2;border-radius:10px}}.small{{color:#5d6b64;font-size:.8em}}@media(max-width:800px){{.evidence{{grid-template-columns:1fr}}.evidence img{{height:auto;max-height:42vh}}}}
</style></head><body><main class="deck">
<section class="slide"><h1>Security Copilot</h1><h2>DEMO</h2><p>A simple way to move from a security finding to a safe, reviewable decision.</p></section>
<section class="slide"><h2>Why I built this</h2><p>A security scan can find a weakness. The harder part is deciding what to do next.</p><ul><li>Which server is affected?</li><li>What change is being suggested?</li><li>Has a person reviewed it?</li><li>How do we know the change worked?</li></ul></section>
<section class="slide"><h2>The idea in one picture</h2><h2>Finding -&gt; Compare -&gt; Suggest -&gt; Approve -&gt; Check</h2><p>Security Copilot puts these steps in one guided conversation.</p></section>
<section class="slide"><h2>Step 1: Start with evidence</h2><p>The finding is matched to the selected server. Nothing has been changed.</p><div class="evidence">{image_html}</div></section>
<section class="slide"><h2>What comes next</h2><ol><li>Apply one approved fix.</li><li>Check the result independently.</li><li>Show whether it worked.</li><li>Add optional low-cost Luna explanations when useful.</li></ol></section>
<section class="slide"><h2>The key message</h2><h2>Security Copilot turns a security finding into a guided, reviewable decision - and then proves whether the fix worked.</h2><p class="small">Current demo status: evidence and approval flow complete; server change intentionally deferred.</p></section>
</main></body></html>"""
    index = output_dir / "index-fallback.html"
    index.write_text(document, encoding="utf-8")
    return index


def build(source_dir: Path, output_dir: Path) -> tuple[Path, Path, Path]:
    assets_dir = output_dir / "assets"
    images = _copy_screenshots(source_dir, assets_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    source = _write_marp(output_dir, images)
    markview = _write_markview(output_dir, images)
    fallback = _write_fallback_html(output_dir, images)
    return source, markview, fallback


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path("/mnt/c/Users/ISSUser/Pictures/Screenshots"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.home() / ".AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-presentation",
    )
    args = parser.parse_args()
    source, markview, fallback = build(args.source_dir, args.output_dir)
    print(source)
    print(markview)
    print(fallback)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
