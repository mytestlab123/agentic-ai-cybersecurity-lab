#!/usr/bin/env python3
"""Build a small offline SecCop presentation from Windows screenshots.

The generated deck is deliberately HTML so it has no third-party dependency,
keeps screenshots outside the public repository, and remains easy to review
with a browser.
"""

from __future__ import annotations

import argparse
import html
import re
import shutil
from pathlib import Path


PHASES = ("2A", "2B", "2C", "3")
_SCREENSHOT_RE = re.compile(r"^SecCop-Phase-(2A|2B|2C|3)-(\d{2})\.(png|jpg|jpeg)$", re.IGNORECASE)


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


def _slide(phase: str, title: str, intent: str, gate: str, result: str, images: list[Path], assets_dir: Path) -> str:
    image_html = "".join(
        f'<img src="assets/{html.escape(image.name)}" alt="SecCop Phase {phase} evidence {index}">' 
        for index, image in enumerate(images, start=1)
    ) or '<div class="placeholder">Screenshot will be added after the demo checkpoint.</div>'
    return f"""<section class="slide" id="phase-{phase.lower()}">
  <div class="kicker">SECURITY COPILOT · PHASE {html.escape(phase)}</div>
  <h2>{html.escape(title)}</h2>
  <div class="columns">
    <div class="copy">
      <h3>Intent</h3><p>{html.escape(intent)}</p>
      <h3>Safety gate</h3><p>{html.escape(gate)}</p>
      <h3>Result</h3><p>{html.escape(result)}</p>
    </div>
    <div class="evidence">{image_html}</div>
  </div>
</section>"""


def build(source_dir: Path, output_dir: Path) -> Path:
    assets_dir = output_dir / "assets"
    images = _copy_screenshots(source_dir, assets_dir)
    slides = [
        '<section class="slide title"><div class="kicker">SECURITY COPILOT · MANAGER DEMO</div><h1>Inspector to SSM</h1><p>Evidence-first vulnerability triage with a human approval gate.</p><p class="muted">Screenshots are local demo evidence. AWS mutation remains separately gated.</p></section>',
        _slide("2A", "Deterministic proposal and approval", "Compare one Inspector finding with one exact live EC2 target, then explain the proposed package change in plain language.", "Typed CSV, exact-target AWS reads, and explicit human approval. No SSM mutation.", "A proposal is recorded as approved or rejected with mutation_performed=false.", images["2A"], assets_dir),
        _slide("2B", "Allow-listed SSM remediation", "Apply one approved package change through a named SSM operation.", "Exact target, package scope, no arbitrary model shell, and an explicit reboot decision.", "The command result is evidence, not yet proof that Inspector is resolved.", images["2B"], assets_dir),
        _slide("2C", "Validation and closure", "Compare before-and-after patch state and obtain a fresh Inspector result.", "Require post-checks and distinguish VERIFIED, PENDING_RESCAN, and FAILED.", "The demo closes only when the selected finding is independently verified.", images["2C"], assets_dir),
        _slide("3", "Optional GovTech Luna advisory", "Use a low-cost hosted model to summarize sanitized evidence for a human.", "The API key authorizes inference only; model output is untrusted and cannot authorize AWS.", "Show token usage when inference occurs; exact billing remains portal-authoritative.", images["3"], assets_dir),
    ]
    output_dir.mkdir(parents=True, exist_ok=True)
    document = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Security Copilot presentation</title><style>
body{margin:0;background:#111;color:#eee;font:18px Arial,sans-serif}.deck{scroll-snap-type:y mandatory}.slide{min-height:100vh;box-sizing:border-box;padding:7vh 8vw;scroll-snap-align:start;background:linear-gradient(135deg,#17212b,#111)}.slide:nth-child(odd){background:linear-gradient(135deg,#1d2620,#111)}.title{display:flex;flex-direction:column;justify-content:center}.kicker{color:#55d69d;letter-spacing:.14em;font-size:.72rem;font-weight:700}.slide h1{font-size:clamp(3rem,8vw,6rem);margin:.35em 0 .15em}.slide h2{font-size:clamp(2rem,5vw,4rem);margin:.3em 0 .8em}.slide h3{color:#9bc5ff;font-size:1rem;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.35em}.slide p{line-height:1.5;max-width:48rem}.muted{color:#999}.columns{display:grid;grid-template-columns:minmax(260px,.8fr) minmax(320px,1.2fr);gap:5vw;align-items:start}.evidence{display:grid;gap:14px}.evidence img{width:100%;max-height:70vh;object-fit:contain;background:#222;border:1px solid #555;border-radius:10px}.placeholder{padding:5rem 2rem;text-align:center;color:#777;border:1px dashed #555;border-radius:10px}@media(max-width:800px){.columns{grid-template-columns:1fr}.slide{padding:5vh 6vw}}
</style></head><body><main class="deck">""" + "".join(slides) + "</main></body></html>"
    index = output_dir / "index.html"
    index.write_text(document, encoding="utf-8")
    return index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=Path("/mnt/c/Users/ISSUser/Pictures/Screenshots"))
    parser.add_argument("--output-dir", type=Path, default=Path.home() / ".AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-presentation")
    args = parser.parse_args()
    index = build(args.source_dir, args.output_dir)
    print(index)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
