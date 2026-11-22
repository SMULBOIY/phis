#!/usr/bin/env python3
"""Stage 1 exit gate for the Phishing Website Detection System.

Verifies that the project skeleton and the Stage 1 architecture artefacts are
present and internally consistent, that the diagram is self-contained, that
secrets/database are gitignored, and that no later-stage implementation was
started prematurely.

This gate is STAGE-AWARE: once Stage 2 (or a later stage) has been delivered,
checks that assert "this later file must not exist" are reported as SKIP instead
of failing. That keeps the historical gate re-runnable as a regression test
from every later stage, while each new stage gets its own stricter gate.

Usage:
    cd phishing-detection-system
    python scripts/verify_stage1.py

Exit code 0 = every applicable check passed, 1 = at least one check failed.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DIRS = (
    "dataset/raw",
    "dataset/processed",
    "ml/saved_model",
    "models",
    "services",
    "routes",
    "templates",
    "static/css",
    "static/js",
    "static/images",
    "static/vendor",
    "instance",
    "docs/diagrams",
    "scripts",
    "tests",
)

REQUIRED_FILES = (
    "README.md",
    ".gitignore",
    "docs/ARCHITECTURE.md",
    "docs/DECISIONS.md",
    "docs/STAGE_PLAN.md",
    "docs/diagrams/architecture.svg",
    "scripts/verify_stage1.py",
)

REQUIRED_SECTIONS = {
    "docs/ARCHITECTURE.md": (
        "## 2. System context and trust boundaries",
        "## 3. Architectural style",
        "## 5. Communication and data flows",
        "## 6. Machine-learning decision architecture",
        "## 7. Feature contract",
        "## 8. Model artefact contract",
        "## 9. Data architecture",
        "## 10. Security architecture",
        "## 11. HTTP and API contracts",
        "## 15. Stage 1 test plan",
        "## 16. Common errors and fixes",
    ),
    "docs/DECISIONS.md": (
        "## ADR-001",
        "## ADR-002",
        "## ADR-004",
        "## ADR-006",
        "## ADR-009",
    ),
    "docs/STAGE_PLAN.md": (
        "## Gate discipline",
        "## Stage roadmap",
        "## How to signal the next stage",
    ),
    "README.md": (
        "## Project status",
        "## Quick start",
        "## Repository layout",
        "## Academic integrity",
    ),
}

REQUIRED_GITIGNORE = (
    ".env",
    "instance/*.db",
    "__pycache__/",
    "*.py[cod]",
    ".venv/",
    "ml/saved_model/*.joblib",
)

# Deliberately split so this verifier does not flag its own marker list.
PLACEHOLDER_MARKERS = ("NotImplemented" + "Error", "TODO: imple" + "ment", "placeholder" + " function")

# Directories that must stay free of Python code while the project is at Stage 1.
CODE_DIRS = ("ml", "models", "routes", "services", "tests")

# Stage detection: marker files that only appear once a stage is delivered.
STAGE_2_DELIVERED = (ROOT / "config.py").is_file() and (ROOT / "docs" / "SETUP.md").is_file()
STAGE_7_DELIVERED = (ROOT / "app.py").is_file()

failures: list[str] = []
checks = 0


def check(label: str, condition: bool, hint: str = "") -> None:
    """Record and print one named check."""
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        suffix = f"  -> {hint}" if hint else ""
        print(f"  FAIL  {label}{suffix}")
        failures.append(label)


def skip(label: str, reason: str) -> None:
    """Report a check that no longer applies now that a later stage exists."""
    print(f"  SKIP  {label} ({reason})")


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def main() -> int:
    print("=" * 68)
    print("STAGE 1 EXIT GATE - phishing website detection system")
    print(f"Project root: {ROOT}")
    print("=" * 68)

    print("\n[1] Runtime")
    version = ".".join(str(part) for part in sys.version_info[:3])
    check("Python >= 3.10", sys.version_info >= (3, 10), f"found {version}")

    print("\n[2] Project skeleton")
    for rel in REQUIRED_DIRS:
        check(f"dir  {rel}/", (ROOT / rel).is_dir(), "directory missing")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"file {rel}", path.is_file() and path.stat().st_size > 0, "missing or empty")

    print("\n[3] Architecture documentation completeness")
    for rel, headings in REQUIRED_SECTIONS.items():
        text = read(rel)
        for heading in headings:
            check(f"{rel} :: {heading}", heading in text, "required section missing")

    print("\n[4] Architecture diagram is self-contained SVG")
    svg_path = ROOT / "docs/diagrams/architecture.svg"
    try:
        root = ET.parse(svg_path).getroot()
        check("SVG parses as well-formed XML", root.tag.endswith("svg"))
        external = [
            f"{k}={value}"
            for element in root.iter()
            for k, value in element.attrib.items()
            if k != "xmlns" and ("http://" in value or "https://" in value)
        ]
        check("SVG has no external references", not external, "; ".join(external[:2]))
        scripts = [element for element in root.iter() if element.tag.endswith("script")]
        check("SVG contains no scripts", not scripts)
    except (ET.ParseError, OSError) as exc:
        check("SVG parses as well-formed XML", False, str(exc))

    print("\n[5] Repository security hygiene")
    gitignore = read(".gitignore")
    for token in REQUIRED_GITIGNORE:
        check(f".gitignore :: {token}", token in gitignore, "rule missing")

    print("\n[6] Stage discipline: no premature code, no placeholders")
    if not STAGE_2_DELIVERED:
        check("requirements.txt belongs to Stage 2", not (ROOT / "requirements.txt").exists())
        for directory in CODE_DIRS:
            folder = ROOT / directory
            stray = sorted(folder.glob("*.py")) if folder.is_dir() else []
            check(f"{directory}/ has no *.py yet", not stray,
                  ", ".join(path.name for path in stray))
    else:
        skip("requirements.txt belongs to Stage 2", "delivered in Stage 2")
        skip("ml|models|routes|services|tests have no *.py", "enforced by the current stage gate")

    if not STAGE_7_DELIVERED:
        check("root app.py not started yet", not (ROOT / "app.py").exists())
    else:
        skip("root app.py not started yet", "delivered in Stage 7")

    for rel in REQUIRED_FILES:
        if not rel.endswith(".py"):
            continue
        path = ROOT / rel
        if path.resolve() == Path(__file__).resolve():
            continue
        text = read(rel)
        check(
            f"{rel} has no placeholder markers",
            not any(marker in text for marker in PLACEHOLDER_MARKERS),
        )

    print("\n" + "=" * 68)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        print("\nFix the items above before proceeding to the next stage.")
        return 1
    print(f"RESULT: PASS - all {checks} applicable checks passed")
    print("Stage 1 artefacts intact. This gate remains valid as a regression test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
