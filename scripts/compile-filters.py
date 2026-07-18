#!/usr/bin/env python3
"""Compile component AdGuard filter files into assets/Filter-1.txt."""

from __future__ import annotations

from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
OUTPUT = ASSETS / "Filter-1.txt"
SOURCES = [
    ("Filter-2.txt", "Manual DNS allow/block rules"),
    ("Filter-3.txt", "Karakeep generated allowlist candidates"),
    ("Filter-4.txt", "Browser add-on rules"),
]


def read_source(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"missing source filter: {path}")
    return path.read_text(encoding="utf-8").splitlines()


def build() -> str:
    lines = [
        "! Title: Sick Prodigy Compiled AdGuard List",
        "! Expires: 1 day (update frequency)",
        "! Description: Compiled from Filter-2.txt, Filter-3.txt, and Filter-4.txt.",
        "! Homepage: https://gitea.sickgaming.net/sickprodigy/adguard-list",
        "! License: https://gitea.sickgaming.net/sickprodigy/adguard-list/raw/branch/main/LICENSE",
        f"! Last modified: {date.today().strftime('%m/%d/%Y')}",
        "! Version: generated",
        "!",
        "! Source files:",
    ]
    lines.extend(f"! - {name}: {description}" for name, description in SOURCES)

    for name, description in SOURCES:
        lines.extend([
            "",
            "! =============================================================================",
            f"! Begin {name}: {description}",
            "! =============================================================================",
        ])
        lines.extend(read_source(ASSETS / name))
        lines.extend(["", f"! End {name}"])

    return "\n".join(lines) + "\n"


def main() -> int:
    OUTPUT.write_text(build(), encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

