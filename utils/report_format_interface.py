#!/usr/bin/env python3
"""CI-facing interface for WhiteHaX Markdown report formatting.

Pipelines and the DAST bridge call this module. The implementation runs
``utils/format_whitehax_report.py`` unchanged through its documented CLI so
that formatter stays the single source of presentation rules.

Usage:

    python utils/report_format_interface.py whitehax-recommendations.md
    python utils/report_format_interface.py whitehax-recommendations.md --overwrite
    python utils/report_format_interface.py report.md --output-dir formatted
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Protocol


FORMATTER_SCRIPT = Path(__file__).resolve().parent / "format_whitehax_report.py"


class ReportFormatter(Protocol):
    """Contract used by CI and the WhiteHaX DAST bridge."""

    def format_file(
        self,
        source: Path,
        *,
        overwrite: bool = True,
        output_dir: Path | None = None,
    ) -> Path:
        """Format ``source`` and return the path of the written Markdown file."""


class WhiteHaxCliReportFormatter:
    """Adapter that executes ``format_whitehax_report.py`` as-is."""

    def __init__(self, formatter_script: Path = FORMATTER_SCRIPT, python: str | None = None):
        self.formatter_script = formatter_script
        self.python = python or sys.executable

    def format_file(
        self,
        source: Path,
        *,
        overwrite: bool = True,
        output_dir: Path | None = None,
    ) -> Path:
        source = Path(source)
        if not self.formatter_script.is_file():
            raise FileNotFoundError(f"Formatter script missing: {self.formatter_script}")
        if source.suffix.lower() not in {".txt", ".md"} or not source.is_file():
            raise ValueError(f"input must be an existing .txt or .md file: {source}")

        command = [self.python, str(self.formatter_script), str(source)]
        if output_dir is not None:
            command.extend(["--output-dir", str(output_dir)])
        if overwrite:
            command.append("--overwrite")

        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        if completed.stdout.strip():
            print(completed.stdout.strip())
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "formatter failed").strip()
            raise RuntimeError(detail)

        destination = (output_dir or source.parent) / f"{source.stem}-formatted.md"
        if not destination.is_file():
            raise FileNotFoundError(f"formatter succeeded but output is missing: {destination}")
        return destination


def get_report_formatter() -> ReportFormatter:
    """Return the default CI formatter implementation."""
    return WhiteHaxCliReportFormatter()


def format_report_file(
    source: Path,
    *,
    overwrite: bool = True,
    output_dir: Path | None = None,
) -> Path:
    """Format one report file through the default interface."""
    return get_report_formatter().format_file(
        source,
        overwrite=overwrite,
        output_dir=output_dir,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Format WhiteHaX Markdown reports via format_whitehax_report.py"
    )
    parser.add_argument("input", nargs="+", type=Path, help="One or more .txt or .md files")
    parser.add_argument("--output-dir", type=Path, help="Write Markdown files to this directory")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        default=True,
        help="Replace an existing formatted output (default: true)",
    )
    parser.add_argument(
        "--no-overwrite",
        action="store_false",
        dest="overwrite",
        help="Fail when the formatted output already exists",
    )
    args = parser.parse_args(argv)

    failed = False
    formatter = get_report_formatter()
    for source in args.input:
        try:
            output = formatter.format_file(
                source,
                overwrite=args.overwrite,
                output_dir=args.output_dir,
            )
            print(f"[INFO] Formatted report ready: {output}")
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"{source}: {exc}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
