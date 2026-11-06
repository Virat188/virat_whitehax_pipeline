#!/usr/bin/env python3
r"""Format WhiteHaX .txt or .md reports for GitHub Markdown display.

Usage (Python 3.11 or newer; no third-party packages required):

    python format_whitehax_report.py "report.txt"
    python format_whitehax_report.py "report.md" "second report.txt"
    python format_whitehax_report.py "report.txt" --output-dir "formatted"
    python format_whitehax_report.py "report.txt" --overwrite

Input and output contract:
    * Each positional input must be an existing UTF-8 .txt or .md file. The
      script accepts multiple files but does not search directories recursively.
    * For each input, write <input stem>-formatted.md beside the source, or in
      --output-dir when given. The source file is never modified. Existing
      outputs are protected unless --overwrite is supplied.
    * Success returns exit code 0. An invalid input, read/write error, or
      existing output returns exit code 1; other input files are still tried.

Formatting logic, in execution order:
    1. Normalize line endings and excess blank lines, limit heading depth to
       four levels, and show the critical posture in readable wording while
       retaining its machine value in the summary table.
    2. Remove rows with no value from the opening Metric/Value table.
    3. Remove only whole top-level sections that have identical headings and
       identical bodies. Within summary/security-assessment sections, remove
       only repeated bullet lines with exactly the same text. Repeated RTO
       option headings and their nested configuration are preserved.
    4. Add a comparison table before the RTO option details. The detailed
       option blocks remain below the table.
    5. Replace the opening Metric/Value table with a shorter At a glance table;
       for an RTO report with no security metrics, use its response-time and
       improvement-plan values.
    6. Ignore headings inside fenced code blocks and preserve HTML entities
       such as &lt; so Markdown does not turn their values into HTML tags.

This is presentation-only formatting. It does not verify risk scores, repair
conflicting findings, infer missing metrics, or run a WhiteHaX scan. Review
the formatted result before publishing it as a release decision artifact.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)\s*$")
TABLE_ROW = re.compile(r"^\|(.+)\|$")
ITEM = re.compile(r"^####[ \t]+Item[ \t]+(\d+)[ \t]*$", re.I)
METRIC = re.compile(r"^-[ \t]+\*\*(.+?):\*\*[ \t]*(.*?)\s*$")


def heading(line: str):
    match = HEADING.match(line)
    return (len(match.group(1)), match.group(2)) if match else None


def fence_states(lines: list[str]):
    """Track fenced blocks so their code is never treated as report structure."""
    marker = None
    for line in lines:
        stripped = line.lstrip()
        found = re.match(r"^(`{3,}|~{3,})", stripped)
        if found:
            token = found.group(1)
            if marker is None:
                marker = token
            elif token[0] == marker[0] and len(token) >= len(marker):
                marker = None
            yield True
        else:
            yield marker is not None


def clean_lines(text: str):
    text = text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    in_code = list(fence_states(lines))
    result = []
    previous_blank = False
    for line, code in zip(lines, in_code):
        if not code:
            h = heading(line)
            if h and h[0] > 4:
                line = "#### " + h[1]
            # Keep the raw machine value available while making the status scannable.
            line = line.replace("| critical_immediate_action_required |", "| Critical: immediate action required (`critical_immediate_action_required`) |")
            line = line.replace("**critical_immediate_action_required posture.**", "**Critical: immediate action required.**")
        blank = not line.strip()
        if blank and previous_blank and not code:
            continue
        result.append(line)
        previous_blank = blank
    return result


def remove_empty_summary_rows(lines: list[str]):
    out = []
    in_summary_table = False
    for line in lines:
        if line == "| Metric | Value |":
            in_summary_table = True
        elif in_summary_table and not line.startswith("|"):
            in_summary_table = False
        if in_summary_table and TABLE_ROW.match(line):
            cells = [part.strip() for part in line.strip("|").split("|")]
            if len(cells) == 2 and cells[0] not in ("Metric", "---") and not cells[1]:
                continue
        out.append(line)
    return out


def sections(lines: list[str]):
    """Split at top-level report sections, keeping nested detail together."""
    starts = [i for i, line in enumerate(lines) if (h := heading(line)) and h[0] <= 3]
    if not starts:
        return [(None, lines)]
    spans = [(None, lines[: starts[0]])]
    for pos, start in enumerate(starts):
        end = starts[pos + 1] if pos + 1 < len(starts) else len(lines)
        spans.append((lines[start], lines[start:end]))
    return spans


def drop_exact_duplicate_sections(lines: list[str]):
    # A repeated option heading is meaningful in its parent context. Compare
    # only complete top-level sections, including all of their nested content.
    seen = set()
    out = []
    for title, block in sections(lines):
        key = (title, "\n".join(line.strip() for line in block[1:] if line.strip()))
        if title and key in seen and key[1]:
            continue
        seen.add(key)
        out.extend(block)
    return out


def dedupe_summary_bullets(lines: list[str]):
    summary_titles = {"executive summary", "summary", "security assessment"}
    seen = set()
    active_level = None
    out = []
    for line in lines:
        h = heading(line)
        if h:
            level, title = h
            if active_level is not None and level <= active_level:
                active_level = None
            if level in (3, 4) and title.strip().lower() in summary_titles:
                active_level = level
        if active_level is not None and line.startswith("- **"):
            key = line.strip()
            if key in seen:
                continue
            seen.add(key)
        out.append(line)
    return out


def initial_overview(lines: list[str]):
    report = next((line for line in lines if line.startswith("Report `")), None)
    rows = {}
    in_table = False
    for line in lines:
        if line == "| Metric | Value |":
            in_table = True
            continue
        if in_table and not line.startswith("|"):
            break
        if in_table and line.startswith("|"):
            cells = [v.strip() for v in line.strip("|").split("|")]
            if len(cells) == 2 and cells[0] != "---" and cells[1]:
                rows[cells[0]] = cells[1]
    if not report:
        return None
    if any("### At a glance" == line for line in lines):
        return None
    if rows:
        ordered = [key for key in ("Security posture", "Risk score", "Failed tests", "Critical", "Timeline") if key in rows]
        return ["### At a glance", "", "| Metric | Result |", "| --- | --- |"] + [f"| {key} | {rows[key]} |" for key in ordered]
    # Performance reports do not have a security posture. Surface their actual metrics.
    latency = next((lines[i + 2].strip() for i, line in enumerate(lines[:-2]) if line == "### Initial response time ms"), None)
    total = next((m.group(1) for line in lines if (m := re.match(r"^- \*\*Total improvement:\*\* (.+)$", line))), None)
    if latency or total:
        result = ["### At a glance", "", "| Metric | Result |", "| --- | --- |"]
        if latency:
            result.append(f"| Initial response time | {latency} ms |")
        if total:
            result.append(f"| Planned improvement | {total} |")
        return result
    return None


def rto_comparison(lines: list[str]):
    if "### Recommendation tables" not in lines or "### Configuration comparison" in lines:
        return lines
    start = lines.index("### Recommendation tables")
    item_starts = [i for i in range(start + 1, len(lines)) if ITEM.match(lines[i])]
    if len(item_starts) < 2:
        return lines
    keys = ("Avg response time", "Performance tier", "Required memory gb", "Required cpu cores", "Estimated monthly cost")
    rows = []
    for pos, i in enumerate(item_starts):
        end = item_starts[pos + 1] if pos + 1 < len(item_starts) else len(lines)
        values = {}
        for line in lines[i + 1:end]:
            match = METRIC.match(line)
            if match and match.group(1) in keys:
                values.setdefault(match.group(1), match.group(2))
        if values:
            rows.append((ITEM.match(lines[i]).group(1), values))
    if len(rows) < 2:
        return lines
    table = [
        "### Configuration comparison", "",
        "| Option | Avg response time (ms) | Tier | Memory (GB) | CPU cores | Monthly cost |",
        "| --- | ---: | --- | ---: | ---: | --- |",
    ]
    for number, values in rows:
        cells = [number] + [values.get(key, "Not specified").replace("|", "\\|") for key in keys]
        table.append("| " + " | ".join(cells) + " |")
    table += ["", "Detailed configuration for each option follows.", ""]
    return lines[:start] + table + lines[start:]


def format_report(text: str) -> str:
    lines = clean_lines(text)
    lines = remove_empty_summary_rows(lines)
    lines = drop_exact_duplicate_sections(lines)
    lines = dedupe_summary_bullets(lines)
    lines = rto_comparison(lines)
    overview = initial_overview(lines)
    if overview:
        table_start = next((i for i, line in enumerate(lines) if line == "| Metric | Value |"), None)
        if table_start is not None:
            table_end = table_start
            while table_end < len(lines) and lines[table_end].startswith("|"):
                table_end += 1
            lines[table_start:table_end] = overview
        else:
            insert = next((i for i, line in enumerate(lines) if line.startswith("### ")), len(lines))
            lines[insert:insert] = overview + [""]
    return "\n".join(lines).strip() + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Format WhiteHaX .txt and .md reports as Markdown.")
    parser.add_argument("input", nargs="+", type=Path, help="One or more .txt or .md files")
    parser.add_argument("--output-dir", type=Path, help="Write Markdown files to this directory")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing output file")
    args = parser.parse_args(argv)
    failed = False
    for source in args.input:
        try:
            if source.suffix.lower() not in (".txt", ".md") or not source.is_file():
                raise ValueError("input must be an existing .txt or .md file")
            output_dir = args.output_dir or source.parent
            output = output_dir / (source.stem + "-formatted.md")
            if output.resolve() == source.resolve():
                raise ValueError("output would overwrite the source")
            if output.exists() and not args.overwrite:
                raise FileExistsError(f"output already exists: {output} (use --overwrite)")
            result = format_report(source.read_text(encoding="utf-8-sig"))
            output_dir.mkdir(parents=True, exist_ok=True)
            output.write_text(result, encoding="utf-8", newline="\n")
            print(f"{source} -> {output}")
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"{source}: {exc}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
