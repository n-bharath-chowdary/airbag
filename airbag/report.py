"""Rendering: human-readable text and the machine-readable JSON contract."""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, List

from . import __version__
from .findings import BLOCK, INFO, WARN, Finding
from .fixes import Fix

RESET = "\033[0m"
COLORS = {BLOCK: "\033[1;31m", WARN: "\033[1;33m", INFO: "\033[36m", "ok": "\033[1;32m"}

HEADINGS = {
    BLOCK: ("BLOCKERS", "must be fixed before this change is pushed"),
    WARN: ("WARNINGS", "confirm with a human before pushing"),
    INFO: ("NOTES", "informational"),
}

AGENT_INSTRUCTIONS = {
    "blocked": (
        "STOP. Do not run `git commit` or `git push`. Show the findings below to the user in "
        "plain language, explain the risk of each blocker, and propose the listed fixes. Apply "
        "fixes only after the user confirms. For any leaked credential, tell the user it must be "
        "rotated at the provider - removing it from the file is not enough once it has been "
        "written down. Re-run Airbag after fixing and only proceed when it reports `clean`."
    ),
    "warned": (
        "Pause before pushing. Summarise these warnings for the user, say which are worth acting "
        "on, and ask whether to fix them or proceed. Do not decide on the user's behalf. Re-run "
        "Airbag after any fix."
    ),
    "clean": (
        "No blockers or warnings. It is safe to continue with the commit or push the user asked "
        "for."
    ),
    "error": (
        "Airbag could not complete. Report the error to the user and let them decide whether "
        "to proceed without the check."
    ),
}


def _use_color(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _paint(text: str, key: str, enabled: bool) -> str:
    if not enabled or key not in COLORS:
        return text
    return "{}{}{}".format(COLORS[key], text, RESET)


def render_text(report, fixes: List[Fix], no_color: bool = False, quiet: bool = False) -> str:
    color = _use_color(no_color)
    counts = report.counts
    lines: List[str] = []

    header = "Airbag {} | {} | {} file(s) | {:.1f}s".format(
        __version__, report.context.scope.label, len(report.context.files), report.duration
    )
    lines.append(header)
    lines.append("-" * min(len(header), 78))

    grouped: Dict[str, List[Finding]] = {BLOCK: [], WARN: [], INFO: []}
    for finding in report.findings:
        grouped.setdefault(finding.severity, []).append(finding)

    for severity in (BLOCK, WARN, INFO):
        bucket = grouped.get(severity) or []
        if not bucket:
            continue
        if quiet and severity == INFO:
            continue
        title, note = HEADINGS[severity]
        lines.append("")
        lines.append(_paint("{} ({}) - {}".format(title, len(bucket), note), severity, color))
        for finding in bucket:
            lines.append("")
            lines.append("  {} {}".format(
                _paint("[{}/{}]".format(finding.check, finding.rule), severity, color),
                finding.title,
            ))
            location = finding.location()
            if location != "(repository)":
                suffix = "  {}".format(finding.evidence) if finding.evidence else ""
                lines.append("      at {}{}".format(location, suffix))
            if finding.detail:
                for detail_line in finding.detail.splitlines():
                    lines.append("      {}".format(detail_line))
            if finding.remediation:
                lines.append("      -> {}".format(_wrap(finding.remediation, 10)))

    if fixes:
        lines.append("")
        lines.append("SUGGESTED FIXES (nothing is applied without your confirmation)")
        for index, fix in enumerate(fixes, start=1):
            marker = "" if fix.safe else "  [manual]"
            lines.append("  {}. {}{}".format(index, fix.description, marker))
            for command in fix.commands:
                lines.append("       $ {}".format(command))
        lines.append("")
        lines.append("  Apply the safe ones with:  airbag fix")

    lines.append("")
    if report.status == "blocked":
        verdict = _paint("AIRBAG DEPLOYED", BLOCK, color)
        tail = "blocked. Resolve the items above before committing or pushing."
    elif report.status == "warned":
        verdict = _paint("REVIEW NEEDED", WARN, color)
        tail = "confirm these warnings with a human before pushing."
    else:
        verdict = _paint("CLEAR", "ok", color)
        tail = "nothing is standing between this change and a safe push."
    lines.append("RESULT: {} - {}".format(verdict, tail))
    lines.append(
        "        {} blocker(s), {} warning(s), {} note(s).".format(
            counts["block"], counts["warn"], counts["info"]
        )
    )
    if report.skipped:
        lines.append("        skipped checks: {}".format(", ".join(sorted(report.skipped))))
    return "\n".join(lines)


def _wrap(text: str, indent: int, width: int = 92) -> str:
    import textwrap

    prefix = " " * indent
    wrapped = textwrap.wrap(text, width=width - indent)
    if not wrapped:
        return text
    return ("\n" + prefix).join(wrapped)


def render_json(report, fixes: List[Fix]) -> str:
    payload = {
        "tool": "airbag",
        "version": __version__,
        "status": report.status,
        "exit_code": report.exit_code,
        "stage": report.context.stage,
        "scope": {
            "mode": report.context.scope.mode,
            "label": report.context.scope.label,
            "range": report.context.scope.rev_range,
            "files": len(report.context.files),
        },
        "summary": report.counts,
        "duration_seconds": round(report.duration, 3),
        "skipped_checks": sorted(report.skipped),
        "findings": [f.to_dict() for f in report.findings],
        "fixes": [f.to_dict() for f in fixes],
        "agent_instructions": AGENT_INSTRUCTIONS.get(report.status, AGENT_INSTRUCTIONS["clean"]),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_error_json(message: str) -> str:
    return json.dumps(
        {
            "tool": "airbag",
            "version": __version__,
            "status": "error",
            "exit_code": 3,
            "error": message,
            "findings": [],
            "fixes": [],
            "agent_instructions": AGENT_INSTRUCTIONS["error"],
        },
        indent=2,
    )
