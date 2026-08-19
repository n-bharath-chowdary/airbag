"""Finding model and severity handling."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

BLOCK = "block"
WARN = "warn"
INFO = "info"

_ORDER = {BLOCK: 0, WARN: 1, INFO: 2}

EXIT_CLEAN = 0
EXIT_WARN = 1
EXIT_BLOCK = 2
EXIT_ERROR = 3


@dataclasses.dataclass
class Finding:
    """A single problem detected in the change set."""

    check: str
    rule: str
    severity: str
    title: str
    remediation: str
    detail: str = ""
    path: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    fix_id: Optional[str] = None

    def location(self) -> str:
        if self.path and self.line:
            return "{}:{}".format(self.path, self.line)
        if self.path:
            return self.path
        return "(repository)"

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["location"] = self.location()
        return data


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (_ORDER.get(f.severity, 9), f.check, f.path or "", f.line or 0),
    )


def worst_severity(findings: List[Finding]) -> Optional[str]:
    if any(f.severity == BLOCK for f in findings):
        return BLOCK
    if any(f.severity == WARN for f in findings):
        return WARN
    if findings:
        return INFO
    return None


def exit_code_for(findings: List[Finding]) -> int:
    worst = worst_severity(findings)
    if worst == BLOCK:
        return EXIT_BLOCK
    if worst == WARN:
        return EXIT_WARN
    return EXIT_CLEAN


def redact(value: str, keep_head: int = 4, keep_tail: int = 2) -> str:
    """Mask a secret so the finding itself never leaks the credential."""
    value = value.strip()
    if len(value) <= keep_head + keep_tail:
        return "*" * len(value)
    masked = len(value) - keep_head - keep_tail
    return "{}{}{}".format(value[:keep_head], "*" * min(masked, 24), value[-keep_tail:])
