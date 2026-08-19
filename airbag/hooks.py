"""Editor hook entry points.

`airbag hook claude` implements a Claude Code **PreToolUse** hook for the
Bash tool. It reads the hook payload on stdin, decides whether the command is a
git commit or push, and gates it:

    clean     -> exit 0, silent, the command runs
    warnings  -> a PreToolUse "ask" decision, so the user is asked to confirm
    blockers  -> exit 2 with the reason on stderr, which refuses the command
                 and hands the details back to the model

Exit code 2 is the universally supported way to block a tool call, so blockers
never depend on the richer JSON protocol being understood.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import List, Optional

from . import gitutil
from .config import load as load_config
from .findings import BLOCK, WARN
from .fixes import plan as plan_fixes
from .scanner import scan

BYPASS = re.compile(r"--no-verify\b")

WRITE_SUBCOMMANDS = {"commit", "push"}

# Global git options that consume the following token, so `git -C dir push`
# is recognised as a push rather than sliding past the check.
VALUE_FLAGS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
               "--config-env", "--super-prefix"}

SEGMENT_SPLIT = re.compile(r"&&|\|\||;|\||\n")


def _tokenize(segment: str) -> List[str]:
    """Split a shell segment, keeping quotes so `echo 'git push'` is not a push.

    posix=False keeps the quote characters attached to the token, so a quoted
    string never looks like a bare `git` invocation, and Windows backslashes
    survive intact.
    """
    import shlex

    try:
        return shlex.split(segment, posix=False)
    except ValueError:
        return segment.split()


def git_subcommands(command: str) -> List[str]:
    """Every git subcommand invoked by a (possibly compound) shell command."""
    found: List[str] = []
    for segment in SEGMENT_SPLIT.split(command):
        tokens = _tokenize(segment)
        index = 0
        while index < len(tokens):
            token = tokens[index].strip("\"'")
            base = os.path.basename(token).lower()
            if base in ("git", "git.exe"):
                index += 1
                while index < len(tokens):
                    candidate = tokens[index].strip("\"'")
                    if not candidate.startswith("-"):
                        found.append(candidate.lower())
                        break
                    if candidate in VALUE_FLAGS:
                        index += 1  # skip this flag's value
                    index += 1
                continue
            index += 1
    return found


def is_git_write(command: str) -> bool:
    return any(sub in WRITE_SUBCOMMANDS for sub in git_subcommands(command))


def _read_payload() -> dict:
    try:
        raw = sys.stdin.read()
    except Exception:
        return {}
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        return {}


def _first_directory(*candidates) -> str:
    """First candidate that is actually a directory on this machine."""
    for candidate in candidates:
        if candidate and os.path.isdir(candidate):
            return candidate
    return os.getcwd()


def _extract_command(payload: dict) -> str:
    tool_input = payload.get("tool_input") or {}
    if isinstance(tool_input, dict):
        for key in ("command", "cmd", "script"):
            value = tool_input.get(key)
            if isinstance(value, str):
                return value
    return ""


def _summarise(report, fixes) -> str:
    lines: List[str] = []
    blockers = [f for f in report.findings if f.severity == BLOCK]
    warnings = [f for f in report.findings if f.severity == WARN]

    if blockers:
        lines.append("Airbag BLOCKED this command. {} blocker(s):".format(len(blockers)))
    else:
        lines.append("Airbag found {} warning(s) on this change:".format(len(warnings)))

    for finding in (blockers or warnings)[:12]:
        location = finding.location()
        lines.append("  - [{}] {}".format(finding.rule, finding.title))
        if location != "(repository)":
            lines.append("      at {}".format(location))
        lines.append("      fix: {}".format(finding.remediation))

    extra = len(blockers or warnings) - 12
    if extra > 0:
        lines.append("  ... and {} more.".format(extra))

    if blockers and warnings:
        lines.append("")
        lines.append("There are also {} warning(s); run `airbag scan` to see them.".format(
            len(warnings)
        ))

    if fixes:
        lines.append("")
        lines.append("Proposed fixes (require the user's approval):")
        for fix in fixes[:8]:
            lines.append("  - {}".format(fix.description))
        lines.append("Apply with: airbag fix")

    lines.append("")
    if blockers:
        lines.append(
            "Do not retry this git command until the blockers are resolved. Explain each one to "
            "the user, ask before applying any fix, and re-run `airbag scan` afterwards. "
            "Any leaked credential must be rotated at the provider - deleting the line is not "
            "enough."
        )
    else:
        lines.append(
            "Summarise these warnings for the user and ask whether to fix them or proceed."
        )
    return "\n".join(lines)


def claude_pretooluse(argv: Optional[List[str]] = None) -> int:
    if os.environ.get("AIRBAG_DISABLE"):
        return 0

    payload = _read_payload()
    command = _extract_command(payload)
    if not command or not is_git_write(command):
        return 0
    if BYPASS.search(command):
        # An explicit bypass is the user's call; say so and get out of the way.
        print("airbag: --no-verify detected, skipping the safety gate.", file=sys.stderr)
        return 0

    stage = "push" if "push" in git_subcommands(command) else "commit"

    try:
        cwd = _first_directory(
            payload.get("cwd"), os.environ.get("CLAUDE_PROJECT_DIR"), os.getcwd()
        )
        root = gitutil.repo_root(cwd)
        if not root:
            return 0
        config = load_config(root, None)
        scope = gitutil.resolve_scope(root, "auto", None, stage)
        report = scan(root, config, scope, stage)
        fixes = plan_fixes(root, report.findings)
    except Exception as exc:  # never wedge the user's workflow on our bug
        print("airbag: check skipped ({}: {})".format(type(exc).__name__, exc), file=sys.stderr)
        return 0

    if report.status == "clean":
        return 0

    reason = _summarise(report, fixes)

    if report.status == "blocked" or os.environ.get("AIRBAG_HOOK_MODE") == "block-on-warn":
        print(reason, file=sys.stderr)
        return 2

    decision = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(decision))
    return 0


def generic_stdin_gate(stage: str) -> int:
    """Stage-agnostic gate for editors without a structured hook protocol.

    Prints a human summary and returns the Airbag exit code.
    """
    root = gitutil.repo_root(os.getcwd())
    if not root:
        return 0
    config = load_config(root, None)
    scope = gitutil.resolve_scope(root, "auto", None, stage)
    report = scan(root, config, scope, stage)
    fixes = plan_fixes(root, report.findings)
    if report.status != "clean":
        print(_summarise(report, fixes), file=sys.stderr)
    return report.exit_code
