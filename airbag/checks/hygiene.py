"""Commit and branch hygiene."""

from __future__ import annotations

import re
from typing import List

from ..findings import INFO, WARN, Finding
from ..gitutil import current_branch, git

LOW_EFFORT_MESSAGE = re.compile(
    r"(?i)^\s*(?:update[sd]?|fix(?:e[sd])?|changes?|stuff|things|wip|temp|tmp|test|misc|"
    r"minor|cleanup|refactor|commit|initial|final|done|asdf|\.+|-+)\s*[.!]?\s*$"
)

CONVENTIONAL = re.compile(
    r"^(?:build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(?:\([^)]+\))?!?: .+"
)


def run(ctx) -> List[Finding]:
    cfg = ctx.config
    findings: List[Finding] = []

    protected = [b.lower() for b in cfg.opt("hygiene", "protected_branches", []) or []]
    branch = current_branch(ctx.root)
    if ctx.stage == "push" and branch and branch.lower() in protected:
        findings.append(
            Finding(
                check="hygiene",
                rule="push-to-protected-branch",
                severity=WARN,
                title="Pushing directly to `{}`".format(branch),
                detail="This branch is listed as protected in the Airbag config.",
                remediation=(
                    "Open a pull request instead: `git switch -c <feature-branch>` then push that. "
                    "If direct pushes are intended here, remove `{}` from "
                    "`checks.hygiene.protected_branches`.".format(branch)
                ),
            )
        )

    max_files = int(cfg.opt("hygiene", "max_files", 80))
    if len(ctx.files) > max_files:
        findings.append(
            Finding(
                check="hygiene",
                rule="oversized-changeset",
                severity=INFO,
                title="{} files in one change".format(len(ctx.files)),
                detail="Scope: {}.".format(ctx.scope.label),
                remediation=(
                    "Large changes are hard to review, and unreviewed generated code is exactly "
                    "how bad changes ship. Consider splitting this up."
                ),
            )
        )

    message = ctx.message
    if message is None and ctx.stage == "commit":
        message = _pending_message(ctx.root)

    if message:
        subject = message.strip().splitlines()[0].strip() if message.strip() else ""
        if subject and len(subject) < 10:
            findings.append(
                Finding(
                    check="hygiene",
                    rule="short-commit-message",
                    severity=INFO,
                    title="Commit subject is very short",
                    detail="Subject: {!r}".format(subject),
                    remediation="Say what changed and why in one line - future you will need it.",
                )
            )
        elif subject and LOW_EFFORT_MESSAGE.match(subject):
            findings.append(
                Finding(
                    check="hygiene",
                    rule="low-effort-commit-message",
                    severity=INFO,
                    title="Commit subject carries no information",
                    detail="Subject: {!r}".format(subject),
                    remediation=(
                        "Describe the change, e.g. `fix(auth): reject expired refresh tokens`."
                    ),
                )
            )
    return findings


def _pending_message(root: str) -> str:
    """Read .git/COMMIT_EDITMSG if a commit is in progress."""
    import os

    code, out, _ = git(["rev-parse", "--git-dir"], cwd=root)
    if code != 0:
        return ""
    git_dir = out.strip()
    if not os.path.isabs(git_dir):
        git_dir = os.path.join(root, git_dir)
    path = os.path.join(git_dir, "COMMIT_EDITMSG")
    try:
        with open(path, "rb") as handle:
            text = handle.read().decode("utf-8", "replace")
    except OSError:
        return ""
    lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    return "\n".join(lines).strip()
