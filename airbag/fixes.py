"""The fix engine.

Airbag only ever proposes fixes that are reversible and that do not touch
your source code:

  * appending patterns to .gitignore
  * untracking files that should never have been staged (`git rm --cached`,
    which leaves the file on disk)

Secrets are deliberately *not* auto-fixed. Rewriting a credential out of a
source file is a judgement call - the key has to be rotated either way, and a
tool guessing at the replacement does more harm than good.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from .checks import gitignore as gitignore_check
from .findings import Finding
from .gitutil import git

GITIGNORE_HEADER = "# --- added by Airbag ---"


class Fix:
    def __init__(
        self,
        fix_id: str,
        kind: str,
        description: str,
        commands: List[str],
        safe: bool = True,
        payload: Optional[Dict] = None,
    ) -> None:
        self.id = fix_id
        self.kind = kind
        self.description = description
        self.commands = commands
        self.safe = safe
        self.payload = payload or {}

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "description": self.description,
            "commands": self.commands,
            "safe": self.safe,
        }


def plan(root: str, findings: List[Finding]) -> List[Fix]:
    """Build the list of fixes implied by a set of findings."""
    fixes: List[Fix] = []
    seen = set()

    untrack_files: List[str] = []
    untrack_dirs: List[str] = []
    wants_gitignore = False

    for finding in findings:
        if not finding.fix_id:
            continue
        if finding.fix_id in seen:
            continue
        seen.add(finding.fix_id)

        if finding.fix_id.startswith("untrack:"):
            untrack_files.append(finding.fix_id.split(":", 1)[1])
        elif finding.fix_id.startswith("untrack-dir:"):
            untrack_dirs.append(finding.fix_id.split(":", 1)[1])
        elif finding.fix_id in ("gitignore-append", "gitignore-create"):
            wants_gitignore = True
        elif finding.fix_id == "run-tests":
            fixes.append(
                Fix(
                    "run-tests",
                    "run-tests",
                    "Run the detected test suite and report the result",
                    ["airbag scan --run-tests"],
                    safe=False,
                )
            )

    missing = gitignore_check.missing_patterns(root)
    if untrack_files or untrack_dirs:
        # Anything we untrack should also be ignored, or it comes straight back.
        for path in untrack_dirs:
            pattern = path.rstrip("/") + "/"
            if pattern not in missing:
                missing.append(pattern)
        for path in untrack_files:
            base = os.path.basename(path)
            extension = os.path.splitext(base)[1]
            pattern = "*" + extension if extension else path
            if pattern not in missing and path not in missing:
                missing.append(pattern)
        wants_gitignore = True

    if wants_gitignore and missing:
        fixes.append(
            Fix(
                "gitignore",
                "gitignore",
                "Add {} pattern(s) to .gitignore".format(len(missing)),
                ["# append to .gitignore: " + ", ".join(missing[:10])],
                safe=True,
                payload={"patterns": missing},
            )
        )

    for path in untrack_dirs:
        fixes.append(
            Fix(
                "untrack-dir:{}".format(path),
                "untrack",
                "Untrack `{}/` (files stay on disk)".format(path),
                ["git rm -r --cached -- {}".format(_quote(path))],
                safe=True,
                payload={"path": path, "recursive": True},
            )
        )

    for path in untrack_files:
        fixes.append(
            Fix(
                "untrack:{}".format(path),
                "untrack",
                "Untrack `{}` (file stays on disk)".format(path),
                ["git rm --cached -- {}".format(_quote(path))],
                safe=True,
                payload={"path": path, "recursive": False},
            )
        )
    return fixes


def apply(root: str, fixes: List[Fix], only: Optional[List[str]] = None) -> List[str]:
    """Apply the safe fixes. Returns a log of what happened."""
    log: List[str] = []
    for fix in fixes:
        if only and not any(fix.id == token or fix.kind == token for token in only):
            continue
        if not fix.safe:
            log.append("skipped (not auto-applicable): {}".format(fix.description))
            continue

        if fix.kind == "gitignore":
            log.append(_apply_gitignore(root, fix.payload.get("patterns", [])))
        elif fix.kind == "untrack":
            log.append(_apply_untrack(root, fix.payload["path"], fix.payload["recursive"]))
    return log


def _apply_gitignore(root: str, patterns: List[str]) -> str:
    if not patterns:
        return "gitignore: nothing to add"
    path = os.path.join(root, ".gitignore")
    existing = ""
    if os.path.isfile(path):
        with open(path, "rb") as handle:
            existing = handle.read().decode("utf-8", "replace")

    current = {line.strip() for line in existing.splitlines()}
    to_add = [p for p in patterns if p not in current]
    if not to_add:
        return "gitignore: already up to date"

    block = ""
    if existing and not existing.endswith("\n"):
        block += "\n"
    if GITIGNORE_HEADER not in existing:
        block += ("\n" if existing.strip() else "") + GITIGNORE_HEADER + "\n"
    block += "\n".join(to_add) + "\n"

    with open(path, "ab") as handle:
        handle.write(block.encode("utf-8"))
    return "gitignore: added {} pattern(s): {}".format(len(to_add), ", ".join(to_add))


def _apply_untrack(root: str, path: str, recursive: bool) -> str:
    args = ["rm", "--cached", "-r", "--", path] if recursive else ["rm", "--cached", "--", path]
    code, _, err = git(args, cwd=root)
    if code != 0:
        # Not staged yet: nothing to untrack, which is a fine outcome.
        if "did not match any files" in err:
            return "untrack: {} was not tracked".format(path)
        return "untrack failed for {}: {}".format(path, err.strip()[:200])
    return "untracked {} (still on disk)".format(path)


def _quote(path: str) -> str:
    return '"{}"'.format(path) if " " in path else path
