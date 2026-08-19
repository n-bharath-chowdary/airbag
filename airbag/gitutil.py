"""Thin, dependency-free wrapper around the git plumbing Airbag needs."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

MAX_LINE_LENGTH = 4000
MAX_ADDED_LINES = 250000
BINARY_SNIFF_BYTES = 8000


class GitError(RuntimeError):
    pass


def run(args: Sequence[str], cwd: Optional[str] = None, check: bool = False) -> Tuple[int, str, str]:
    """Run a command, returning (code, stdout, stderr) decoded as text."""
    if cwd and not os.path.isdir(cwd):
        cwd = None
    try:
        proc = subprocess.run(
            list(args),
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        # Missing executable or an unusable cwd must never raise into a hook.
        if check:
            raise GitError("could not run {}: {}".format(" ".join(args), exc))
        return 127, "", str(exc)
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    if check and proc.returncode != 0:
        raise GitError("command failed: {}\n{}".format(" ".join(args), err.strip()))
    return proc.returncode, out, err


def git(args: Sequence[str], cwd: Optional[str] = None, check: bool = False) -> Tuple[int, str, str]:
    return run(["git"] + list(args), cwd=cwd, check=check)


def repo_root(start: Optional[str] = None) -> Optional[str]:
    code, out, _ = git(["rev-parse", "--show-toplevel"], cwd=start or os.getcwd())
    if code != 0:
        return None
    return os.path.normpath(out.strip()) or None


def current_branch(root: str) -> str:
    _, out, _ = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    return out.strip()


def has_commits(root: str) -> bool:
    code, _, _ = git(["rev-parse", "--verify", "HEAD"], cwd=root)
    return code == 0


def upstream_ref(root: str) -> Optional[str]:
    code, out, _ = git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], cwd=root)
    if code == 0 and out.strip():
        return out.strip()
    return None


def default_remote_base(root: str) -> Optional[str]:
    """Best-effort base commit for a branch that has no upstream yet."""
    for ref in ("origin/HEAD", "origin/main", "origin/master"):
        code, out, _ = git(["rev-parse", "--verify", "--quiet", ref], cwd=root)
        if code == 0 and out.strip():
            code2, base, _ = git(["merge-base", ref, "HEAD"], cwd=root)
            if code2 == 0 and base.strip():
                return base.strip()
    return None


class Scope:
    """Describes what is being inspected and where its content comes from."""

    def __init__(self, mode: str, rev_range: Optional[str] = None, label: str = "") -> None:
        self.mode = mode  # staged | range | worktree | all
        self.rev_range = rev_range
        self.label = label or mode

    @property
    def content_ref(self) -> Optional[str]:
        """Revision used to read content; None means read the working tree."""
        if self.mode == "staged":
            return ""  # the index, addressed as ":path"
        if self.mode == "range" and self.rev_range:
            return self.rev_range.split("..")[-1] or "HEAD"
        return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Scope(mode={!r}, range={!r})".format(self.mode, self.rev_range)


def resolve_scope(root: str, mode: str, rev_range: Optional[str], stage: str) -> Scope:
    """Turn CLI intent into a concrete scope, with sensible fallbacks."""
    if mode == "all":
        return Scope("all", label="all tracked files")
    if rev_range:
        return Scope("range", rev_range, label="range {}".format(rev_range))
    if mode == "staged":
        return Scope("staged", label="staged changes")
    if mode == "worktree":
        return Scope("worktree", label="working tree vs HEAD")

    # mode == "auto"
    if stage == "push":
        if not has_commits(root):
            return Scope("all", label="all tracked files (no commits yet)")
        upstream = upstream_ref(root)
        if upstream:
            rng = "{}..HEAD".format(upstream)
            _, out, _ = git(["rev-list", "--count", rng], cwd=root)
            if out.strip().isdigit() and int(out.strip()) > 0:
                return Scope("range", rng, label="commits ahead of {}".format(upstream))
            return Scope("range", rng, label="no new commits vs {}".format(upstream))
        base = default_remote_base(root)
        if base:
            return Scope("range", "{}..HEAD".format(base), label="commits not on origin")
        return Scope("all", label="all tracked files (branch not pushed yet)")

    # stage == commit
    if has_staged_changes(root):
        return Scope("staged", label="staged changes")
    if has_commits(root):
        return Scope("worktree", label="working tree vs HEAD")
    return Scope("all", label="all tracked files")


def has_staged_changes(root: str) -> bool:
    code, out, _ = git(["diff", "--cached", "--name-only"], cwd=root)
    return code == 0 and bool(out.strip())


def changed_files(root: str, scope: Scope) -> List[str]:
    if scope.mode == "all":
        _, out, _ = git(["ls-files", "-z"], cwd=root)
    elif scope.mode == "staged":
        _, out, _ = git(
            ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR", "-M"], cwd=root
        )
    elif scope.mode == "range":
        _, out, _ = git(
            ["diff", "--name-only", "-z", "--diff-filter=ACMR", "-M", scope.rev_range], cwd=root
        )
    else:  # worktree
        _, out, _ = git(
            ["diff", "--name-only", "-z", "--diff-filter=ACMR", "-M", "HEAD"], cwd=root
        )
    return [p for p in out.split("\x00") if p]


def untracked_files(root: str) -> List[str]:
    _, out, _ = git(["ls-files", "-z", "--others", "--exclude-standard"], cwd=root)
    return [p for p in out.split("\x00") if p]


def tracked_files(root: str) -> List[str]:
    _, out, _ = git(["ls-files", "-z"], cwd=root)
    return [p for p in out.split("\x00") if p]


def read_blob(root: str, path: str, scope: Scope) -> Optional[bytes]:
    ref = scope.content_ref
    if ref is None:
        full = os.path.join(root, path)
        try:
            with open(full, "rb") as handle:
                return handle.read()
        except OSError:
            return None
    spec = "{}:{}".format(ref, path) if ref else ":{}".format(path)
    proc = subprocess.run(
        ["git", "show", spec], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def blob_size(root: str, path: str, scope: Scope) -> int:
    ref = scope.content_ref
    if ref is not None:
        spec = "{}:{}".format(ref, path) if ref else ":{}".format(path)
        code, out, _ = git(["cat-file", "-s", spec], cwd=root)
        if code == 0 and out.strip().isdigit():
            return int(out.strip())
    try:
        return os.path.getsize(os.path.join(root, path))
    except OSError:
        return 0


def is_binary(data: bytes) -> bool:
    if not data:
        return False
    chunk = data[:BINARY_SNIFF_BYTES]
    if b"\x00" in chunk:
        return True
    text_chars = bytes(range(32, 127)) + b"\n\r\t\f\b"
    nontext = sum(1 for byte in chunk if byte not in text_chars)
    return nontext / max(len(chunk), 1) > 0.30


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def added_lines(root: str, scope: Scope) -> Dict[str, List[Tuple[int, str]]]:
    """Map path -> [(line_number, added_line_text)] for the scope.

    Every line of a newly added file counts as an added line, which is exactly
    what we want: brand new files get scanned in full.
    """
    if scope.mode == "all":
        return _added_lines_from_worktree(root)

    if scope.mode == "staged":
        args = ["diff", "--cached", "-U0", "--no-color", "--diff-filter=ACMR", "-M"]
    elif scope.mode == "range":
        args = ["diff", "-U0", "--no-color", "--diff-filter=ACMR", "-M", scope.rev_range or "HEAD"]
    else:
        args = ["diff", "-U0", "--no-color", "--diff-filter=ACMR", "-M", "HEAD"]

    proc = subprocess.run(
        ["git"] + args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    text = proc.stdout.decode("utf-8", "replace")

    result: Dict[str, List[Tuple[int, str]]] = {}
    path: Optional[str] = None
    lineno = 0
    total = 0
    for raw in text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            path = None if target == "/dev/null" else _strip_prefix(target)
            continue
        if raw.startswith("--- ") or raw.startswith("diff --git"):
            continue
        match = _HUNK.match(raw)
        if match:
            lineno = int(match.group(1))
            continue
        if path and raw.startswith("+"):
            if total >= MAX_ADDED_LINES:
                break
            content = raw[1:]
            if len(content) > MAX_LINE_LENGTH:
                content = content[:MAX_LINE_LENGTH]
            result.setdefault(path, []).append((lineno, content))
            lineno += 1
            total += 1
    return result


def _strip_prefix(target: str) -> str:
    if target.startswith("b/") or target.startswith("a/"):
        return target[2:]
    return target


def _added_lines_from_worktree(root: str) -> Dict[str, List[Tuple[int, str]]]:
    result: Dict[str, List[Tuple[int, str]]] = {}
    total = 0
    for path in tracked_files(root):
        full = os.path.join(root, path)
        try:
            with open(full, "rb") as handle:
                data = handle.read(2 * 1024 * 1024)
        except OSError:
            continue
        if is_binary(data):
            continue
        lines = data.decode("utf-8", "replace").splitlines()
        entries = []
        for index, line in enumerate(lines, start=1):
            if total >= MAX_ADDED_LINES:
                break
            entries.append((index, line[:MAX_LINE_LENGTH]))
            total += 1
        if entries:
            result[path] = entries
    return result
