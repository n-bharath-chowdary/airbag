"""Repository waste: vendored dependencies, build output, junk and huge files.

GitHub rejects any single file over 100 MB outright and warns above 50 MB, and
a repository that has ever contained ``node_modules`` carries that weight in
its history forever. This check catches the mistake while it is still cheap to
undo - before the commit exists.
"""

from __future__ import annotations

import os
import posixpath
import re
from typing import Dict, List, Optional, Tuple

from ..findings import BLOCK, INFO, WARN, Finding

KB = 1024
MB = 1024 * 1024

GITHUB_HARD_LIMIT = 100 * MB
GITHUB_SOFT_LIMIT = 50 * MB

# directory name -> (severity, reason, ignore pattern)
DENY_DIRS: Dict[str, Tuple[str, str, str]] = {
    "node_modules": (BLOCK, "installed npm dependencies", "node_modules/"),
    "bower_components": (BLOCK, "installed bower dependencies", "bower_components/"),
    "__pycache__": (BLOCK, "compiled Python bytecode", "__pycache__/"),
    ".pytest_cache": (BLOCK, "pytest cache", ".pytest_cache/"),
    ".mypy_cache": (BLOCK, "mypy cache", ".mypy_cache/"),
    ".ruff_cache": (BLOCK, "ruff cache", ".ruff_cache/"),
    ".tox": (BLOCK, "tox environments", ".tox/"),
    "site-packages": (BLOCK, "a Python virtual environment", ".venv/"),
    ".gradle": (BLOCK, "gradle cache", ".gradle/"),
    ".terraform": (BLOCK, "downloaded terraform providers", ".terraform/"),
    ".next": (BLOCK, "Next.js build output", ".next/"),
    ".nuxt": (BLOCK, "Nuxt build output", ".nuxt/"),
    ".svelte-kit": (BLOCK, "SvelteKit build output", ".svelte-kit/"),
    ".parcel-cache": (BLOCK, "Parcel cache", ".parcel-cache/"),
    ".turbo": (BLOCK, "Turborepo cache", ".turbo/"),
    "DerivedData": (BLOCK, "Xcode derived data", "DerivedData/"),
    "coverage": (WARN, "test coverage output", "coverage/"),
    "htmlcov": (WARN, "coverage HTML report", "htmlcov/"),
    "dist": (WARN, "build output", "dist/"),
    "build": (WARN, "build output", "build/"),
    "out": (WARN, "build output", "out/"),
    "target": (WARN, "build output", "target/"),
    "Pods": (WARN, "CocoaPods dependencies", "Pods/"),
    "vendor": (WARN, "vendored dependencies", "vendor/"),
    "logs": (WARN, "log output", "logs/"),
    ".idea": (WARN, "JetBrains IDE settings", ".idea/"),
    ".vs": (WARN, "Visual Studio settings", ".vs/"),
}

VENV_MARKERS = ("pyvenv.cfg", "site-packages")

# extension -> (severity, reason)
DENY_EXT: Dict[str, Tuple[str, str]] = {
    ".pyc": (BLOCK, "compiled Python bytecode"),
    ".pyo": (BLOCK, "compiled Python bytecode"),
    ".class": (BLOCK, "compiled Java bytecode"),
    ".o": (BLOCK, "compiled object file"),
    ".obj": (BLOCK, "compiled object file"),
    ".a": (BLOCK, "static library"),
    ".lib": (BLOCK, "static library"),
    ".so": (BLOCK, "compiled shared library"),
    ".dylib": (BLOCK, "compiled shared library"),
    ".dll": (BLOCK, "compiled shared library"),
    ".exe": (BLOCK, "compiled executable"),
    ".msi": (BLOCK, "installer package"),
    ".dmg": (BLOCK, "disk image"),
    ".iso": (BLOCK, "disk image"),
    ".log": (WARN, "log output"),
    ".tmp": (WARN, "temporary file"),
    ".temp": (WARN, "temporary file"),
    ".bak": (WARN, "backup file"),
    ".orig": (BLOCK, "merge leftover file"),
    ".rej": (BLOCK, "failed patch leftover"),
    ".swp": (WARN, "vim swap file"),
    ".swo": (WARN, "vim swap file"),
    ".sqlite": (WARN, "database file"),
    ".sqlite3": (WARN, "database file"),
    ".db": (WARN, "database file"),
    ".mdb": (WARN, "database file"),
    ".dump": (WARN, "database dump"),
    ".zip": (WARN, "archive"),
    ".tar": (WARN, "archive"),
    ".gz": (WARN, "archive"),
    ".tgz": (WARN, "archive"),
    ".rar": (WARN, "archive"),
    ".7z": (WARN, "archive"),
    ".psd": (WARN, "large design source file"),
    ".ai": (WARN, "large design source file"),
    ".sketch": (WARN, "large design source file"),
    ".mp4": (WARN, "video file"),
    ".mov": (WARN, "video file"),
    ".avi": (WARN, "video file"),
    ".mkv": (WARN, "video file"),
    ".ckpt": (BLOCK, "model checkpoint"),
    ".safetensors": (BLOCK, "model weights"),
    ".pt": (WARN, "model weights"),
    ".pth": (WARN, "model weights"),
    ".h5": (WARN, "model weights / dataset"),
    ".onnx": (WARN, "model weights"),
    ".pkl": (WARN, "pickled data"),
    ".parquet": (WARN, "dataset"),
}

DENY_NAMES = {
    ".ds_store": (BLOCK, "macOS folder metadata", ".DS_Store"),
    "thumbs.db": (BLOCK, "Windows thumbnail cache", "Thumbs.db"),
    "desktop.ini": (BLOCK, "Windows folder metadata", "desktop.ini"),
    "npm-debug.log": (BLOCK, "npm crash log", "npm-debug.log*"),
    "yarn-error.log": (BLOCK, "yarn crash log", "yarn-error.log*"),
    "pnpm-debug.log": (BLOCK, "pnpm crash log", "pnpm-debug.log*"),
    ".env.local": (BLOCK, "local environment file", ".env.local"),
    "terraform.tfstate": (BLOCK, "terraform state (contains secrets)", "*.tfstate"),
    "terraform.tfstate.backup": (BLOCK, "terraform state backup", "*.tfstate.backup"),
}

SCRATCH_NAME = re.compile(
    r"(?i)^(untitled|new[ _-]?file|copy[ _-]?of[ _-]|temp|tmp|test123|asdf|qwerty|foo|bar|baz|"
    r"scratch|delete[ _-]?me|todo|aaa|zzz)[0-9]*(\.[A-Za-z0-9]+)?$"
)
DUPLICATE_NAME = re.compile(r"(?i).+ \(\d+\)\.[A-Za-z0-9]+$|.+ copy(\s\d+)?\.[A-Za-z0-9]+$")

# Extensions that are perfectly normal even though they match a deny rule above.
ALLOW_SMALL = {".zip", ".gz", ".tar", ".tgz", ".db", ".sqlite", ".sqlite3", ".log", ".pkl"}
ALLOW_SMALL_LIMIT = 256 * KB


def _segments(path: str) -> List[str]:
    return [s for s in path.replace("\\", "/").split("/") if s]


def _human(size: int) -> str:
    if size >= MB:
        return "{:.1f} MB".format(size / MB)
    if size >= KB:
        return "{:.0f} KB".format(size / KB)
    return "{} B".format(size)


def _dir_verdict(path: str) -> Optional[Tuple[str, str, str, str]]:
    """Return (severity, reason, ignore_pattern, matched_dir) for a denied dir."""
    segs = _segments(path)
    for index, seg in enumerate(segs[:-1]):
        if seg in DENY_DIRS:
            severity, reason, pattern = DENY_DIRS[seg]
            return severity, reason, pattern, "/".join(segs[: index + 1])
        if seg in ("venv", ".venv", "virtualenv", "env") and any(
            marker in path for marker in VENV_MARKERS
        ):
            return BLOCK, "a Python virtual environment", seg + "/", "/".join(segs[: index + 1])
    return None


def run(ctx) -> List[Finding]:
    cfg = ctx.config
    warn_file = int(cfg.opt("waste", "warn_file_kb", 2048)) * KB
    block_file = int(cfg.opt("waste", "block_file_kb", 51200)) * KB
    warn_total = int(cfg.opt("waste", "warn_total_kb", 20480)) * KB
    extra_deny = list(cfg.opt("waste", "extra_deny", []) or [])
    extra_allow = list(cfg.opt("waste", "extra_allow", []) or [])

    findings: List[Finding] = []
    reported_dirs: Dict[str, int] = {}
    total_bytes = 0

    for path in ctx.files:
        normalized = path.replace("\\", "/")
        if ctx.path_allowed(normalized) or _matches_any(normalized, extra_allow):
            continue

        size = ctx.size_of(path)
        total_bytes += size
        base = posixpath.basename(normalized)
        lowered = base.lower()
        _, ext = posixpath.splitext(lowered)

        verdict = _dir_verdict(normalized)
        if verdict is not None:
            severity, reason, pattern, matched = verdict
            reported_dirs[matched] = reported_dirs.get(matched, 0) + 1
            if reported_dirs[matched] == 1:
                findings.append(
                    Finding(
                        check="waste",
                        rule="generated-directory",
                        severity=severity,
                        title="`{}/` should not be in version control".format(matched),
                        detail="This directory holds {} and can be regenerated.".format(reason),
                        path=matched,
                        remediation=(
                            "Add `{}` to .gitignore and untrack it with "
                            "`git rm -r --cached {}` (files stay on disk).".format(pattern, matched)
                        ),
                        fix_id="untrack-dir:{}".format(matched),
                    )
                )
            continue

        if lowered in DENY_NAMES:
            severity, reason, pattern = DENY_NAMES[lowered]
            findings.append(_junk_finding(normalized, severity, reason, pattern))
            continue

        if _matches_any(normalized, extra_deny):
            findings.append(_junk_finding(normalized, BLOCK, "denied by project config", normalized))
            continue

        if ext in DENY_EXT:
            severity, reason = DENY_EXT[ext]
            if ext in ALLOW_SMALL and size <= ALLOW_SMALL_LIMIT:
                pass
            else:
                findings.append(_junk_finding(normalized, severity, reason, "*" + ext))
                continue

        if SCRATCH_NAME.match(base) or DUPLICATE_NAME.match(base):
            findings.append(
                Finding(
                    check="waste",
                    rule="scratch-file",
                    severity=WARN,
                    title="`{}` looks like a scratch or duplicate file".format(normalized),
                    detail="Throwaway names are a common sign of leftover experimentation.",
                    path=normalized,
                    remediation="Delete it, or give it a real name if it is meant to ship.",
                )
            )

        if size >= GITHUB_HARD_LIMIT:
            findings.append(
                Finding(
                    check="waste",
                    rule="file-over-github-limit",
                    severity=BLOCK,
                    title="`{}` is {} - GitHub will reject this push".format(normalized, _human(size)),
                    detail="GitHub refuses any single file larger than 100 MB.",
                    path=normalized,
                    remediation=(
                        "Remove the file from the commit, or track it with Git LFS "
                        "(`git lfs track \"{}\"`). Store large artifacts in a release "
                        "or object storage instead.".format("*" + ext if ext else normalized)
                    ),
                    fix_id="untrack:{}".format(normalized),
                )
            )
        elif size >= block_file:
            findings.append(
                Finding(
                    check="waste",
                    rule="file-too-large",
                    severity=BLOCK,
                    title="`{}` is {}".format(normalized, _human(size)),
                    detail="Files this large bloat every future clone of the repository.",
                    path=normalized,
                    remediation=(
                        "Use Git LFS or external storage. If this is intentional, raise "
                        "`checks.waste.block_file_kb` in .airbag.json."
                    ),
                    fix_id="untrack:{}".format(normalized),
                )
            )
        elif size >= warn_file:
            findings.append(
                Finding(
                    check="waste",
                    rule="file-large",
                    severity=WARN,
                    title="`{}` is {}".format(normalized, _human(size)),
                    detail="Large files are permanent once committed.",
                    path=normalized,
                    remediation=(
                        "Confirm this file really belongs in git. Consider Git LFS "
                        "or an external asset host."
                    ),
                )
            )
        elif size >= GITHUB_SOFT_LIMIT:
            findings.append(
                Finding(
                    check="waste",
                    rule="file-github-warning",
                    severity=WARN,
                    title="`{}` is {} - above GitHub's 50 MB warning threshold".format(
                        normalized, _human(size)
                    ),
                    detail="GitHub warns on files above 50 MB and rejects above 100 MB.",
                    path=normalized,
                    remediation="Track it with Git LFS or move it out of the repository.",
                )
            )

    for matched, count in reported_dirs.items():
        if count > 1:
            findings.append(
                Finding(
                    check="waste",
                    rule="generated-directory-size",
                    severity=INFO,
                    title="`{}/` contributes {} files to this change".format(matched, count),
                    detail="Counted while scanning {}.".format(ctx.scope.label),
                    path=matched,
                    remediation="Untrack the whole directory rather than individual files.",
                )
            )

    if total_bytes >= warn_total:
        findings.append(
            Finding(
                check="waste",
                rule="changeset-too-large",
                severity=WARN,
                title="This change adds {} of content".format(_human(total_bytes)),
                detail="{} files across {}.".format(len(ctx.files), ctx.scope.label),
                remediation=(
                    "Review the file list for generated output before pushing. Repository size "
                    "is permanent - history cannot be shrunk without a force-push rewrite."
                ),
            )
        )
    return findings


def _junk_finding(path: str, severity: str, reason: str, pattern: str) -> Finding:
    return Finding(
        check="waste",
        rule="junk-file",
        severity=severity,
        title="`{}` should not be committed".format(path),
        detail="Detected as {}.".format(reason),
        path=path,
        remediation=(
            "Add `{}` to .gitignore and untrack it with `git rm --cached {}`.".format(pattern, path)
        ),
        fix_id="untrack:{}".format(path),
    )


def _matches_any(path: str, patterns: List[str]) -> bool:
    import fnmatch

    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)
