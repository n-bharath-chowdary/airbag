"""`.gitignore` hygiene - the cheapest possible prevention layer.

Most leaked `.env` files and committed `node_modules` trees are one careless
`git add .` away. Getting the ignore file right once removes the whole class
of mistake, so this check proposes concrete additions based on what the
repository actually contains.
"""

from __future__ import annotations

import os
import subprocess
from typing import Dict, List, Tuple

from ..findings import BLOCK, WARN, Finding

# marker file(s) -> (ecosystem label, recommended ignore patterns)
ECOSYSTEMS: List[Tuple[Tuple[str, ...], str, Tuple[str, ...]]] = [
    (("package.json",), "Node.js",
     ("node_modules/", "npm-debug.log*", "yarn-error.log*", ".pnpm-store/", "coverage/")),
    (("next.config.js", "next.config.mjs", "next.config.ts"), "Next.js", (".next/", "out/")),
    (("nuxt.config.js", "nuxt.config.ts"), "Nuxt", (".nuxt/", ".output/")),
    (("pyproject.toml", "setup.py", "requirements.txt"), "Python",
     ("__pycache__/", "*.py[cod]", ".venv/", "venv/", "*.egg-info/", ".pytest_cache/",
      ".mypy_cache/", ".ruff_cache/")),
    (("go.mod",), "Go", ("*.exe", "*.test", "*.out")),
    (("Cargo.toml",), "Rust", ("/target/",)),
    (("pom.xml", "build.gradle", "build.gradle.kts"), "JVM", ("target/", "build/", "*.class")),
    (("Gemfile",), "Ruby", (".bundle/", "vendor/bundle/", "log/", "tmp/")),
    (("composer.json",), "PHP", ("vendor/",)),
    (("Package.swift", "Podfile"), "Swift/iOS", ("Pods/", "DerivedData/", "*.xcuserstate")),
    (("main.tf", "terraform.tf"), "Terraform",
     (".terraform/", "*.tfstate", "*.tfstate.*", "*.tfvars")),
]

UNIVERSAL = (
    ".env",
    ".env.local",
    ".env.*.local",
    "*.pem",
    "*.key",
    ".DS_Store",
    "Thumbs.db",
    "*.log",
)

# Patterns whose absence is genuinely dangerous rather than merely untidy.
CRITICAL = {".env", ".env.local", "*.pem", "*.key"}


def _is_ignored(root: str, path: str) -> bool:
    proc = subprocess.run(
        ["git", "check-ignore", "-q", "--", path],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def _read_gitignore(root: str) -> Tuple[bool, List[str]]:
    path = os.path.join(root, ".gitignore")
    if not os.path.isfile(path):
        return False, []
    try:
        with open(path, "rb") as handle:
            text = handle.read().decode("utf-8", "replace")
    except OSError:
        return False, []
    entries = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    return True, entries


def detect_ecosystems(root: str) -> Dict[str, Tuple[str, ...]]:
    found: Dict[str, Tuple[str, ...]] = {}
    for markers, label, patterns in ECOSYSTEMS:
        if any(os.path.exists(os.path.join(root, marker)) for marker in markers):
            found[label] = patterns
    return found


def run(ctx) -> List[Finding]:
    root = ctx.root
    findings: List[Finding] = []
    exists, entries = _read_gitignore(root)
    entry_set = set(entries)

    ecosystems = detect_ecosystems(root)
    recommended: List[str] = list(UNIVERSAL)
    for patterns in ecosystems.values():
        recommended.extend(patterns)

    # De-duplicate while preserving order.
    seen = set()
    ordered = []
    for pattern in recommended:
        if pattern not in seen:
            seen.add(pattern)
            ordered.append(pattern)

    missing = [p for p in ordered if p not in entry_set]

    if not exists:
        findings.append(
            Finding(
                check="gitignore",
                rule="gitignore-missing",
                severity=WARN,
                title="This repository has no .gitignore",
                detail="Detected: {}.".format(", ".join(ecosystems) or "no known ecosystem"),
                path=".gitignore",
                remediation="Create one. Airbag can generate a starting file with "
                            "`airbag fix --only gitignore`.",
                fix_id="gitignore-create",
            )
        )
    elif missing:
        critical_missing = [p for p in missing if p in CRITICAL]
        severity = WARN
        title = "{} recommended .gitignore entr{} missing".format(
            len(missing), "y is" if len(missing) == 1 else "ies are"
        )
        findings.append(
            Finding(
                check="gitignore",
                rule="gitignore-incomplete",
                severity=severity,
                title=title,
                detail="Missing: {}".format(", ".join(missing[:12])
                                            + (" ..." if len(missing) > 12 else "")),
                path=".gitignore",
                remediation=(
                    "Append them with `airbag fix --only gitignore`. Critical gaps here: "
                    "{}.".format(", ".join(critical_missing) if critical_missing else "none")
                ),
                fix_id="gitignore-append",
            )
        )

    # An unignored .env sitting in the working tree is one `git add .` from disaster.
    for candidate in (".env", ".env.local", ".env.production", ".env.development"):
        full = os.path.join(root, candidate)
        if os.path.isfile(full) and not _is_ignored(root, candidate):
            findings.append(
                Finding(
                    check="gitignore",
                    rule="env-file-not-ignored",
                    severity=BLOCK,
                    title="`{}` exists but is not ignored".format(candidate),
                    detail="A single `git add .` would commit your live credentials.",
                    path=candidate,
                    remediation="Add `{}` to .gitignore now.".format(candidate),
                    fix_id="gitignore-append",
                )
            )
    return findings


def missing_patterns(root: str) -> List[str]:
    """Public helper used by the fix engine."""
    _, entries = _read_gitignore(root)
    entry_set = set(entries)
    recommended = list(UNIVERSAL)
    for patterns in detect_ecosystems(root).values():
        recommended.extend(patterns)
    out: List[str] = []
    for pattern in recommended:
        if pattern not in entry_set and pattern not in out:
            out.append(pattern)
    return out
