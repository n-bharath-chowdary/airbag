"""Dependency and supply-chain review.

An agent that adds a package is making a trust decision on your behalf. This
check surfaces every dependency entering the repository so a human can look at
the names before they are installed, and flags the specific shapes that are
worth a second look: install hooks, unpinned versions, and direct VCS/URL
dependencies.
"""

from __future__ import annotations

import json
import os
import re
from typing import List

from ..findings import INFO, WARN, Finding

MANIFESTS = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip",
    "pyproject.toml": "python",
    "Pipfile": "pip",
    "go.mod": "go",
    "Cargo.toml": "cargo",
    "Gemfile": "rubygems",
    "composer.json": "composer",
    "pubspec.yaml": "pub",
}

LOCKFILES = {
    "package.json": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"),
    "Cargo.toml": ("Cargo.lock",),
    "Gemfile": ("Gemfile.lock",),
    "composer.json": ("composer.lock",),
    "pubspec.yaml": ("pubspec.lock",),
}

INSTALL_HOOK = re.compile(r"[\"'](pre|post)?install[\"']\s*:|[\"']prepare[\"']\s*:")
NPM_DEP_LINE = re.compile(r"^\s*[\"']([@A-Za-z0-9._/-]+)[\"']\s*:\s*[\"']([^\"']+)[\"']\s*,?\s*$")
PIP_DEP_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(\[[^\]]+\])?\s*([<>=!~^]{0,2}[^#;]*)?")
UNPINNED = re.compile(r"^(?:\*|latest|>=?\s*0?\.?\d*|\^|~)?$")
VCS_DEP = re.compile(r"(?i)(?:git\+|github:|https?://|file:|link:|git@)")


def _basename(path: str) -> str:
    return os.path.basename(path.replace("\\", "/"))


def run(ctx) -> List[Finding]:
    findings: List[Finding] = []
    changed = {_basename(p): p for p in ctx.files}

    touched_manifests = [name for name in changed if name in MANIFESTS]
    if not touched_manifests:
        return findings

    for manifest in touched_manifests:
        path = changed[manifest]
        added = ctx.added.get(path, [])
        ecosystem = MANIFESTS[manifest]
        # For JSON manifests, parse the file so `"test": "node test.js"` in
        # `scripts` is never mistaken for a dependency.
        declared = _declared_dependencies(ctx, path, manifest)

        new_deps: List[str] = []
        for lineno, line in added:
            if ctx.line_ignored(line):
                continue

            if INSTALL_HOOK.search(line) and manifest == "package.json":
                findings.append(
                    Finding(
                        check="deps",
                        rule="install-hook-added",
                        severity=WARN,
                        title="An install hook was added to package.json",
                        detail="{}:{} - {}".format(path, lineno, line.strip()[:120]),
                        path=path,
                        line=lineno,
                        remediation=(
                            "Install hooks run automatically on every `npm install`, including in "
                            "CI. Confirm this script is intentional and does only what it claims."
                        ),
                    )
                )
                continue

            name, version = _parse_dependency(manifest, line)
            if not name:
                continue
            if declared is not None and name not in declared:
                continue
            new_deps.append("{}{}".format(name, (" " + version) if version else ""))

            if version and VCS_DEP.search(version):
                findings.append(
                    Finding(
                        check="deps",
                        rule="vcs-dependency",
                        severity=WARN,
                        title="Dependency `{}` points at a URL or VCS ref".format(name),
                        detail="{}:{} -> {}".format(path, lineno, version),
                        path=path,
                        line=lineno,
                        remediation=(
                            "Direct VCS/URL dependencies bypass registry integrity checks and can "
                            "change under you. Prefer a published, version-pinned release."
                        ),
                    )
                )
            elif version and version.strip() in ("*", "latest", "") and ecosystem in ("npm", "pip"):
                findings.append(
                    Finding(
                        check="deps",
                        rule="unpinned-dependency",
                        severity=WARN,
                        title="Dependency `{}` is unpinned".format(name),
                        detail="{}:{} -> {}".format(path, lineno, version or "(no constraint)"),
                        path=path,
                        line=lineno,
                        remediation="Pin a version range so builds are reproducible.",
                    )
                )

        if new_deps:
            findings.append(
                Finding(
                    check="deps",
                    rule="dependencies-added",
                    severity=INFO,
                    title="{} dependency line(s) added to {}".format(len(new_deps), manifest),
                    detail="; ".join(new_deps[:10]) + (" ..." if len(new_deps) > 10 else ""),
                    path=path,
                    remediation=(
                        "Check each name for typosquats (a character off from a popular package) "
                        "and confirm you actually need it."
                    ),
                )
            )

        for lockfile_group in [LOCKFILES.get(manifest, ())]:
            if not lockfile_group:
                continue
            present = [lf for lf in lockfile_group if os.path.exists(os.path.join(ctx.root, lf))]
            if present and not any(_basename(p) in lockfile_group for p in ctx.files):
                findings.append(
                    Finding(
                        check="deps",
                        rule="lockfile-drift",
                        severity=WARN,
                        title="{} changed but {} did not".format(manifest, present[0]),
                        detail="A stale lockfile means CI installs different versions than you did.",
                        path=path,
                        remediation="Run your package manager's install to refresh {} and stage "
                                    "it with this change.".format(present[0]),
                    )
                )
    return findings


DEP_SECTIONS = (
    "dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
    "require", "require-dev",
)


def _declared_dependencies(ctx, path: str, manifest: str):
    """Names actually declared as dependencies, or None if we cannot tell.

    Returning a set (even an empty one) suppresses everything not in it, which
    is what keeps `[project.urls]` and `scripts` out of the dependency report.
    """
    data = ctx.content(path)
    if not data:
        return None
    text = data.decode("utf-8", "replace")

    if manifest in ("package.json", "composer.json"):
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        if not isinstance(parsed, dict):
            return None
        names = set()
        for section in DEP_SECTIONS:
            block = parsed.get(section)
            if isinstance(block, dict):
                names.update(block.keys())
        return names

    if manifest in ("pyproject.toml", "Cargo.toml"):
        try:
            import tomllib
        except ImportError:
            return set()  # cannot parse reliably -> stay quiet rather than wrong
        try:
            parsed = tomllib.loads(text)
        except Exception:
            return set()
        return _toml_dependency_names(parsed)

    return None


def _toml_dependency_names(parsed: dict) -> set:
    names = set()

    def add_requirements(items):
        for item in items or []:
            if isinstance(item, str):
                match = re.match(r"^\s*([A-Za-z0-9._-]+)", item)
                if match:
                    names.add(match.group(1))

    project = parsed.get("project")
    if isinstance(project, dict):
        add_requirements(project.get("dependencies"))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                add_requirements(group)

    tool = parsed.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            for key in ("dependencies", "dev-dependencies"):
                block = poetry.get(key)
                if isinstance(block, dict):
                    names.update(block.keys())

    # Cargo.toml
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = parsed.get(key)
        if isinstance(block, dict):
            names.update(block.keys())
    return names


def _parse_dependency(manifest: str, line: str):
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("//"):
        return None, None

    if manifest in ("package.json", "composer.json"):
        match = NPM_DEP_LINE.match(line)
        if not match:
            return None, None
        name, version = match.group(1), match.group(2)
        # Skip non-dependency string fields like "name" / "license".
        if name in ("name", "version", "license", "description", "main", "module", "types",
                    "author", "homepage", "repository", "type", "private", "packageManager"):
            return None, None
        return name, version

    if manifest.startswith("requirements") or manifest == "Pipfile":
        if "=" in stripped or stripped.isidentifier() or re.match(r"^[A-Za-z0-9._-]+", stripped):
            match = PIP_DEP_LINE.match(stripped)
            if match and match.group(1):
                return match.group(1), (match.group(3) or "").strip()
        return None, None

    if manifest == "go.mod":
        match = re.match(r"^\s*([a-z0-9./_-]+\.[a-z]{2,}/[^\s]+)\s+(v[^\s]+)", stripped)
        if match:
            return match.group(1), match.group(2)
        return None, None

    if manifest in ("Cargo.toml", "pyproject.toml"):
        match = re.match(r"^([A-Za-z0-9._-]+)\s*=\s*[\"']?([^\"'\s]+)?", stripped)
        if match and match.group(1) not in ("name", "version", "edition", "authors", "license",
                                            "description", "readme", "requires-python"):
            return match.group(1), match.group(2) or ""
        return None, None

    if manifest == "Gemfile":
        match = re.match(r"^gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?", stripped)
        if match:
            return match.group(1), match.group(2) or ""
        return None, None

    return None, None
