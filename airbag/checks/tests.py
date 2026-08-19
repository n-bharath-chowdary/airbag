"""Test-suite detection and (opt-in) execution.

The default is deliberately conservative: Airbag *detects* your test
command and reports that it has not been run, but does not execute it unless
you ask. Running a repository's test command executes arbitrary code from that
repository, which is not something a tool should do behind your back.

Enable execution with ``--run-tests`` or ``"checks": {"tests": {"mode": "run"}}``.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import subprocess
from typing import List, Optional, Tuple

from ..findings import BLOCK, INFO, WARN, Finding

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java",
    ".kt", ".rb", ".php", ".c", ".cpp", ".cs", ".swift", ".scala", ".vue", ".svelte",
}

TEST_PATH = re.compile(
    r"(?i)(?:^|/)(?:tests?|spec|specs|__tests__)/|"
    r"(?:^|/)test_[^/]+\.py$|_test\.(?:py|go|rb|js|ts)$|"
    r"\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs)$|"
    r"(?:^|/)[^/]+Test\.(?:java|kt|cs)$"
)

NPM_PLACEHOLDER = re.compile(r"(?i)no test specified|exit\s+1\s*$")


def _exists(root: str, *parts: str) -> bool:
    return os.path.exists(os.path.join(root, *parts))


def _read_json(root: str, name: str) -> Optional[dict]:
    path = os.path.join(root, name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as handle:
            return json.loads(handle.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None


def _read_text(root: str, name: str) -> str:
    path = os.path.join(root, name)
    try:
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _package_manager(root: str) -> str:
    if _exists(root, "pnpm-lock.yaml"):
        return "pnpm"
    if _exists(root, "yarn.lock"):
        return "yarn"
    if _exists(root, "bun.lockb") or _exists(root, "bun.lock"):
        return "bun"
    return "npm"


def detect_command(root: str) -> Optional[Tuple[str, str]]:
    """Return (human_command, ecosystem) or None."""
    package = _read_json(root, "package.json")
    if package:
        script = (package.get("scripts") or {}).get("test")
        if script and not NPM_PLACEHOLDER.search(str(script)):
            manager = _package_manager(root)
            return ("{} test".format(manager), "node")

    pyproject = _read_text(root, "pyproject.toml")
    if (
        _exists(root, "pytest.ini")
        or "[tool.pytest" in pyproject
        or "[tool:pytest]" in _read_text(root, "setup.cfg")
        or _exists(root, "tests")
        or _exists(root, "test")
    ):
        if _exists(root, "tests") or _exists(root, "test") or "pytest" in pyproject:
            return ("python -m pytest -q", "python")

    if _exists(root, "go.mod"):
        return ("go test ./...", "go")
    if _exists(root, "Cargo.toml"):
        return ("cargo test", "rust")
    if _exists(root, "Gemfile") and (_exists(root, "spec") or _exists(root, "test")):
        return ("bundle exec rake test", "ruby")
    if _exists(root, "pom.xml"):
        return ("mvn -q test", "java")
    if _exists(root, "gradlew") or _exists(root, "build.gradle"):
        return ("./gradlew test", "java")
    if _exists(root, "Makefile") and re.search(r"(?m)^test:", _read_text(root, "Makefile")):
        return ("make test", "make")
    return None


def has_test_files(paths: List[str]) -> bool:
    return any(TEST_PATH.search(p.replace("\\", "/")) for p in paths)


def _split_command(command: str) -> List[str]:
    import shlex

    return shlex.split(command, posix=(os.name != "nt"))


def run(ctx) -> List[Finding]:
    cfg = ctx.config
    mode = str(cfg.opt("tests", "mode", "auto")).lower()
    if ctx.run_tests:
        mode = "run"
    if mode == "off":
        return []

    findings: List[Finding] = []
    root = ctx.root
    configured = cfg.opt("tests", "command", None)
    detected = (configured, "configured") if configured else detect_command(root)

    changed_source = [
        p for p in ctx.files
        if posixpath.splitext(p.replace("\\", "/").lower())[1] in SOURCE_EXTENSIONS
    ]
    repo_has_tests = has_test_files(ctx.all_tracked)

    if detected is None:
        if changed_source and not repo_has_tests:
            findings.append(
                Finding(
                    check="tests",
                    rule="no-test-suite",
                    severity=WARN if ctx.stage == "push" else INFO,
                    title="No test suite found in this repository",
                    detail="{} source file(s) are changing with nothing to verify them.".format(
                        len(changed_source)
                    ),
                    remediation=(
                        "Add at least a smoke test before shipping. Untested generated code is "
                        "how broken changes reach production."
                    ),
                )
            )
        return findings

    command, ecosystem = detected

    if changed_source and not has_test_files(ctx.files):
        findings.append(
            Finding(
                check="tests",
                rule="no-tests-touched",
                severity=INFO,
                title="{} source file(s) changed, no test file changed".format(len(changed_source)),
                detail="Detected {} test suite ({}).".format(ecosystem, command),
                remediation="Consider adding or updating a test that covers this change.",
            )
        )

    if mode in ("detect", "auto"):
        findings.append(
            Finding(
                check="tests",
                rule="tests-not-run",
                severity=WARN if ctx.stage == "push" else INFO,
                title="Test suite was not run",
                detail="Detected `{}` but Airbag does not execute it by default.".format(
                    command
                ),
                remediation=(
                    "Run `{}` and confirm it passes before pushing, or re-run Airbag with "
                    "`--run-tests` to have it execute the suite for you.".format(command)
                ),
                fix_id="run-tests",
            )
        )
        return findings

    # mode == "run"
    timeout = int(cfg.opt("tests", "timeout", 300))
    try:
        proc = subprocess.run(
            _split_command(command),
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except FileNotFoundError:
        findings.append(
            Finding(
                check="tests",
                rule="test-runner-missing",
                severity=WARN,
                title="Test command not found",
                detail="`{}` could not be executed on this machine.".format(command),
                remediation="Install the toolchain, or set `checks.tests.command` in "
                            ".airbag.json to the right command.",
            )
        )
        return findings
    except subprocess.TimeoutExpired:
        findings.append(
            Finding(
                check="tests",
                rule="tests-timed-out",
                severity=WARN,
                title="Test suite timed out after {}s".format(timeout),
                detail="Command: `{}`.".format(command),
                remediation="Run the suite manually, or raise `checks.tests.timeout`.",
            )
        )
        return findings

    if proc.returncode == 0:
        findings.append(
            Finding(
                check="tests",
                rule="tests-passed",
                severity=INFO,
                title="Test suite passed",
                detail="`{}` exited 0.".format(command),
                remediation="No action needed.",
            )
        )
        return findings

    output = proc.stdout.decode("utf-8", "replace").strip().splitlines()
    tail = "\n".join(output[-30:]) if output else "(no output)"
    findings.append(
        Finding(
            check="tests",
            rule="tests-failed",
            severity=BLOCK,
            title="Test suite failed (exit {})".format(proc.returncode),
            detail="Command: `{}`\n\n{}".format(command, tail),
            remediation="Fix the failing tests before pushing. Do not push a red suite.",
        )
    )
    return findings
