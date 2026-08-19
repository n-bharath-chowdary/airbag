"""Scan orchestration: builds the context every check reads from."""

from __future__ import annotations

import fnmatch
import time
from typing import Dict, List, Optional, Tuple

from . import gitutil
from .checks import ALL_CHECKS
from .config import Config
from .findings import BLOCK, Finding, WARN, sort_findings


class Context:
    """Everything a check needs, computed once and shared."""

    def __init__(
        self,
        root: str,
        config: Config,
        scope: gitutil.Scope,
        stage: str,
        message: Optional[str] = None,
        run_tests: bool = False,
    ) -> None:
        self.root = root
        self.config = config
        self.scope = scope
        self.stage = stage
        self.message = message
        self.run_tests = run_tests

        self.files: List[str] = gitutil.changed_files(root, scope)
        self.added: Dict[str, List[Tuple[int, str]]] = gitutil.added_lines(root, scope)
        self._all_tracked: Optional[List[str]] = None
        self._content_cache: Dict[str, Optional[bytes]] = {}
        self._size_cache: Dict[str, int] = {}

    # -- lazily computed ---------------------------------------------------
    @property
    def all_tracked(self) -> List[str]:
        if self._all_tracked is None:
            self._all_tracked = gitutil.tracked_files(self.root)
        return self._all_tracked

    # -- file access -------------------------------------------------------
    def content(self, path: str) -> Optional[bytes]:
        if path not in self._content_cache:
            self._content_cache[path] = gitutil.read_blob(self.root, path, self.scope)
        return self._content_cache[path]

    def size_of(self, path: str) -> int:
        if path not in self._size_cache:
            self._size_cache[path] = gitutil.blob_size(self.root, path, self.scope)
        return self._size_cache[path]

    def is_binary(self, path: str) -> bool:
        data = self.content(path)
        return gitutil.is_binary(data) if data else False

    # -- allow-listing -----------------------------------------------------
    def line_ignored(self, line: str) -> bool:
        marker = self.config.inline_ignore
        return bool(marker) and marker in line

    def path_allowed(self, path: str) -> bool:
        normalized = path.replace("\\", "/")
        for pattern in self.config.allowed_paths:
            if fnmatch.fnmatch(normalized, pattern):
                return True
            if pattern.endswith("/") and normalized.startswith(pattern):
                return True
        return False


class Report:
    def __init__(
        self,
        findings: List[Finding],
        context: Context,
        duration: float,
        skipped: List[str],
    ) -> None:
        self.findings = sort_findings(findings)
        self.context = context
        self.duration = duration
        self.skipped = skipped

    @property
    def counts(self) -> Dict[str, int]:
        out = {"block": 0, "warn": 0, "info": 0}
        for finding in self.findings:
            if finding.severity in out:
                out[finding.severity] += 1
        return out

    @property
    def status(self) -> str:
        counts = self.counts
        strict = self.context.config.fail_on == "warn"
        if counts["block"] or (strict and counts["warn"]):
            return "blocked"
        if counts["warn"]:
            return "warned"
        return "clean"

    @property
    def exit_code(self) -> int:
        status = self.status
        if status == "blocked":
            return 2
        if status == "warned":
            return 1
        return 0

    def blockers(self) -> List[Finding]:
        strict = self.context.config.fail_on == "warn"
        return [
            f for f in self.findings
            if f.severity == BLOCK or (strict and f.severity == WARN)
        ]


def scan(
    root: str,
    config: Config,
    scope: gitutil.Scope,
    stage: str,
    message: Optional[str] = None,
    run_tests: bool = False,
    only: Optional[List[str]] = None,
) -> Report:
    started = time.time()
    context = Context(root, config, scope, stage, message=message, run_tests=run_tests)

    findings: List[Finding] = []
    skipped: List[str] = []

    for name, module in ALL_CHECKS:
        if only and name not in only:
            skipped.append(name)
            continue
        if not config.enabled(name):
            skipped.append(name)
            continue
        try:
            findings.extend(module.run(context))
        except Exception as exc:  # a broken check must never block a commit silently
            findings.append(
                Finding(
                    check=name,
                    rule="check-crashed",
                    severity="info",
                    title="Check `{}` failed to run".format(name),
                    detail="{}: {}".format(type(exc).__name__, exc),
                    remediation="Please report this at "
                                "https://github.com/n-bharath-chowdary/airbag/issues",
                )
            )

    findings = _apply_allowlist(findings, config, context)
    return Report(findings, context, time.time() - started, skipped)


def _apply_allowlist(findings: List[Finding], config: Config, context: Context) -> List[Finding]:
    allowed_rules = set(config.allowed_rules)
    kept: List[Finding] = []
    for finding in findings:
        if finding.rule in allowed_rules:
            continue
        if finding.path and context.path_allowed(finding.path):
            continue
        kept.append(finding)
    return kept
