"""Configuration loading and merging.

Resolution order (later wins):
    built-in defaults  ->  .airbag.json in the repo root  ->  CLI flags
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

CONFIG_FILENAMES = (".airbag.json", ".airbag.jsonc", ".airbag/config.json")

DEFAULTS: Dict[str, Any] = {
    # "block" -> only hard blockers fail the run (exit 2); warnings exit 1.
    # "warn"  -> warnings are promoted to blockers.
    "fail_on": "block",
    "checks": {
        "secrets": {
            "enabled": True,
            "entropy": True,
            "entropy_threshold": 4.2,
            "min_entropy_length": 24,
        },
        "waste": {
            "enabled": True,
            "warn_file_kb": 2048,
            "block_file_kb": 51200,
            "warn_total_kb": 20480,
            "extra_deny": [],
            "extra_allow": [],
        },
        "quality": {
            "enabled": True,
            "syntax": True,
            "debug_statements": True,
            "placeholders": True,
            "dangerous": True,
            "todos": True,
        },
        "gitignore": {"enabled": True},
        "tests": {
            # auto  -> run on `--stage push`, detect-only on `--stage commit`
            # run   -> always execute the detected/configured command
            # detect-> never execute, only report that tests exist
            # off   -> skip entirely
            "mode": "auto",
            "enabled": True,
            "command": None,
            "timeout": 300,
        },
        "deps": {"enabled": True},
        "hygiene": {
            "enabled": True,
            "protected_branches": ["main", "master", "trunk", "production", "release"],
            "max_files": 80,
        },
    },
    "allow": {
        # glob patterns whose findings are downgraded to info
        "paths": [],
        # rule ids to disable entirely, e.g. "todo-added"
        "rules": [],
    },
    # any line containing this marker is skipped by line-based checks
    "inline_ignore": "airbag:allow",
}

_LINE_COMMENT = re.compile(r"(?m)^\s*//.*?$")


def _strip_jsonc(text: str) -> str:
    """Allow `//` line comments in config files."""
    return _LINE_COMMENT.sub("", text)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    def __init__(self, data: Dict[str, Any], source: Optional[str] = None) -> None:
        self.data = data
        self.source = source

    # -- accessors ---------------------------------------------------------
    def check(self, name: str) -> Dict[str, Any]:
        return self.data.get("checks", {}).get(name, {})

    def enabled(self, name: str) -> bool:
        return bool(self.check(name).get("enabled", True))

    def opt(self, check: str, key: str, default: Any = None) -> Any:
        return self.check(check).get(key, default)

    @property
    def fail_on(self) -> str:
        return self.data.get("fail_on", "block")

    @property
    def allowed_rules(self) -> List[str]:
        return list(self.data.get("allow", {}).get("rules", []))

    @property
    def allowed_paths(self) -> List[str]:
        return list(self.data.get("allow", {}).get("paths", []))

    @property
    def inline_ignore(self) -> str:
        return self.data.get("inline_ignore", "airbag:allow")


def load(repo_root: str, explicit_path: Optional[str] = None) -> Config:
    candidates = [explicit_path] if explicit_path else [
        os.path.join(repo_root, name) for name in CONFIG_FILENAMES
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            with open(path, "rb") as handle:
                raw = handle.read().decode("utf-8", "replace")
            try:
                user = json.loads(_strip_jsonc(raw))
            except ValueError as exc:
                raise ValueError("invalid config at {}: {}".format(path, exc))
            return Config(_deep_merge(DEFAULTS, user), source=path)
    return Config(json.loads(json.dumps(DEFAULTS)), source=None)
