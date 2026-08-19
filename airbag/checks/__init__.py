"""Individual checks. Each module exposes ``run(ctx) -> List[Finding]``."""

from __future__ import annotations

from . import deps, gitignore, hygiene, quality, secrets, tests, waste

# Order matters: this is the order findings are reported in.
ALL_CHECKS = (
    ("secrets", secrets),
    ("waste", waste),
    ("quality", quality),
    ("tests", tests),
    ("gitignore", gitignore),
    ("deps", deps),
    ("hygiene", hygiene),
)

__all__ = ["ALL_CHECKS", "secrets", "waste", "quality", "tests", "gitignore", "deps", "hygiene"]
