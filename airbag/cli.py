"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__, gitutil, install as install_mod
from .config import load as load_config
from .fixes import apply as apply_fixes, plan as plan_fixes
from .report import render_error_json, render_json, render_text
from .scanner import scan

SUBCOMMANDS = ("scan", "fix", "install", "doctor", "hook", "version")


def _force_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airbag",
        description="Pre-commit / pre-push safety gate for AI-generated code.",
    )
    parser.add_argument("--version", action="version", version="airbag " + __version__)
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="inspect pending changes (default)")
    _add_scan_arguments(scan_parser)

    fix_parser = sub.add_parser("fix", help="apply the safe fixes for the current findings")
    _add_scan_arguments(fix_parser)
    fix_parser.add_argument(
        "--only",
        dest="only_fix",
        default=None,
        help="comma separated fix ids or kinds, e.g. gitignore,untrack",
    )
    fix_parser.add_argument(
        "--dry-run", action="store_true", help="print what would change and exit"
    )

    install_parser = sub.add_parser("install", help="wire Airbag into an editor or git")
    install_parser.add_argument(
        "target",
        nargs="?",
        default="all",
        choices=["all", "git", "claude", "cursor", "codex", "windsurf", "ci"],
        help="which integration to install (default: all)",
    )
    install_parser.add_argument("--repo", default=None, help="repository path")
    install_parser.add_argument("--force", action="store_true", help="overwrite existing files")

    doctor_parser = sub.add_parser("doctor", help="show what Airbag sees in this repository")
    doctor_parser.add_argument("--repo", default=None, help="repository path")

    hook_parser = sub.add_parser("hook", help="entry point used by editor and git hooks")
    hook_parser.add_argument(
        "kind",
        choices=["claude", "pre-commit", "pre-push"],
        help="claude: read a PreToolUse payload on stdin and gate the Bash command",
    )

    sub.add_parser("version", help="print the version")
    return parser


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--staged", action="store_true", help="scan staged changes only")
    scope.add_argument("--worktree", action="store_true", help="scan the working tree vs HEAD")
    scope.add_argument("--all", action="store_true", help="scan every tracked file")
    parser.add_argument("--range", dest="rev_range", default=None, help="scan a commit range A..B")
    parser.add_argument(
        "--stage",
        choices=["commit", "push"],
        default="commit",
        help="what is about to happen (affects severity and test behaviour)",
    )
    parser.add_argument("--json", action="store_true", help="emit the machine-readable report")
    parser.add_argument("--quiet", action="store_true", help="hide informational notes")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--strict", action="store_true", help="treat warnings as blockers")
    parser.add_argument("--run-tests", action="store_true", help="execute the detected test suite")
    parser.add_argument(
        "--checks", default=None, help="comma separated checks to run, e.g. secrets,waste"
    )
    parser.add_argument("--config", default=None, help="path to a .airbag.json")
    parser.add_argument("--message", default=None, help="the commit message about to be used")
    parser.add_argument("--repo", default=None, help="repository path")
    parser.add_argument(
        "--fix", action="store_true", help="apply safe fixes after scanning (scan only)"
    )


def _scope_mode(args) -> str:
    if getattr(args, "all", False):
        return "all"
    if getattr(args, "staged", False):
        return "staged"
    if getattr(args, "worktree", False):
        return "worktree"
    return "auto"


def _resolve_root(args) -> Optional[str]:
    start = getattr(args, "repo", None) or os.getcwd()
    return gitutil.repo_root(start)


def _run_scan(args, apply_mode: bool) -> int:
    want_json = getattr(args, "json", False)
    root = _resolve_root(args)
    if not root:
        message = "not inside a git repository (run `git init` first)"
        if want_json:
            print(render_error_json(message))
        else:
            print("airbag: " + message, file=sys.stderr)
        return 3

    try:
        config = load_config(root, args.config)
    except ValueError as exc:
        if want_json:
            print(render_error_json(str(exc)))
        else:
            print("airbag: " + str(exc), file=sys.stderr)
        return 3

    if args.strict:
        config.data["fail_on"] = "warn"

    only = [c.strip() for c in args.checks.split(",")] if args.checks else None
    scope = gitutil.resolve_scope(root, _scope_mode(args), args.rev_range, args.stage)

    report = scan(
        root,
        config,
        scope,
        args.stage,
        message=args.message,
        run_tests=args.run_tests,
        only=only,
    )
    fixes = plan_fixes(root, report.findings)

    applied: List[str] = []
    should_apply = apply_mode or getattr(args, "fix", False)
    if should_apply and not getattr(args, "dry_run", False):
        only_fix = getattr(args, "only_fix", None)
        tokens = [t.strip() for t in only_fix.split(",")] if only_fix else None
        applied = apply_fixes(root, fixes, only=tokens)

    if want_json:
        import json as _json

        payload = _json.loads(render_json(report, fixes))
        if should_apply:
            payload["applied_fixes"] = applied
            payload["note"] = (
                "Fixes were applied. Re-run `airbag scan` to confirm the change is clean."
            )
        print(_json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render_text(report, fixes, no_color=args.no_color, quiet=args.quiet))
        if should_apply:
            print("")
            if getattr(args, "dry_run", False):
                print("DRY RUN - no changes made. Remove --dry-run to apply.")
            elif applied:
                print("APPLIED FIXES")
                for line in applied:
                    print("  - " + line)
                print("\nRe-run `airbag scan` to confirm.")
            else:
                print("No auto-applicable fixes for the current findings.")

    return report.exit_code


def _run_doctor(args) -> int:
    root = _resolve_root(args)
    if not root:
        print("airbag: not inside a git repository", file=sys.stderr)
        return 3

    from .checks.gitignore import detect_ecosystems
    from .checks.tests import detect_command

    config = load_config(root, None)
    branch = gitutil.current_branch(root)
    upstream = gitutil.upstream_ref(root) or "(none)"
    ecosystems = detect_ecosystems(root) or {}
    test_command = detect_command(root)
    hooks = install_mod.installed_hooks(root)

    print("Airbag {} doctor".format(__version__))
    print("  repository     : {}".format(root))
    print("  branch         : {} -> {}".format(branch or "(none)", upstream))
    print("  config         : {}".format(config.source or "built-in defaults"))
    print("  ecosystems     : {}".format(", ".join(ecosystems) or "none detected"))
    print("  test command   : {}".format(test_command[0] if test_command else "none detected"))
    print("  git hooks      : {}".format(", ".join(hooks) or "none installed"))
    print("  node available : {}".format("yes" if _node() else "no (JS syntax check skipped)"))
    print("")
    print("Run `airbag scan` to inspect pending changes.")
    return 0


def _node() -> bool:
    code, _, _ = gitutil.run(["node", "--version"])
    return code == 0


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8()
    argv = list(sys.argv[1:] if argv is None else argv)

    # `airbag --staged` should behave like `airbag scan --staged`.
    if argv and argv[0] not in SUBCOMMANDS and not argv[0] in ("-h", "--help", "--version"):
        argv.insert(0, "scan")
    elif not argv:
        argv = ["scan"]

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print("airbag " + __version__)
        return 0
    if args.command == "install":
        return install_mod.run(args)
    if args.command == "doctor":
        return _run_doctor(args)
    if args.command == "hook":
        from . import hooks as hooks_mod

        if args.kind == "claude":
            return hooks_mod.claude_pretooluse()
        stage = "push" if args.kind == "pre-push" else "commit"
        return hooks_mod.generic_stdin_gate(stage)
    if args.command == "fix":
        return _run_scan(args, apply_mode=True)
    return _run_scan(args, apply_mode=False)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
