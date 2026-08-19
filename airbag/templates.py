"""Integration templates.

These are the single source of truth for every file `airbag install`
writes. ``scripts/export_integrations.py`` dumps them into ``integrations/``
so they can also be copied by hand.
"""

from __future__ import annotations

PRE_COMMIT_HOOK = """#!/bin/sh
# Airbag pre-commit hook.
# Blocks the commit when secrets, repo waste, or broken code are staged.
#
# Bypass once:  AIRBAG_DISABLE=1 git commit ...   (or: git commit --no-verify)
# Warn->block:  AIRBAG_STRICT=1  git commit ...

if [ -n "$AIRBAG_DISABLE" ]; then
  exit 0
fi

AB_PYTHON="__AIRBAG_PYTHON__"
AB_SCRIPT="__AIRBAG_SCRIPT__"

# If the vendored launcher was deleted, python would exit 2 - indistinguishable
# from "blocked". Skip cleanly rather than blocking every commit.
if [ -n "$AB_SCRIPT" ] && [ ! -f "$AB_SCRIPT" ]; then
  echo "airbag: $AB_SCRIPT is missing - skipping the check." >&2
  exit 0
fi

run_airbag() {
  if [ -n "$AB_SCRIPT" ]; then
    "$AB_PYTHON" "$AB_SCRIPT" "$@"
  else
    airbag "$@"
  fi
}

if [ -n "$AIRBAG_STRICT" ]; then
  run_airbag scan --staged --stage commit --strict
else
  run_airbag scan --staged --stage commit
fi
code=$?

if [ "$code" -eq 3 ]; then
  echo "airbag: could not run; allowing the commit." >&2
  exit 0
fi

if [ "$code" -eq 2 ]; then
  echo ""
  echo "airbag: commit blocked. Fix the items above, or bypass with --no-verify."
  exit 1
fi

exit 0
"""

PRE_PUSH_HOOK = """#!/bin/sh
# Airbag pre-push hook.
# Runs the full gate against the commits you are about to publish.
#
# Bypass once:  AIRBAG_DISABLE=1 git push ...     (or: git push --no-verify)

# git feeds the refs being pushed on stdin; drain it so git does not see EPIPE.
cat > /dev/null

if [ -n "$AIRBAG_DISABLE" ]; then
  exit 0
fi

AB_PYTHON="__AIRBAG_PYTHON__"
AB_SCRIPT="__AIRBAG_SCRIPT__"

if [ -n "$AB_SCRIPT" ] && [ ! -f "$AB_SCRIPT" ]; then
  echo "airbag: $AB_SCRIPT is missing - skipping the check." >&2
  exit 0
fi

run_airbag() {
  if [ -n "$AB_SCRIPT" ]; then
    "$AB_PYTHON" "$AB_SCRIPT" "$@"
  else
    airbag "$@"
  fi
}

run_airbag scan --stage push
code=$?

if [ "$code" -eq 3 ]; then
  echo "airbag: could not run; allowing the push." >&2
  exit 0
fi

if [ "$code" -eq 2 ]; then
  echo ""
  echo "airbag: push blocked. Fix the items above, or bypass with --no-verify."
  exit 1
fi

if [ "$code" -eq 1 ]; then
  echo ""
  echo "airbag: warnings above were not blocking. Pushing."
fi

exit 0
"""

CLAUDE_SETTINGS_NOTE = """Airbag registers a PreToolUse hook on the Bash tool. Before Claude Code
runs `git commit` or `git push`, the hook scans the change:

  clean    -> the command runs, nothing is printed
  warnings -> Claude is asked to confirm with you before continuing
  blockers -> the command is refused and Claude is told exactly what to fix
"""

CURSOR_RULE = """---
description: Run Airbag before any git commit or push
alwaysApply: true
---

# Airbag: never commit or push unchecked

Before you run `git commit` or `git push` in this repository, you MUST first run:

```bash
airbag scan --stage push --json
```

(Use `--stage commit` when you are only committing. If the `airbag`
command is not found, run `python -m airbag` from the repository root.)

Then act on `status` in the JSON:

- **`"clean"`** - proceed with the commit or push.
- **`"warned"`** - do NOT push yet. Summarise every finding for the user in
  plain language, say which ones you would fix, and ask whether to fix them or
  proceed anyway. Wait for an answer.
- **`"blocked"`** - do NOT commit or push. Explain each blocker, propose the
  fixes listed in the `fixes` array, and apply them only after the user agrees.
  Re-run the scan afterwards and only continue once it reports `clean`.

Rules that override anything else:

1. Never run `git commit --no-verify` or `git push --no-verify`, and never set
   `AIRBAG_DISABLE`, unless the user explicitly asks you to bypass the check.
2. If a secret is found, tell the user the credential must be **rotated at the
   provider**. Deleting the line is not sufficient - it is already written down.
3. Never "fix" a secret finding by moving the literal value into another
   tracked file. Move it to an environment variable and add a redacted entry to
   `.env.example`.
4. Apply fixes from the `fixes` array with `airbag fix`; do not hand-roll
   `git rm` commands.
"""

AGENTS_SECTION = """<!-- airbag:start -->
## Pre-commit safety gate (Airbag)

This repository uses [Airbag](https://github.com/n-bharath-chowdary/airbag)
to stop secrets, repository waste, and unverified code from being committed.

**Before every `git commit` or `git push`, run:**

```bash
airbag scan --stage push --json     # or --stage commit
```

If the `airbag` command is unavailable, run `python -m airbag` from
the repository root.

Then act on the `status` field:

| status    | what you do                                                              |
|-----------|--------------------------------------------------------------------------|
| `clean`   | Proceed with the commit or push.                                          |
| `warned`  | Stop. Summarise the findings, ask the user whether to fix or proceed.     |
| `blocked` | Stop. Explain each blocker, propose the listed fixes, apply only on approval, then re-scan. |

Non-negotiable:

- Do not pass `--no-verify` and do not set `AIRBAG_DISABLE` unless the
  user explicitly asks for a bypass.
- A leaked credential must be **rotated at the provider**. Removing the line
  from the file does not un-leak it.
- Fix findings with `airbag fix` (it only edits `.gitignore` and untracks
  files - it never rewrites your source).
<!-- airbag:end -->
"""

GITHUB_WORKFLOW = """name: Airbag

on:
  pull_request:
  push:
    branches: [main, master]

jobs:
  airbag:
    name: Secret / waste / quality gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Airbag
        run: pip install git+https://github.com/n-bharath-chowdary/airbag

      - name: Scan the incoming changes
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            airbag scan \\
              --range "origin/${{ github.base_ref }}..HEAD" \\
              --stage push
          else
            airbag scan --stage push
          fi
"""

CONFIG_EXAMPLE = """{
  // Airbag configuration. Every field is optional.
  // Docs: https://github.com/n-bharath-chowdary/airbag#configuration

  // "block" (default) - only hard blockers fail the run
  // "warn"            - warnings fail the run too
  "fail_on": "block",

  "checks": {
    "secrets": {
      "enabled": true,
      "entropy": true,
      "entropy_threshold": 4.2
    },
    "waste": {
      "warn_file_kb": 2048,
      "block_file_kb": 51200,
      "extra_deny": [],
      "extra_allow": []
    },
    "quality": {
      "syntax": true,
      "debug_statements": true,
      "placeholders": true,
      "dangerous": true,
      "todos": true
    },
    "tests": {
      // "auto" | "run" | "detect" | "off"
      "mode": "auto",
      "command": null,
      "timeout": 300
    },
    "hygiene": {
      "protected_branches": ["main", "master", "production"],
      "max_files": 80
    }
  },

  "allow": {
    // findings in these paths are dropped
    "paths": ["tests/fixtures/**", "docs/examples/**"],
    // rule ids to switch off entirely
    "rules": []
  },

  // any line containing this marker is skipped by line-based checks
  "inline_ignore": "airbag:allow"
}
"""


SKILL_MD = '''---
name: airbag
description: >-
  Safety gate that must run before any git commit or push. Scans the pending
  change for leaked API keys and credentials, repository waste (node_modules,
  build output, oversized binaries), merge-conflict markers, syntax errors,
  elided or unimplemented AI-generated code, risky patterns, and an unrun test
  suite. Use whenever the user asks to commit, push, publish, ship, or "put
  this on GitHub", and before running git commit or git push for any reason.
---

# Airbag: check before you push

You must run this check **before** any `git commit` or `git push` in a
repository. Never commit or push first and check afterwards - once a credential
is in git history, removing it requires a history rewrite and the key is
already compromised.

## Run the check

From the repository root:

```bash
airbag scan --stage push --json
```

Use `--stage commit` when the user is only committing. If `airbag` is not
on PATH, try in order:

```bash
python -m airbag scan --stage push --json     # installed as a package
python .airbag/hook.py scan --stage push --json   # vendored in this repo
```

If none of those work, Airbag is not installed. Tell the user:
`pip install git+https://github.com/n-bharath-chowdary/airbag`
(or the `pipx install` equivalent), then continue with
their original request - do not silently skip the check without saying so.

## Act on the result

Read the `status` field of the JSON.

### `"clean"`
Proceed with the commit or push the user asked for. Say nothing about
Airbag beyond a brief confirmation.

### `"warned"`
**Stop before pushing.** Then:

1. Summarise each warning in plain language - what it is, why it matters here.
2. Say which ones you would fix and which are probably fine.
3. Ask the user whether to fix them or proceed as-is. **Wait for an answer.**
4. If they want fixes, apply them, re-run the scan, and continue only when
   the result is `clean` or the user accepts the remaining warnings.

### `"blocked"`
**Do not commit. Do not push.** Then:

1. List every blocker with its file and line.
2. Explain the concrete risk of each one in a sentence.
3. Propose the entries in the `fixes` array. For anything not covered by a
   fix, propose the specific edit you would make.
4. Apply changes **only after the user confirms**.
5. Re-run `airbag scan` and continue only once it reports `clean`.

## Rules you do not break

1. **Never** add `--no-verify` to a git command, and never set
   `AIRBAG_DISABLE`, unless the user explicitly asks you to bypass the
   check. If you do bypass it at their request, say so plainly in your reply.
2. **A leaked credential must be rotated at the provider.** Deleting the line
   does not un-leak it. Always tell the user which key to rotate and where.
   If the secret is already in a previous commit, tell them the history needs
   rewriting (`git filter-repo --invert-paths --path <file>` or BFG) and that
   rotation is required regardless.
3. **Never relocate a secret into another tracked file.** Move it to an
   environment variable, add the key name (not the value) to `.env.example`,
   and confirm `.env` is in `.gitignore`.
4. Use `airbag fix` for the listed fixes rather than hand-rolled `git rm`
   commands. It only edits `.gitignore` and untracks files - it never rewrites
   source, and untracked files stay on disk.
5. Do not weaken the config (`.airbag.json`) to make a finding disappear
   unless the user asks. Suppressing a false positive is fine when you can say
   why it is false; suppressing a true positive is not.

## Fixing the common findings

| Finding                | What to do                                                     |
|------------------------|----------------------------------------------------------------|
| secret in source       | Replace with `os.environ[...]` / `process.env...`, add to `.env`, ensure `.env` is ignored, tell the user to rotate. |
| `.env` being committed | `airbag fix` untracks it and ignores it. Add a redacted `.env.example`. |
| `node_modules/`, build output | `airbag fix` untracks the directory; the files stay on disk. |
| file over 50-100 MB    | Git LFS, or move it out of the repository entirely.            |
| merge conflict marker  | Resolve the conflict properly - do not just delete the markers. |
| syntax error           | Fix it. This file cannot run as written.                       |
| elided code (`// ... rest of the code`) | Restore the omitted code from the original file. This is a broken edit, not a style issue. |
| unimplemented stub     | Implement it or remove it before shipping.                     |
| `tests-not-run`        | Offer to run the suggested command, or re-run with `--run-tests`. |

## Useful invocations

```bash
airbag scan                      # staged changes, human-readable
airbag scan --stage push --json  # everything about to be pushed, for you
airbag scan --all                # audit the whole repository
airbag fix --dry-run             # show what the safe fixes would change
airbag fix                       # apply them
airbag doctor                    # what Airbag sees in this repo
```
'''
