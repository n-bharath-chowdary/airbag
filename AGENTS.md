# Agent instructions for the Airbag repository

Airbag gates its own commits. Run `python -m pytest -q` before pushing.
If you change `airbag/templates.py`, run
`python scripts/export_integrations.py` to refresh `integrations/` and `skills/`.

<!-- airbag:start -->
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
