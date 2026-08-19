---
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
