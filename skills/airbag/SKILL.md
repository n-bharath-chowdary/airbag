---
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
